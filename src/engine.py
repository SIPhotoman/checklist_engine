"""Execution engine that runs encrypted checklists step by step.

:class:`ChecklistRunner` pulls contract classes from a
:class:`~vault.SecureRegistry`, threads one shared
:class:`~contracts.Context` through them and applies the call-time
:class:`~contracts.OnError` policy.

For each step:

1. Instantiate the step class and call ``run(ctx, **params)``.
2. On exception, retry up to ``on_error.retries`` more times, sleeping
   ``retry_delay`` in between. The same instance is reused, so a step can
   track its own attempts through the context.
3. If it still fails, apply the policy: ``ABORT`` stops immediately,
   ``CONTINUE`` moves on, ``ROLLBACK`` calls ``undo(ctx)`` on the
   already-completed steps in reverse order and then stops.

Every attempt is captured in a :class:`~contracts.ChecklistReport`.
"""

import logging
import time

from contracts import (
    Checklist,
    Context,
    ChecklistReport,
    OnError,
    Step,
    StepResult,
)

__all__ = ["ChecklistRunner"]

_LOG = logging.getLogger("checklist")


class ChecklistRunner:
    """Runs checklists resolved from a registry (or given inline)."""

    def __init__(self, registry, logger=None):
        """:param registry: a :class:`~vault.SecureRegistry`, or anything
            with a ``get(name)`` returning a contract class.
        :param logger: optional logger; defaults to ``"checklist"``.
        """
        self._registry = registry
        self._log = logger or _LOG

    def run(self, checklist, ctx=None, on_error=None):
        """Execute ``checklist``; return a
        :class:`~contracts.ChecklistReport`.

        :param checklist: a checklist name to resolve from the registry, a
            :class:`~contracts.Checklist` class or instance, or a raw
            ``list[(step_name, params)]``.
        :param ctx: optional pre-populated :class:`~contracts.Context`.
        :param on_error: :class:`~contracts.OnError` policy for this run.
            This is the call-time knob; when given it overrides whatever
            the checklist declares. Defaults to a fail-safe ``ABORT``.
        """
        name, steps, default_policy = self._resolve(checklist)
        policy = on_error or default_policy or OnError()
        ctx = ctx if ctx is not None else Context()
        report = ChecklistReport(name)
        completed = []  # (step_name, instance) pairs, for a possible undo
        self._log.info(
            "checklist %r started: %d step(s), %r", name, len(steps), policy
        )
        for index, (step_name, params) in enumerate(steps, start=1):
            result, instance = self._run_step(
                index, step_name, params, ctx, policy
            )
            report.record(result)
            if result.ok:
                completed.append((step_name, instance))
                continue
            if policy.policy == OnError.CONTINUE:
                self._log.warning(
                    "step %r failed; continuing per policy", step_name
                )
                continue
            if policy.policy == OnError.ROLLBACK:
                self._rollback(completed, ctx, report)
            self._log.error(
                "checklist %r stopping at step %r", name, step_name
            )
            break
        report.finish()
        self._log.info("checklist %r done: %s", name, report.summary())
        return report

    def _run_step(self, index, step_name, params, ctx, policy):
        """Run one step with retries; return ``(StepResult, instance)``."""
        try:
            step = self._load_step(step_name)
        except Exception as exc:
            self._log.error("cannot load step %r: %r", step_name, exc)
            result = StepResult(
                step_name, StepResult.FAILED, error=repr(exc), attempts=0
            )
            return result, None

        attempts = 0
        started = time.time()
        max_attempts = 1 + policy.retries
        last_error = None

        while attempts < max_attempts:
            attempts += 1
            try:
                self._log.info(
                    "step %d %r attempt %d", index, step_name, attempts
                )
                value = step.run(ctx, **params)
            except Exception as exc:
                last_error = exc
                self._log.warning(
                    "step %r attempt %d failed: %r", step_name, attempts, exc
                )
                if attempts < max_attempts and policy.retry_delay:
                    time.sleep(policy.retry_delay)
                continue
            duration = time.time() - started
            self._log.info("step %r ok in %.3fs", step_name, duration)
            result = StepResult(
                step_name,
                StepResult.OK,
                value=value,
                attempts=attempts,
                duration=duration,
            )
            return result, step

        result = StepResult(
            step_name,
            StepResult.FAILED,
            error=repr(last_error),
            attempts=attempts,
            duration=time.time() - started,
        )
        return result, step

    def _load_step(self, step_name):
        """Resolve ``step_name`` to a fresh :class:`~contracts.Step`."""
        cls = self._registry.get(step_name)
        if not (isinstance(cls, type) and issubclass(cls, Step)):
            raise TypeError(
                "contract %r is not a Step subclass (got %r)"
                % (step_name, cls)
            )
        return cls()

    def _rollback(self, completed, ctx, report):
        """Call ``undo`` on completed steps in reverse; record outcomes."""
        report.rolled_back = True
        self._log.warning("rolling back %d completed step(s)", len(completed))
        for step_name, instance in reversed(completed):
            try:
                instance.undo(ctx)
            except Exception as exc:
                # Undo is best-effort: logged, but never allowed to mask
                # the failure that triggered the rollback.
                self._log.error("undo for step %r failed: %r", step_name, exc)
                report.record(
                    StepResult(
                        step_name,
                        StepResult.FAILED,
                        error="undo: " + repr(exc),
                    )
                )
            else:
                self._log.info("rolled back step %r", step_name)
                report.record(StepResult(step_name, StepResult.ROLLED_BACK))

    def _resolve(self, checklist):
        """Normalise ``checklist`` to ``(name, steps, policy)``."""
        if isinstance(checklist, str):
            return self._from_checklist_class(self._registry.get(checklist))
        if isinstance(checklist, type) and issubclass(checklist, Checklist):
            return self._from_checklist_class(checklist)
        if isinstance(checklist, Checklist):
            return (
                checklist.display_name(),
                _normalise_steps(checklist.steps),
                checklist.on_error,
            )
        if isinstance(checklist, (list, tuple)):
            return ("<inline>", _normalise_steps(checklist), None)
        raise TypeError("unsupported checklist type: %r" % (type(checklist),))

    @staticmethod
    def _from_checklist_class(cls):
        if not (isinstance(cls, type) and issubclass(cls, Checklist)):
            raise TypeError("%r is not a Checklist subclass" % (cls,))
        return (cls.display_name(), _normalise_steps(cls.steps), cls.on_error)


def _normalise_steps(steps):
    """Validate step entries, returning a list of ``(name, params)``.

    Accepts ``"name"``, ``("name",)`` and ``("name", params)``. Without
    this check a bare two-character name such as ``"ok"`` would silently
    unpack into step ``"o"`` with params ``"k"``.
    """
    normalised = []
    for position, entry in enumerate(steps, start=1):
        if isinstance(entry, str):
            name, params = entry, {}
        elif isinstance(entry, (list, tuple)) and len(entry) in (1, 2):
            name = entry[0]
            params = entry[1] if len(entry) == 2 else {}
        else:
            raise TypeError(
                "step %d must be a name or a (name, params) pair, got %r"
                % (position, entry)
            )
        if not isinstance(name, str):
            raise TypeError(
                "step %d name must be a string, got %r" % (position, name)
            )
        params = {} if params is None else params
        if not hasattr(params, "keys"):
            raise TypeError(
                "params for step %r must be a mapping, got %r"
                % (name, type(params))
            )
        normalised.append((name, dict(params)))
    return normalised
