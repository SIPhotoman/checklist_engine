"""Run synchronous checklists with bounded attempts and compensation."""

from __future__ import annotations

import inspect
import logging
import signal
import time
from contextlib import contextmanager
from functools import partial
from threading import current_thread, main_thread
from types import CoroutineType, FrameType
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

from contracts import (
    Checklist,
    ChecklistReport,
    Context,
    OnError,
    Step,
    StepResult,
    StepTimeout,
    _checklist_name,
    _execution_budget,
    _is_synchronous_method,
    _snapshot_policy,
    earlier,
    is_class,
    normalise_steps,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from contracts import Phase

__all__ = ["ChecklistRunner"]

_LOG = logging.getLogger("checklist")
_BUDGET_EXPIRED = "StepTimeout"


class Registry(Protocol):
    """Resolve a checklist or step name to a contract class."""

    def get(self, name: str, /) -> object:
        """Return the registered object for a name."""
        ...


class Logger(Protocol):
    """Accept the standard levelled logging calls."""

    def info(self, msg: str, /, *args: object) -> None:
        """Log an information event."""
        ...

    def warning(self, msg: str, /, *args: object) -> None:
        """Log a warning event."""
        ...

    def error(self, msg: str, /, *args: object) -> None:
        """Log an error event."""
        ...


class _LogMethod(Protocol):
    def __call__(self, message: str, /, *args: object) -> None: ...


class _UnsupportedContractError(TypeError):
    """Reject asynchronous contracts in the synchronous engine."""


class _TimerError(RuntimeError):
    """Distinguish timer infrastructure from contract failures."""


def _deadline(seconds: float | None) -> float | None:
    return None if seconds is None else time.monotonic() + seconds


def _check_budget(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise StepTimeout("The execution budget expired")


@contextmanager
def _time_limit(deadline: float) -> Iterator[None]:
    """Borrow a free Unix timer and preserve the host's handler."""
    if (
        _execution_budget.deferred
        or current_thread() is not main_thread()
        or not hasattr(signal, "setitimer")
        or not hasattr(signal, "getitimer")
        or not hasattr(signal, "SIGALRM")
        or not hasattr(signal, "ITIMER_REAL")
    ):
        yield
        return

    alarm = signal.SIGALRM
    timer = signal.ITIMER_REAL
    try:
        occupied = signal.getsignal(alarm) != signal.SIG_DFL or any(
            signal.getitimer(timer),
        )
    except (OSError, ValueError) as exc:
        raise _TimerError("Cannot inspect the process timer") from exc
    if occupied:
        yield
        return

    active = False
    armed = False

    def expire(_signum: int, _frame: FrameType | None) -> None:
        if active and not _execution_budget.deferred:
            raise StepTimeout("The execution budget expired")

    try:
        previous = signal.signal(alarm, expire)
    except (OSError, ValueError) as exc:
        raise _TimerError("Cannot install the timer handler") from exc
    try:
        seconds = max(deadline - time.monotonic(), 0.000001)
        try:
            signal.setitimer(timer, seconds)
        except (OSError, ValueError, OverflowError) as exc:
            raise _TimerError("Cannot arm the timer") from exc
        armed = True
        active = True
        yield
    finally:
        active = False
        try:
            if armed:
                signal.setitimer(timer, 0.0)
            signal.signal(alarm, previous)
        except (OSError, ValueError, OverflowError) as exc:
            # An armed timer still needs a handler after a disarm error.
            raise _TimerError(
                "Cannot restore the process timer safely"
            ) from exc


def _timed[Result](
    ctx: Context,
    deadline: float | None,
    operation: Callable[[], Result],
) -> Result:
    previous = _execution_budget.deadline
    with ctx.limit(earlier(previous, deadline)) as effective:
        if effective is None:
            return operation()
        try:
            _execution_budget.deadline = effective
            with _time_limit(effective):
                _check_budget(effective)
                outcome = operation()
                _check_budget(effective)
                return outcome
        finally:
            _execution_budget.deadline = previous


def _sync_method(method: object) -> None:
    if not _is_synchronous_method(method):
        raise _UnsupportedContractError("Expected a synchronous method")


def _sync_value(value: object) -> object:
    if isinstance(value, CoroutineType):
        value.close()
        raise _UnsupportedContractError("A step returned a coroutine")
    if inspect.isawaitable(value) or inspect.isasyncgen(value):
        raise _UnsupportedContractError(
            "A step returned an asynchronous object"
        )
    return value


def _error_code(error: Exception, default: str) -> str:
    if isinstance(error, StepTimeout):
        return _BUDGET_EXPIRED
    if isinstance(error, _UnsupportedContractError):
        return "UnsupportedAsync"
    if isinstance(error, _TimerError):
        return "TimerError"
    return default


def _emit(method: _LogMethod, message: str, *args: object) -> None:
    try:
        method(message, *args)
    except Exception:  # noqa: BLE001 - Preserve rollback on log errors.
        return


def _subclass[T](candidate: object, base: type[T]) -> TypeGuard[type[T]]:
    return is_class(candidate) and issubclass(candidate, base)


class ChecklistRunner:
    """Resolve and execute checklists using a registry."""

    def __init__(
        self, registry: Registry, logger: Logger | None = None
    ) -> None:
        """Select the registry and optional logging sink."""
        self._registry = registry
        self._log: Logger = logger if logger is not None else _LOG

    def run(
        self,
        checklist: object,
        ctx: Context | None = None,
        on_error: OnError | None = None,
    ) -> ChecklistReport:
        """Validate the plan and return its final execution report."""
        override = _snapshot_policy(on_error) if on_error is not None else None
        if ctx is not None and not isinstance(ctx, Context):
            raise TypeError("The run context must be a Context instance")
        context = Context() if ctx is None else ctx
        name, plan, default = self._resolve(checklist, context)
        policy = (
            override if override is not None else _snapshot_policy(default)
        )
        report = ChecklistReport(name)
        completed: list[tuple[str, Step]] = []
        _emit(
            self._log.info, "checklist %r started: %d step(s)", name, len(plan)
        )

        for step_name, arguments in plan:
            result, instance = self._run_step(
                step_name, arguments, context, policy
            )
            report.record(result)
            if result.ok:
                if policy.policy == OnError.ROLLBACK and instance is not None:
                    completed.append((step_name, instance))
            elif policy.policy != OnError.CONTINUE:
                if policy.policy == OnError.ROLLBACK:
                    self._rollback(completed, context, report, policy)
                break

        report.finish()
        if not isinstance(self._log, logging.Logger) or self._log.isEnabledFor(
            logging.INFO,
        ):
            _emit(
                self._log.info, "checklist %r done: %s", name, report.summary()
            )
        return report

    def _resolve(
        self,
        checklist: object,
        ctx: Context,
    ) -> tuple[str, list[tuple[str, dict[str, object]]], OnError | None]:
        if isinstance(checklist, str):
            checklist = _timed(
                ctx, None, partial(self._registry.get, checklist)
            )
            if not _subclass(checklist, Checklist):
                raise TypeError("The requested contract is not a checklist")
        if isinstance(checklist, Checklist) or _subclass(checklist, Checklist):
            return (
                _checklist_name(checklist),
                normalise_steps(checklist.steps),
                checklist.on_error,
            )
        return "<inline>", normalise_steps(checklist), None

    def _load_step(self, name: str) -> Step:
        cls = self._registry.get(name)
        if not _subclass(cls, Step):
            raise TypeError("The requested contract is not a step")
        _sync_method(cls.run)
        return cls()

    def _run_step(
        self,
        name: str,
        arguments: dict[str, object],
        ctx: Context,
        policy: OnError,
    ) -> tuple[StepResult, Step | None]:
        started = time.monotonic()
        deadline = earlier(
            _execution_budget.deadline, _deadline(policy.step_total_timeout)
        )
        with ctx.limit(deadline):
            try:
                step = _timed(ctx, None, partial(self._load_step, name))
            except Exception as exc:  # noqa: BLE001 - Report load failures.
                code = _error_code(exc, "StepLoadError")
                _emit(
                    self._log.error, "step %r loading failed: %s", name, code
                )
                return _failed(name, code, 0, started), None
            return (
                self._attempts(step, (name, arguments), ctx, policy, started),
                step,
            )

    def _attempts(
        self,
        step: Step,
        entry: tuple[str, dict[str, object]],
        ctx: Context,
        policy: OnError,
        started: float,
    ) -> StepResult:
        name, arguments = entry
        attempts = 0
        limit = 1 + policy.retries
        retry_safe = policy.allow_unsafe_retries or step.retry_safe is True

        def invoke() -> object:
            nonlocal attempts
            attempts += 1
            return _sync_value(step.run(ctx, **arguments))

        while True:
            prior_attempts = attempts
            try:
                value = _timed(ctx, _deadline(policy.step_timeout), invoke)
            except Exception as exc:  # noqa: BLE001 - Apply failure policy.
                code = _error_code(exc, "StepError")
                _emit(
                    self._log.warning, "step %r attempt failed: %s", name, code
                )
                if (
                    attempts == prior_attempts
                    or not retry_safe
                    or attempts >= limit
                    or isinstance(
                        exc, (_UnsupportedContractError, _TimerError)
                    )
                ):
                    return _failed(name, code, attempts, started)

                waiting_error = _wait_for_retry(ctx, policy.retry_delay)
                if waiting_error is not None:
                    _emit(
                        self._log.warning,
                        "step %r retry stopped: %s",
                        name,
                        waiting_error,
                    )
                    failure = _failed(name, waiting_error, attempts, started)
                    failure.prior_error = code
                    return failure
            else:
                return StepResult(
                    name,
                    StepResult.OK,
                    value=value,
                    attempts=attempts,
                    duration=time.monotonic() - started,
                )

    def _rollback(
        self,
        completed: list[tuple[str, Step]],
        ctx: Context,
        report: ChecklistReport,
        policy: OnError,
    ) -> None:
        report.rollback_requested = True
        for name, step in reversed(completed):
            report.record(self._undo(name, step, ctx, policy.undo_timeout))

    def _undo(
        self,
        name: str,
        step: Step,
        ctx: Context,
        timeout: float | None,
    ) -> StepResult:
        started = time.monotonic()
        actions = 0

        def invoke() -> object:
            nonlocal actions
            undo: Callable[[Context], object] = step.undo
            _sync_method(undo)
            actions += 1
            return _sync_value(undo(ctx))

        attributes = cast("Mapping[str, object]", vars(step))
        if type(step).undo is Step.undo and "undo" not in attributes:
            return StepResult(name, StepResult.SKIPPED, attempts=0)
        try:
            _timed(ctx, _deadline(timeout), invoke)
        except Exception as exc:  # noqa: BLE001 - Continue rollback.
            code = _error_code(exc, "UndoError")
            _emit(self._log.error, "undo for step %r failed: %s", name, code)
            return _failed(name, code, actions, started, phase="undo")
        return StepResult(
            name,
            StepResult.ROLLED_BACK,
            attempts=actions,
            duration=time.monotonic() - started,
        )


def _wait_for_retry(ctx: Context, delay: float) -> str | None:
    remaining = ctx.time_left()
    if remaining is not None and delay >= remaining:
        return _BUDGET_EXPIRED
    if delay:
        try:
            _timed(ctx, None, partial(time.sleep, delay))
        except (
            OSError,
            OverflowError,
            ValueError,
            StepTimeout,
            _TimerError,
        ) as exc:
            return _error_code(exc, "RetryDelayError")
    return None


def _failed(
    name: str,
    code: str,
    attempts: int,
    started: float,
    *,
    phase: Phase = "run",
) -> StepResult:
    return StepResult(
        name,
        StepResult.FAILED,
        error=code,
        attempts=attempts,
        duration=time.monotonic() - started,
        phase=phase,
    )
