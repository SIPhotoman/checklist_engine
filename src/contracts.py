"""Core vocabulary shared by contract authors and the execution engine.

These are the only names a step author needs. They are also pre-injected
into the namespace where a decrypted class is executed (see :mod:`vault`),
so step code can use ``Step``, ``Context`` and friends without importing.

* **Step / contract** -- one atomic action.
* **Checklist** -- an ordered plan of steps.
* **Context** -- shared state threaded through one run.
* **OnError** -- what to do when a step fails.
"""

import time

__all__ = [
    "Context",
    "Step",
    "Checklist",
    "OnError",
    "StepResult",
    "ChecklistReport",
]


class Context(dict):
    """Mutable state shared by every step in a single checklist run.

    A step publishes outputs here and reads inputs produced by earlier
    steps: ``ctx["channel"] = sock`` in one, ``ctx.require("channel")`` in
    the next. A plain ``dict`` subclass, so step code stays portable.
    """

    def require(self, key):
        """Return ``self[key]``, or raise a clear error if it is missing."""
        if key not in self:
            raise KeyError(
                "required context key %r was not set by a prior step" % key
            )
        return self[key]


class Step:
    """Base class for a single checklist item ("contract").

    Subclasses implement :meth:`run` and, optionally, :meth:`undo`. All
    data a step needs arrives as keyword arguments, so the instance stays
    stateless and reusable across runs.
    """

    name = None

    def run(self, ctx, **params):
        """Perform the action; the return value is stored in the report.

        Raise an exception to signal failure -- the engine then applies the
        active :class:`OnError` policy.

        :param ctx: the shared :class:`Context` for this run.
        :param params: parameters declared for this step in the checklist.
        """
        raise NotImplementedError

    def undo(self, ctx):
        """Best-effort rollback of a previously *successful* :meth:`run`.

        Called in reverse order under the ``ROLLBACK`` policy only. The
        default is a no-op. Exceptions raised here are recorded but never
        mask the original failure.
        """
        return None

    @classmethod
    def display_name(cls):
        """Return :attr:`name` if set, else the class name."""
        return cls.name or cls.__name__


class Checklist:
    """An ordered emergency procedure: a named list of steps to execute.

    Subclass it and set :attr:`steps` to ``(step_name, params)`` pairs,
    where ``step_name`` refers to a :class:`Step` in the same bundle and
    ``params`` becomes keyword arguments to its :meth:`Step.run`. An
    :attr:`on_error` set here is a default; a policy passed to the runner
    at call time always wins.

    Example::

        class SecureDispatch(Checklist):
            name = "secure_dispatch"
            steps = [
                ("connect", {"host": "10.0.0.1", "port": 8443}),
                ("channel", {}),
                ("rotate_keys", {"generation": 7}),
                ("send", {"command": "ABORT_ALL"}),
            ]
            on_error = OnError(OnError.ROLLBACK, retries=2)
    """

    name = None
    steps = ()  # a tuple, so subclasses cannot mutate a shared default
    on_error = None

    @classmethod
    def display_name(cls):
        """Return :attr:`name` if set, else the class name."""
        return cls.name or cls.__name__


class OnError:
    """Failure-handling policy for one checklist run.

    Retries come first and are orthogonal to the policy: a step is tried up
    to ``1 + retries`` times before it counts as failed. Only then does
    :attr:`policy` decide the fate of the rest of the run.
    """

    #: Stop at the first failed step (fail-safe default for emergencies).
    ABORT = "abort"
    #: Log the failure and continue with the next step.
    CONTINUE = "continue"
    #: Undo completed steps in reverse order, then stop.
    ROLLBACK = "rollback"

    POLICIES = (ABORT, CONTINUE, ROLLBACK)

    def __init__(self, policy=ABORT, retries=0, retry_delay=0.0):
        """:param policy: one of :attr:`ABORT`, :attr:`CONTINUE`,
            :attr:`ROLLBACK`.
        :param retries: extra attempts per step before it is deemed failed.
        :param retry_delay: seconds to sleep between attempts.
        """
        if policy not in self.POLICIES:
            raise ValueError("unknown failure policy: %r" % (policy,))
        if retries < 0:
            raise ValueError("retries must be >= 0")
        if retry_delay < 0:
            raise ValueError("retry_delay must be >= 0")
        self.policy = policy
        self.retries = retries
        self.retry_delay = retry_delay

    def __repr__(self):
        return "OnError(policy=%r, retries=%d, retry_delay=%s)" % (
            self.policy,
            self.retries,
            self.retry_delay,
        )


class StepResult:
    """Outcome of a single step within a run.

    :attr:`error` holds the *text* of the exception, not the exception
    object, so a report stays safe to log or serialise.
    """

    OK = "ok"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

    def __init__(self, name, status, value=None, error=None, attempts=1,
                 duration=0.0):
        self.name = name
        self.status = status
        self.value = value
        self.error = error
        self.attempts = attempts
        self.duration = duration

    @property
    def ok(self):
        return self.status == self.OK

    def __repr__(self):
        return "StepResult(name=%r, status=%r, attempts=%d, error=%r)" % (
            self.name,
            self.status,
            self.attempts,
            self.error,
        )


class ChecklistReport:
    """Aggregated outcome of a whole checklist run."""

    def __init__(self, checklist_name):
        self.checklist_name = checklist_name
        self.results = []  # StepResult objects, in execution order
        self.ok = True
        self.rolled_back = False
        self.started_at = time.time()
        self.finished_at = None

    def record(self, result):
        self.results.append(result)
        if not result.ok:
            self.ok = False

    def finish(self):
        self.finished_at = time.time()
        return self

    @property
    def duration(self):
        end = self.finished_at if self.finished_at is not None else time.time()
        return end - self.started_at

    def summary(self):
        """Return a short status line.

        Rollback entries are counted separately, so the ``n/m`` figure
        always refers to steps that were actually executed.
        """
        executed = [r for r in self.results
                    if r.status != StepResult.ROLLED_BACK]
        undone = len(self.results) - len(executed)
        passed = sum(1 for r in executed if r.ok)
        tail = " (%d rolled back)" % undone if self.rolled_back else ""
        return "%s: %s -- %d/%d steps ok in %.3fs%s" % (
            self.checklist_name,
            "OK" if self.ok else "FAILED",
            passed,
            len(executed),
            self.duration,
            tail,
        )

    def __repr__(self):
        return "ChecklistReport(%s)" % self.summary()
