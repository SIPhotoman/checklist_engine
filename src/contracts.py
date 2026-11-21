"""Public vocabulary for synchronous checklist contracts."""

from __future__ import annotations

import inspect
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import TIMEOUT_MAX, local
from typing import ClassVar, Literal, TypeGuard, cast

__all__ = [
    "Checklist",
    "ChecklistReport",
    "Context",
    "OnError",
    "Step",
    "StepPlan",
    "StepResult",
    "StepTimeout",
]

type StepEntry = (str | tuple[str] | tuple[str, Mapping[str, object] | None])
type StepPlan = list[StepEntry] | tuple[StepEntry, ...]
type Phase = Literal["run", "undo"]
_PAIR_SIZE = 2


class StepTimeout(Exception):  # noqa: N818 - Retain the public name.
    """Signal that an attempt or its enclosing budget expired."""


class _ExecutionBudget(local):
    """Share the active engine deadline with the registry."""

    deadline: float | None = None
    deferred: bool = False

    @contextmanager
    def defer_interrupts(self) -> Iterator[None]:
        previous = self.deferred
        try:
            self.deferred = True
            yield
        finally:
            self.deferred = previous

    def remaining(self) -> float | None:
        deadline = self.deadline
        if deadline is None:
            return None
        seconds = deadline - time.monotonic()
        if not seconds > 0:
            raise StepTimeout("The execution budget expired")
        return seconds


_execution_budget = _ExecutionBudget()


def earlier(
    current: float | None,
    requested: float | None,
) -> float | None:
    """Choose the earliest deadline, treating None as unlimited."""
    if current is None:
        return requested
    if requested is None:
        return current
    return min(current, requested)


def is_class(value: object) -> TypeGuard[type[object]]:
    """Narrow a dynamic value to a Python class."""
    return isinstance(value, cast("type[object]", type))


def _is_synchronous_method(method: object) -> bool:
    return not (
        inspect.iscoroutinefunction(method)
        or inspect.isasyncgenfunction(method)
    )


class Context(dict[str, object]):
    """Keep shared state and the active deadline for one run."""

    deadline: float | None = None
    _monotonic_deadline: float | None = None

    def require(self, key: str) -> object:
        """Return a required value with a clear missing-key error."""
        try:
            return self[key]
        except KeyError as exc:
            raise KeyError(
                f"Required context key {key!r} was not set"
            ) from exc

    def time_left(self) -> float | None:
        """Return the remaining time in seconds, or None."""
        if self._monotonic_deadline is not None:
            return max(0.0, self._monotonic_deadline - time.monotonic())
        if self.deadline is not None:
            return max(0.0, self.deadline - time.time())
        return None

    @contextmanager
    def limit(self, deadline: float | None) -> Iterator[float | None]:
        """Apply the earlier deadline, then restore prior state."""
        previous = self._monotonic_deadline
        previous_wall = self.deadline
        inherited = previous
        if inherited is None and previous_wall is not None:
            inherited = time.monotonic() + (previous_wall - time.time())
        effective = earlier(inherited, deadline)
        try:
            self._monotonic_deadline = effective
            if effective is not None and effective != previous:
                self.deadline = time.time() + (effective - time.monotonic())
            yield effective
        finally:
            self._monotonic_deadline = previous
            self.deadline = previous_wall


class Step:
    """Implement a synchronous action and an optional compensation."""

    name: ClassVar[str | None] = None
    retry_safe: ClassVar[bool] = False

    def run(self, ctx: Context, **params: object) -> object:
        """Perform the action and return its result."""
        raise NotImplementedError

    def undo(self, ctx: Context) -> None:
        """Compensate for a completed action when overridden."""

    @classmethod
    def display_name(cls) -> str:
        """Return the configured name or the class name."""
        return cls.name or cls.__name__


class Checklist:
    """Declare ordered steps and an optional default failure policy."""

    name: ClassVar[str | None] = None
    steps: ClassVar[StepPlan] = ()
    on_error: ClassVar[OnError | None] = None

    @classmethod
    def display_name(cls) -> str:
        """Return the configured name or the class name."""
        return cls.name or cls.__name__


def _checklist_name(checklist: Checklist | type[Checklist]) -> str:
    name = checklist.display_name()
    if not isinstance(name, str) or not name:
        raise TypeError("The checklist name must be a nonempty string")
    return str.__str__(name)


def _is_sequence(
    value: object,
) -> TypeGuard[list[object] | tuple[object, ...]]:
    return isinstance(value, (list, tuple))


def _is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping) or (
        callable(cast("object", getattr(value, "keys", None)))
        and callable(cast("object", getattr(value, "__getitem__", None)))
    )


def normalise_steps(steps: object) -> list[tuple[str, dict[str, object]]]:
    """Validate and copy an entire plan before executing a step."""
    if not _is_sequence(steps):
        raise TypeError("Checklist steps must be a list or tuple")

    normalised: list[tuple[str, dict[str, object]]] = []
    for position, entry in enumerate(steps, start=1):
        name: object
        params: object = None
        if isinstance(entry, str):
            name = entry
        elif _is_sequence(entry) and len(entry) in (1, _PAIR_SIZE):
            name = entry[0]
            if len(entry) == _PAIR_SIZE:
                params = entry[1]
        else:
            raise TypeError(f"Invalid checklist entry at position {position}")

        if not isinstance(name, str) or not name:
            raise ValueError(
                f"Step name at position {position} must be nonempty"
            )
        normalised.append((str.__str__(name), _arguments(params, position)))
    return normalised


def _arguments(params: object, position: int) -> dict[str, object]:
    arguments: dict[str, object] = {}
    if params is None:
        return arguments
    if not _is_mapping(params):
        raise TypeError(f"Parameters for step {position} must be a mapping")
    for key in params.keys():  # noqa: SIM118 - Support the keys() protocol.
        if not isinstance(key, str) or key in {"ctx", "self"}:
            raise TypeError(f"Invalid parameter name for step {position}")
        arguments[str.__str__(key)] = params[key]
    return arguments


def _seconds(value: object, *, allow_zero: bool) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not 0 <= value <= TIMEOUT_MAX
        or (value == 0 and not allow_zero)
    ):
        raise ValueError("Timeouts and delays must be finite in-range numbers")
    return float(value)


class OnError:
    """Configure failure policy, retry eligibility and time budgets."""

    ABORT: ClassVar[str] = "abort"
    CONTINUE: ClassVar[str] = "continue"
    ROLLBACK: ClassVar[str] = "rollback"
    POLICIES: ClassVar[tuple[str, ...]] = (ABORT, CONTINUE, ROLLBACK)

    def __init__(  # noqa: PLR0913 - Preserve the public policy options.
        self,
        policy: str = ABORT,
        retries: int = 0,
        retry_delay: float = 0.0,
        step_timeout: float | None = None,
        *,
        step_total_timeout: float | None = None,
        undo_timeout: float | None = None,
        allow_unsafe_retries: bool = False,
    ) -> None:
        """Validate options for a run or a reusable checklist."""
        if policy not in self.POLICIES:
            raise ValueError("Unknown failure policy")
        if (
            not isinstance(retries, int)
            or isinstance(retries, bool)
            or not 0 <= retries < sys.maxsize
        ):
            raise ValueError("Retries must be a nonnegative in-range integer")
        if not isinstance(allow_unsafe_retries, bool):
            raise TypeError("allow_unsafe_retries must be bool")
        self.policy = str.__str__(policy)
        self.retries = int(retries)
        self.retry_delay = _seconds(retry_delay, allow_zero=True)
        self.step_timeout = self._timeout(step_timeout)
        self.step_total_timeout = self._timeout(step_total_timeout)
        self.undo_timeout = self._timeout(undo_timeout)
        self.allow_unsafe_retries = allow_unsafe_retries

    @staticmethod
    def _timeout(value: object) -> float | None:
        return None if value is None else _seconds(value, allow_zero=False)

    def __repr__(self) -> str:
        """Describe the effective retry and timeout configuration."""
        return (
            f"OnError(policy={self.policy!r}, retries={self.retries}, "
            f"retry_delay={self.retry_delay}, "
            f"step_timeout={self.step_timeout}, "
            f"step_total_timeout={self.step_total_timeout}, "
            f"undo_timeout={self.undo_timeout}, "
            f"allow_unsafe_retries={self.allow_unsafe_retries})"
        )


def _snapshot_policy(policy: OnError | None) -> OnError:
    if policy is None:
        return OnError()
    if not isinstance(policy, OnError):
        raise TypeError("The failure policy must be an OnError instance")
    return OnError(
        policy.policy,
        policy.retries,
        policy.retry_delay,
        policy.step_timeout,
        step_total_timeout=policy.step_total_timeout,
        undo_timeout=policy.undo_timeout,
        allow_unsafe_retries=policy.allow_unsafe_retries,
    )


class StepResult:
    """Record a final step or compensation outcome and attempt count."""

    OK: ClassVar[str] = "ok"
    FAILED: ClassVar[str] = "failed"
    ROLLED_BACK: ClassVar[str] = "rolled_back"
    SKIPPED: ClassVar[str] = "skipped"

    def __init__(  # noqa: PLR0913, PLR0917 - Preserve the positional API.
        self,
        name: str,
        status: str,
        value: object = None,
        error: str | None = None,
        attempts: int = 1,
        duration: float = 0.0,
        *,
        phase: Phase | None = None,
        prior_error: str | None = None,
    ) -> None:
        """Store an outcome with a diagnostic code in error."""
        self.name = name
        self.status = status
        self.value = value
        self.error = error
        self.attempts = attempts
        self.duration = duration
        self.prior_error = prior_error
        if phase is None:
            phase = (
                "undo" if status in (self.ROLLED_BACK, self.SKIPPED) else "run"
            )
        self.phase: Phase = phase

    @property
    def ok(self) -> bool:
        """Return whether this result is a successful run."""
        return self.status == self.OK

    def __repr__(self) -> str:
        """Describe the status, phase and attempt count."""
        return (
            f"StepResult(name={self.name!r}, status={self.status!r}, "
            f"phase={self.phase!r}, attempts={self.attempts}, "
            f"error={self.error!r})"
        )


class ChecklistReport:
    """Collect run and compensation results in execution order."""

    def __init__(self, checklist_name: str) -> None:
        """Start a report with calendar and monotonic timestamps."""
        self.checklist_name = checklist_name
        self.results: list[StepResult] = []
        self.ok = True
        self.rollback_requested = False
        self.rolled_back = False
        self.started_at = time.time()
        self.finished_at: float | None = None
        self._started = time.monotonic()
        self._finished: float | None = None

    def record(self, result: StepResult) -> None:
        """Append an outcome and update the aggregate flags."""
        self.results.append(result)
        if result.status == StepResult.FAILED:
            self.ok = False
        if result.status == StepResult.ROLLED_BACK:
            self.rolled_back = True

    def finish(self) -> ChecklistReport:
        """Capture the finish times and return the report."""
        self.finished_at = time.time()
        self._finished = time.monotonic()
        return self

    @property
    def duration(self) -> float:
        """Return elapsed monotonic seconds."""
        end = (
            self._finished if self._finished is not None else time.monotonic()
        )
        return end - self._started

    def summary(self) -> str:
        """Summarise run outcomes and compensation counts."""
        executed = passed = undone = undo_failed = undo_skipped = 0
        for result in self.results:
            if result.phase == "run":
                executed += 1
                passed += result.ok
            elif result.status == StepResult.ROLLED_BACK:
                undone += 1
            elif result.status == StepResult.SKIPPED:
                undo_skipped += 1
            else:
                undo_failed += 1
        tail = ""
        if self.rollback_requested or undone or undo_failed or undo_skipped:
            tail = (
                f" ({undone} rolled back, {undo_failed} failed, "
                f"{undo_skipped} skipped)"
            )
        status = "OK" if self.ok else "FAILED"
        return (
            f"{self.checklist_name}: {status} -- {passed}/{executed} "
            f"steps ok in {self.duration:.3f}s{tail}"
        )

    def __repr__(self) -> str:
        """Describe the report with its current summary."""
        return f"ChecklistReport({self.summary()})"
