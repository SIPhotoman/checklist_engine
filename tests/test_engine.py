"""Regression scenarios for synchronous execution and compensation."""

from __future__ import annotations

import logging
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

import contracts
import engine
from contracts import (
    Checklist,
    ChecklistReport,
    Context,
    OnError,
    Step,
    StepTimeout,
)
from engine import ChecklistRunner

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class Success(Step):
    def run(self, ctx: Context, **params: object) -> object:
        ctx["ran"] = True
        return params.get("value")

    def undo(self, ctx: Context) -> None:
        ctx["undone"] = True


class Fail(Step):
    def run(self, ctx: Context, **params: object) -> object:
        attempts = ctx.get("calls", 0)
        assert isinstance(attempts, int)
        ctx["calls"] = attempts + 1
        raise ValueError("private fixture")


class Repeatable(Fail):
    retry_safe = True

    def run(self, ctx: Context, **params: object) -> object:
        if ctx.get("calls") == 1:
            return "recovered"
        return super().run(ctx, **params)


class Permanent(Fail):
    retry_safe = True


class NoUndo(Step):
    def run(self, ctx: Context, **params: object) -> object:
        return "done"


class FailingUndo(Success):
    def undo(self, ctx: Context) -> None:
        raise ValueError("private compensation detail")


class TwoSteps(Checklist):
    steps = ("ok", "fail")
    on_error = OnError(OnError.CONTINUE)


def runner(extra: dict[str, object] | None = None) -> ChecklistRunner:
    definitions: dict[str, object] = {
        "ok": Success,
        "fail": Fail,
        "repeatable": Repeatable,
        "permanent": Permanent,
        "no-undo": NoUndo,
        "bad-undo": FailingUndo,
        "plan": TwoSteps,
    }
    definitions.update(extra or {})
    return ChecklistRunner(definitions)


@pytest.mark.parametrize(
    ("policy", "statuses", "undone"),
    [
        (OnError.ABORT, ["ok", "failed"], False),
        (OnError.CONTINUE, ["ok", "failed", "ok"], False),
        (OnError.ROLLBACK, ["ok", "failed", "rolled_back"], True),
    ],
)
def test_failure_policies(
    policy: str,
    statuses: list[str],
    undone: bool,
) -> None:
    ctx = Context()
    report = runner().run(["ok", "fail", "ok"], ctx, OnError(policy))
    assert [result.status for result in report.results] == statuses
    assert bool(ctx.get("undone")) is undone
    assert not report.ok


@pytest.mark.parametrize(
    ("form", "value"),
    [
        (["ok"], None),
        ([("ok",)], None),
        ([["ok"]], None),
        ([("ok", None)], None),
        ((("ok", {"value": 7}),), 7),
        ([["ok", {"value": "x"}]], "x"),
    ],
)
def test_plan_forms(form: object, value: object) -> None:
    result = runner().run(form).results[0]
    assert result.ok
    assert result.value == value


@pytest.mark.parametrize("form", ["plan", TwoSteps, TwoSteps()])
def test_checklist_forms_and_policy_override(form: object) -> None:
    default = runner().run(form)
    override = runner().run(form, on_error=OnError(OnError.ROLLBACK))
    assert len(default.results) == 2
    assert [result.phase for result in override.results] == [
        "run",
        "run",
        "undo",
    ]


@pytest.mark.parametrize(
    ("plan", "error"),
    [
        ("ok", TypeError),
        ({"ok": True}, TypeError),
        (["ok", ""], ValueError),
        (["ok", (1, {})], ValueError),
        (["ok", ("x", {}, {})], TypeError),
        (["ok", ("x", 2)], TypeError),
        (["ok", ("x", {1: True})], TypeError),
        (["ok", ("x", {"ctx": True})], TypeError),
        (["ok", ("x", {"self": True})], TypeError),
    ],
)
def test_invalid_plan_fails_before_action(
    plan: object,
    error: type[Exception],
) -> None:
    ctx = Context()
    with pytest.raises(
        error, match=r"[Ii]nvalid|[Cc]hecklist|Step name|mapping"
    ):
        runner().run(plan, ctx)
    assert "ran" not in ctx


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("policy", "unrecognised", ValueError),
        ("retries", -1, ValueError),
        ("retries", True, ValueError),
        ("retries", 0.5, ValueError),
        ("retries", sys.maxsize, ValueError),
        ("retry_delay", float("nan"), ValueError),
        ("retry_delay", float("inf"), ValueError),
        ("retry_delay", -0.1, ValueError),
        ("retry_delay", 10**400, ValueError),
        ("step_timeout", True, ValueError),
        ("step_timeout", 0.0, ValueError),
        ("step_total_timeout", float("-inf"), ValueError),
        ("undo_timeout", "1", ValueError),
        ("allow_unsafe_retries", 1, TypeError),
    ],
)
def test_invalid_policy_values(
    field: str, value: object, error: type[Exception]
) -> None:
    with pytest.raises(error, match=r"Unknown|Retries|Timeouts|bool"):
        OnError(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "retries", "legacy", "attempts", "ok"),
    [
        ("fail", 3, False, 1, False),
        ("fail", 2, True, 3, False),
        ("repeatable", 0, False, 1, False),
        ("repeatable", 2, False, 2, True),
        ("permanent", 2, False, 3, False),
    ],
)
def test_retry_only_when_agreed(
    name: str,
    retries: int,
    legacy: bool,
    attempts: int,
    ok: bool,
) -> None:
    ctx = Context()
    report = runner().run(
        [name],
        ctx,
        OnError(retries=retries, allow_unsafe_retries=legacy),
    )
    assert report.ok is ok
    assert report.results[0].attempts == attempts
    assert report.results[0].error == (None if ok else "StepError")


def test_policy_snapshot_ignores_mutation_by_step() -> None:
    policy = OnError()

    class Mutate(Fail):
        def run(self, ctx: Context, **params: object) -> object:
            policy.policy = OnError.ROLLBACK
            return super().run(ctx, **params)

    ctx = Context()
    report = runner({"mutate": Mutate}).run(["ok", "mutate"], ctx, policy)
    assert not report.rollback_requested
    assert "undone" not in ctx


def test_mutated_invalid_policy_is_checked_before_run() -> None:
    policy = OnError()
    policy.retries = -1
    ctx = Context()
    with pytest.raises(ValueError, match="Retries"):
        runner().run(["ok"], ctx, policy)
    assert not ctx


@pytest.mark.parametrize(
    ("steps", "phases", "counts", "rolled_back"),
    [
        (["fail"], [], "0 rolled back, 0 failed, 0 skipped", False),
        (
            ["no-undo", "fail"],
            ["skipped"],
            "0 rolled back, 0 failed, 1 skipped",
            False,
        ),
        (
            ["bad-undo", "ok", "fail"],
            ["rolled_back", "failed"],
            "1 rolled back, 1 failed, 0 skipped",
            True,
        ),
    ],
)
def test_rollback_reporting(
    steps: list[str],
    phases: list[str],
    counts: str,
    rolled_back: bool,
) -> None:
    report = runner().run(steps, on_error=OnError(OnError.ROLLBACK))
    outcomes = [
        result.status for result in report.results if result.phase == "undo"
    ]
    assert outcomes == phases
    assert f"{len(steps) - 1}/{len(steps)} steps ok" in report.summary()
    assert report.rollback_requested
    assert report.rolled_back is rolled_back
    assert counts in report.summary()


class AsyncRun(Step):
    async def run(self, ctx: Context, **params: object) -> object:
        ctx["entered"] = True
        return None


class AsyncGeneratorRun(Step):
    async def run(self, ctx: Context, **params: object) -> AsyncIterator[int]:
        ctx["entered"] = True
        yield 1


class WrappedAsync(Step):
    def run(self, ctx: Context, **params: object) -> object:
        return AsyncRun().run(ctx, **params)


class WrappedGenerator(Step):
    def run(self, ctx: Context, **params: object) -> object:
        return AsyncGeneratorRun().run(ctx, **params)


class AsyncUndo(Success):
    async def undo(self, ctx: Context) -> None:  # type: ignore[override]
        ctx["entered"] = True


@pytest.mark.parametrize(
    ("step", "calls"),
    [
        (AsyncRun, 0),
        (AsyncGeneratorRun, 0),
        (WrappedAsync, 1),
        (WrappedGenerator, 1),
    ],
)
def test_synchronous_run_rejects_async(
    step: type[Step],
    calls: int,
) -> None:
    ctx = Context()
    report = runner({"async": step}).run(
        ["async"],
        ctx,
        OnError(retries=2, allow_unsafe_retries=True),
    )
    assert report.results[0].attempts == calls
    assert report.results[0].error == "UnsupportedAsync"
    assert "entered" not in ctx


def test_synchronous_undo_rejects_async() -> None:
    ctx = Context()
    report = runner({"async": AsyncUndo}).run(
        ["async", "fail"],
        ctx,
        OnError(OnError.ROLLBACK),
    )
    assert report.results[-1].phase == "undo"
    assert report.results[-1].error == "UnsupportedAsync"
    assert "entered" not in ctx


class Clock:
    def __init__(self) -> None:
        self.now = 100.0
        self.wall = 10_000.0

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return self.wall

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture  # type: ignore[misc]  # pytest's decorator type contains Any.
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    result = Clock()
    monkeypatch.setattr(engine, "time", result)
    monkeypatch.setattr(contracts, "time", result)
    monkeypatch.setattr(engine, "signal", object())
    return result


def test_context_restores_outer_deadline(clock: Clock) -> None:
    ctx = Context()
    ctx.deadline = clock.wall + 20.0
    with ctx.limit(clock.now + 10.0):
        with ctx.limit(clock.now + 50.0):
            clock.wall -= 3000.0
            clock.now += 2.0
            assert ctx.time_left() == 8.0
        assert ctx.time_left() == 8.0
    assert ctx.deadline == 10_020.0


def test_nested_run_inherits_the_active_deadline(clock: Clock) -> None:
    class Inner(Success):
        def run(self, ctx: Context, **params: object) -> object:
            assert ctx.time_left() == 1.0
            clock.now += 2.0
            return super().run(ctx, **params)

    class Outer(Success):
        def run(self, ctx: Context, **_params: object) -> object:
            report = runner({"inner": Inner}).run(["inner"], Context())
            ctx["inner_error"] = report.results[0].error
            return None

    ctx = Context()
    result = runner({"outer": Outer}).run(
        ["outer"], ctx, OnError(step_timeout=1.0)
    )
    assert result.results[0].error == "StepTimeout"
    assert ctx["inner_error"] == "StepTimeout"
    assert runner().run(["ok"], Context()).ok


def test_named_checklist_resolution_uses_the_context_deadline(
    clock: Clock,
) -> None:
    class Registry:
        def get(self, name: str, /) -> type[Checklist]:
            assert name == "plan"
            clock.now += 2.0
            return TwoSteps

    ctx = Context()
    ctx.deadline = clock.wall + 1.0
    with pytest.raises(StepTimeout):
        ChecklistRunner(Registry()).run("plan", ctx)
    assert "ran" not in ctx


def test_report_duration_uses_monotonic_clock(clock: Clock) -> None:
    report = ChecklistReport("test")
    clock.wall -= 500.0
    clock.now += 0.75
    report.finish()
    assert report.duration == 0.75
    assert report.finished_at == 9500.0


@pytest.mark.parametrize(
    ("phase", "expected_attempts"),
    [("constructor", 0), ("run", 1), ("undo", 1), ("delay", 1)],
)
def test_budgets_cover_each_phase(
    clock: Clock, phase: str, expected_attempts: int
) -> None:
    class Expiring(Success):
        retry_safe = True

        def __init__(self) -> None:
            if phase == "constructor":
                clock.now += 2

        def run(self, ctx: Context, **params: object) -> object:
            if phase == "run":
                clock.now += 2
            if phase == "delay":
                raise ValueError("repeatable failure")
            return super().run(ctx, **params)

        def undo(self, ctx: Context) -> None:
            if phase == "undo":
                clock.now += 2
            super().undo(ctx)

    config = OnError(
        OnError.ROLLBACK,
        retries=2,
        retry_delay=1,
        step_timeout=1,
        step_total_timeout=1,
        undo_timeout=1,
    )
    plan = ["expiring", "fail"] if phase == "undo" else ["expiring"]
    report = runner({"expiring": Expiring}).run(plan, on_error=config)
    result = report.results[-1]
    assert result.error == "StepTimeout"
    assert result.attempts == expected_attempts


def test_retry_sleep_error_is_reported(
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_seconds: float) -> None:
        raise OSError("sleep fixture")

    monkeypatch.setattr(clock, "sleep", unavailable)
    ctx = Context()
    policy = OnError(OnError.ROLLBACK, retries=2, retry_delay=0.1)
    report = runner().run(["ok", "repeatable"], ctx, policy)
    assert report.results[1].error == "RetryDelayError"
    assert report.results[1].prior_error == "StepError"
    assert ctx["undone"] is True


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Unix timer")
@pytest.mark.parametrize("existing", [False, True])
def test_nested_and_external_timers_are_preserved(existing: bool) -> None:
    def app_handler(_signum: int, _frame: object) -> None:
        return None

    handler = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    signal.setitimer(signal.ITIMER_REAL, 0)
    try:
        signal.signal(
            signal.SIGALRM, app_handler if existing else signal.SIG_DFL
        )
        if existing:
            signal.setitimer(signal.ITIMER_REAL, 10.0, 10.0)
        deadline = time.monotonic() + 5.0
        with engine._time_limit(deadline):
            before = signal.getsignal(signal.SIGALRM)
            with engine._time_limit(deadline):
                assert signal.getsignal(signal.SIGALRM) == before
            after = signal.getitimer(signal.ITIMER_REAL)
            assert after[0] > 0
        assert signal.getsignal(signal.SIGALRM) == (
            app_handler if existing else signal.SIG_DFL
        )
        assert (
            signal.getitimer(signal.ITIMER_REAL)[0] > 0
            if existing
            else (signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, *timer)


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Unix timer")
def test_timer_setup_error_restores_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = signal.getsignal(signal.SIGALRM)
    if original != signal.SIG_DFL:
        pytest.skip("The test host already owns SIGALRM")

    def unavailable(
        _timer: int, _seconds: float, _interval: float = 0.0
    ) -> tuple[float, float]:
        raise OSError("timer fixture")

    monkeypatch.setattr(signal, "setitimer", unavailable)
    report = runner().run(["ok"], on_error=OnError(step_timeout=1))
    assert report.results[0].error == "TimerError"
    assert report.results[0].attempts == 0
    assert signal.getsignal(signal.SIGALRM) == original


@pytest.mark.parametrize("threaded", [False, True])
def test_missed_signal_cannot_mark_an_expired_run_ok(threaded: bool) -> None:
    class Wait(Step):
        def run(self, ctx: Context, **params: object) -> object:
            try:
                time.sleep(0.04)
            except StepTimeout:
                return "caught"
            return "late"

    configured = runner({"wait": Wait})
    config = OnError(step_timeout=0.005)
    if threaded:
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(
                configured.run, ["wait"], None, config
            ).result(2)
    else:
        result = configured.run(["wait"], on_error=config)
    assert result.results[0].error == "StepTimeout"
    assert not result.ok


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Unix timer")
def test_disarm_failure_keeps_an_inactive_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = signal.getsignal(signal.SIGALRM)
    if original != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
        pytest.skip("The test host already owns SIGALRM")

    def timer(
        _which: int, seconds: float, _interval: float = 0.0
    ) -> tuple[float, float]:
        if seconds == 0:
            raise OSError("disarm fixture")
        return 0.0, 0.0

    monkeypatch.setattr(signal, "setitimer", timer)
    try:
        report = runner().run(["ok"], on_error=OnError(step_timeout=1))
        assert report.results[0].error == "TimerError"
        assert report.results[0].attempts == 1
        handler = signal.getsignal(signal.SIGALRM)
        assert callable(handler)
        handler(signal.SIGALRM, None)
    finally:
        signal.signal(signal.SIGALRM, original)


def test_sanitised_errors_survive_broken_repr_and_logger() -> None:
    class BadReprError(ValueError):
        def __repr__(self) -> str:
            raise RuntimeError("repr fixture")

    class Raises(Step):
        def run(self, ctx: Context, **params: object) -> object:
            raise BadReprError("private marker")

    class BrokenLogger:
        def info(self, msg: str, /, *args: object) -> None:
            raise RuntimeError("logger fixture")

        warning = info
        error = info

    ctx = Context()
    report = ChecklistRunner(
        {"ok": Success, "fail": Raises},
        BrokenLogger(),
    ).run(["ok", "fail"], ctx, OnError(OnError.ROLLBACK))
    assert "private marker" not in repr(report.results)
    assert report.results[1].error == "StepError"
    assert ctx["undone"] is True


def test_quiet_logging_skips_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = logging.Logger("quiet", level=logging.ERROR)  # noqa: LOG001

    def forbidden(_self: ChecklistReport) -> str:
        raise AssertionError("Summary called for a disabled level")

    monkeypatch.setattr(ChecklistReport, "summary", forbidden)
    assert ChecklistRunner({"ok": Success}, logger).run(["ok"]).ok
