"""Build and run an offline example in a fresh output directory."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import os
import time
from pathlib import Path
from typing import cast

from contracts import Checklist, Context, OnError, Step, StepTimeout
from engine import ChecklistRunner
from vault import (
    BundleError,
    ReleaseStateError,
    SQLiteReleaseState,
    build_bundle,
    load_bundle,
    load_release_bundle,
)

CURRENT_VERSION = 3
PREVIOUS_VERSION = 2
TEST_KEY_BYTES = 32


class ConnectToServer(Step):
    """Simulate opening a transport to the configured address."""

    name = "connect"

    def run(self, ctx: Context, **params: object) -> str:
        """Put the endpoint into the run context."""
        host = params.get("host", "127.0.0.1")
        port = params.get("port", 8443)
        if not isinstance(host, str) or not isinstance(port, int):
            raise TypeError("Expected a host name and integer port")
        ctx.update({"host": host, "port": port, "link": True})
        return f"connected to {host}:{port}"

    def undo(self, ctx: Context) -> None:
        """Close the simulated transport."""
        for key in ("host", "port", "link"):
            ctx.pop(key, None)


class EstablishEncryptedChannel(Step):
    """Simulate channel establishment without network I/O."""

    name = "channel"

    def run(self, ctx: Context, **_params: object) -> str:
        """Set the example channel state and a synthetic session key."""
        if not ctx.get("link"):
            raise ValueError("The example link is closed")
        transcript = f"{ctx.require('host')}:{ctx.require('port')}".encode()
        ctx["session_key"] = hashlib.sha256(
            b"handshake|" + transcript
        ).digest()
        ctx["channel_secure"] = True
        return "channel secured"

    def undo(self, ctx: Context) -> None:
        """Clear the synthetic channel state."""
        ctx.pop("session_key", None)
        ctx.pop("channel_secure", None)


class RotateKeys(Step):
    """Simulate installing an operational key for one generation."""

    name = "rotate_keys"

    def run(self, ctx: Context, **params: object) -> str:
        """Validate the generation before changing the example state."""
        generation = params.get("generation", 0)
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
        ):
            raise ValueError("Expected a nonnegative generation")
        key = ctx.require("session_key")
        if not isinstance(key, bytes) or not ctx.get("channel_secure"):
            raise ValueError("The example channel is unavailable")
        ctx["op_key"] = hmac.digest(
            key,
            f"gen-{generation}".encode("ascii"),
            "sha256",
        )
        ctx["key_generation"] = generation
        return f"rotated to generation {generation}"

    def undo(self, ctx: Context) -> None:
        """Clear the installed example key."""
        ctx.pop("op_key", None)
        ctx.pop("key_generation", None)


class SendCommand(Step):
    """Simulate a repeatable action that can fail before completing."""

    name = "send"
    retry_safe = True

    def run(self, ctx: Context, **params: object) -> dict[str, str]:
        """Return an acknowledgement after the configured failures."""
        ctx.require("op_key")
        if not ctx.get("channel_secure"):
            raise ValueError("The example channel is unavailable")
        command = params.get("command", "PING")
        failures = params.get("fail_times", 0)
        if not isinstance(command, str) or not isinstance(failures, int):
            raise TypeError("Invalid example action parameters")
        previous = ctx.get("_send_attempts", 0)
        if not isinstance(previous, int):
            raise TypeError("Invalid attempt state")
        attempts = previous + 1
        ctx["_send_attempts"] = attempts
        if attempts <= failures:
            raise OSError("Simulated transient failure")
        return {"command": command, "status": "acknowledged"}


class WaitForDeadline(Step):
    """Demonstrate a portable bounded wait."""

    name = "stall"

    def run(self, ctx: Context, **_params: object) -> str:
        """Wait a short interval capped by the current deadline."""
        remaining = ctx.time_left()
        time.sleep(0.04 if remaining is None else min(0.04, remaining))
        if ctx.time_left() == 0.0:
            raise StepTimeout("Example wait expired")
        return "wait completed"


class SecureDispatch(Checklist):
    """Declare the complete simulated sequence."""

    name = "secure_dispatch"
    steps = (
        ("connect", {"host": "127.0.0.1", "port": 8443}),
        ("channel", {}),
        ("rotate_keys", {"generation": 7}),
        ("send", {"command": "PING"}),
    )


SOURCES: dict[str, type[Step | Checklist]] = {
    "connect": ConnectToServer,
    "channel": EstablishEncryptedChannel,
    "rotate_keys": RotateKeys,
    "send": SendCommand,
    "stall": WaitForDeadline,
    "secure_dispatch": SecureDispatch,
}


def run_demo(directory: Path) -> None:
    """Publish two bundles and verify the demo outcomes."""
    directory.mkdir(parents=True)
    current = directory / "current.py"
    older = directory / "previous.py"
    state_path = directory / "accepted.sqlite3"
    key = os.urandom(TEST_KEY_BYTES)

    build_bundle(SOURCES, key, current, version=CURRENT_VERSION)
    state = SQLiteReleaseState(state_path, "demo", allow_initial=True)
    registry = load_release_bundle(current, key, state=state)
    runner = ChecklistRunner(registry)

    good = runner.run("secure_dispatch")
    if not good.ok:
        raise RuntimeError("The example checklist should complete")
    print(good.summary())

    ctx = Context()
    rolled_back = runner.run(
        ["connect", "channel", "rotate_keys", ("send", {"fail_times": 1})],
        ctx,
        OnError(OnError.ROLLBACK),
    )
    if rolled_back.ok or not rolled_back.rolled_back or "op_key" in ctx:
        raise RuntimeError("The example compensation should clear the key")
    print(rolled_back.summary())

    retried = runner.run(
        ["connect", "channel", "rotate_keys", ("send", {"fail_times": 2})],
        on_error=OnError(retries=2),
    )
    if not retried.ok:
        raise RuntimeError("The repeatable example action should recover")
    print(retried.summary())

    timed = runner.run(["stall"], on_error=OnError(step_timeout=0.01))
    if timed.ok or timed.results[0].error != "StepTimeout":
        raise RuntimeError("The example wait should time out")
    print(timed.summary())

    try:
        load_bundle(current, os.urandom(TEST_KEY_BYTES))
    except BundleError:
        print("The wrong key was rejected")
    else:
        raise RuntimeError("The example accepted an unrelated key")

    build_bundle(SOURCES, key, older, version=PREVIOUS_VERSION)
    enrolled = SQLiteReleaseState(state_path, "demo")
    try:
        load_release_bundle(older, key, state=enrolled)
    except ReleaseStateError:
        print("The older release was rejected")
    else:
        raise RuntimeError("The example accepted an older release")


def main() -> None:
    """Parse the output directory for the offline demonstration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    run_demo(cast("Path", arguments.output))


if __name__ == "__main__":
    main()
