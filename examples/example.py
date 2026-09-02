"""Example contract sources plus an end-to-end build-and-run demo.

This file plays two roles:

1. It is the *plaintext source* where an author writes ordinary
   :class:`~contracts.Step` and :class:`~contracts.Checklist` classes --
   the input to :func:`vault.build_bundle`.
2. Its :func:`main` shows the whole lifecycle: encrypt those classes into
   ``secure_bundle.py``, load them back with the key, and run checklists
   under different failure policies.

The steps model the contract from the brief: connect -> establish an
encrypted channel -> rotate keys -> send command. Network and crypto
calls are SIMULATED so the demo runs offline.

Because only the class body is encrypted, a step may use the pre-injected
names (``Step``, ``time``, ``hashlib``, ``hmac``, ``os`` ...) directly and
must ``import`` anything else *inside* a method.
"""

import hashlib
import hmac
import logging
import os

from contracts import Checklist, OnError, Step
from engine import ChecklistRunner
from vault import build_bundle, load_bundle

BUNDLE_PATH = "secure_bundle.py"


# Contract sources: these class bodies are what gets encrypted.
class ConnectToServer(Step):
    """Open the transport link to the control server."""

    name = "connect"

    def run(self, ctx, host="127.0.0.1", port=8443, **_):
        link = {"host": host, "port": port, "open": True}
        ctx["link"] = link
        return "connected to %s:%d" % (host, port)

    def undo(self, ctx):
        link = ctx.pop("link", None)
        if link:
            link["open"] = False


class EstablishEncryptedChannel(Step):
    """Perform a handshake and derive a session key over the open link."""

    name = "channel"

    def run(self, ctx, **_):
        link = ctx.require("link")
        if not link.get("open"):
            raise RuntimeError("link is not open")
        transcript = ("%s:%s" % (link["host"], link["port"])).encode()
        digest = hashlib.sha256(b"handshake|" + transcript).digest()
        ctx["session_key"] = digest
        ctx["channel_secure"] = True
        return "channel secured"

    def undo(self, ctx):
        ctx.pop("session_key", None)
        ctx["channel_secure"] = False


class RotateKeys(Step):
    """Derive a fresh operational key for the requested generation."""

    name = "rotate_keys"

    def run(self, ctx, generation=0, **_):
        if not ctx.get("channel_secure"):
            raise RuntimeError("refusing to rotate keys on insecure channel")
        if generation < 0:
            raise ValueError("generation must be non-negative")
        session_key = ctx.require("session_key")
        message = b"gen-%d" % generation
        ctx["op_key"] = hmac.new(session_key, message, hashlib.sha256).digest()
        ctx["key_generation"] = generation
        return "rotated to generation %d" % generation


class SendCommand(Step):
    """Send the emergency command over the secured, keyed channel."""

    name = "send"

    def run(self, ctx, command="NOOP", fail_times=0, **_):
        if not ctx.get("channel_secure"):
            raise RuntimeError("cannot send on an insecure channel")
        ctx.require("op_key")
        seen = ctx.get("_send_attempts", 0) + 1
        ctx["_send_attempts"] = seen
        if seen <= fail_times:
            raise IOError("transient send failure #%d" % seen)
        return {"command": command, "status": "acknowledged"}


class SecureDispatch(Checklist):
    """The canonical happy-path emergency procedure."""

    name = "secure_dispatch"
    steps = [
        ("connect", {"host": "10.0.0.7", "port": 8443}),
        ("channel", {}),
        ("rotate_keys", {"generation": 7}),
        ("send", {"command": "ARM_SAFE_MODE"}),
    ]


# Handed to build_bundle: both the steps and the checklist get encrypted.
SOURCES = {
    "connect": ConnectToServer,
    "channel": EstablishEncryptedChannel,
    "rotate_keys": RotateKeys,
    "send": SendCommand,
    "secure_dispatch": SecureDispatch,
}


# Demo driver.
def main():
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)-7s %(message)s"
    )

    # The key would normally come from a secure element
    key = os.urandom(32)

    # 1. Offline: encrypt the plaintext classes into an importable bundle
    build_bundle(SOURCES, key, BUNDLE_PATH)
    print("built encrypted bundle -> %s\n" % BUNDLE_PATH)

    # 2. Runtime: load the bundle back with the key.
    registry = load_bundle(BUNDLE_PATH, key)
    runner = ChecklistRunner(registry)
    print("contracts in bundle:", registry.names(), "\n")

    # 3a. Happy path: default ABORT policy, checklist resolved by name.
    print("=== run A: happy path (ABORT) ===")
    report = runner.run("secure_dispatch")
    print(report.summary(), "\n")

    # 3b. Forced failure with ROLLBACK: undo runs in reverse order.
    print("=== run B: forced failure, ROLLBACK ===")
    failing = [
        ("connect", {"host": "10.0.0.7", "port": 8443}),
        ("channel", {}),
        ("rotate_keys", {"generation": -1}),  # invalid -> raises
        ("send", {"command": "ARM_SAFE_MODE"}),
    ]
    report = runner.run(failing, on_error=OnError(OnError.ROLLBACK, retries=1))
    _dump(report)

    # 3c. Transient fault recovered by retries (call-time policy).
    print("=== run C: flaky send, retries ===")
    flaky = [
        ("connect", {}),
        ("channel", {}),
        ("rotate_keys", {"generation": 1}),
        ("send", {"command": "PING", "fail_times": 2}),
    ]
    report = runner.run(
        flaky, on_error=OnError(OnError.ABORT, retries=3, retry_delay=0.0)
    )
    _dump(report)

    # 3d. The key is the trust boundary: a wrong key yields no contracts.
    print("=== run D: wrong key ===")
    wrong = ChecklistRunner(load_bundle(BUNDLE_PATH, os.urandom(32)))
    report = wrong.run([("connect", {})])
    print(report.summary())
    print("   ", report.results[0])


def _dump(report):
    print(report.summary())
    for result in report.results:
        print("   ", result)
    print()


if __name__ == "__main__":
    main()
