## 📖 Read this in other languages

- [Русский](README.ru.md)
- [English](README.md)

---

# Checklist Engine

Encrypted, executable emergency checklists.
Contract classes are written as ordinary Python,
compiled offline into an encrypted bundle, and decrypted one at a time at
runtime by a device holding the key.

## Model

* **Step** (a *contract*) — one atomic action: `run(ctx, **params)`, plus an
  optional `undo(ctx)`.
* **Checklist** — an ordered list of `(step_name, params)` pairs.
* **Context** — a `dict` shared by every step of one run; steps publish
  outputs into it and read the outputs of earlier steps.
* **OnError** — the call-time failure policy: `ABORT`, `CONTINUE` or
  `ROLLBACK`, plus `retries` and `retry_delay`.

## Files

| File | Role |
|---|---|
| `crypto.py` | AES-GCM-SIV, and key derivation (Argon2id → HKDF-SHA3-512) |
| `contracts.py` | `Step`, `Checklist`, `Context`, `OnError`, result types |
| `vault.py` | `build_bundle` (offline compiler), `SecureRegistry` (loader) |
| `engine.py` | `ChecklistRunner` — executes checklists, applies the policy |
| `example.py` | Example contracts plus a runnable end-to-end demo |

Install: `pip install -r requirements.txt` (needs `cryptography>=44.0`).
Run the demo: `python example.py`.

## Lifecycle

**1. Author contracts** as plain Python in one file:

```python
from contracts import Checklist, Step

class ConnectToServer(Step):
    name = "connect"

    def run(self, ctx, host="127.0.0.1", port=8443, **_):
        ctx["link"] = open_socket(host, port)
        return "connected"

    def undo(self, ctx):
        ctx.pop("link", None).close()

class SecureDispatch(Checklist):
    name = "secure_dispatch"
    steps = [
        ("connect", {"host": "10.0.0.7", "port": 8443}),
        ("channel", {}),
        ("rotate_keys", {"generation": 7}),
        ("send", {"command": "ARM_SAFE_MODE"}),
    ]
```

**2. Compile to an encrypted bundle** (offline, on a trusted machine):

```python
from vault import build_bundle

build_bundle({"connect": ConnectToServer,
              "secure_dispatch": SecureDispatch}, key, "secure_bundle.py")
```

The result is an importable `.py` file holding `{name: base64_ciphertext}`.
No source code appears in it.

**3. Load and run** on the device:

```python
from engine import ChecklistRunner
from vault import load_bundle
from contracts import OnError

runner = ChecklistRunner(load_bundle("secure_bundle.py", key))
report = runner.run("secure_dispatch",
                    on_error=OnError(OnError.ROLLBACK, retries=2))
print(report.summary())   # secure_dispatch: OK -- 4/4 steps ok in 0.002s
```

`runner.run()` also accepts a `Checklist` class or instance, or an inline
`[(step_name, params), ...]` list. Each entry may be `"name"`, `("name",)`
or `("name", params)`.

## Execution semantics

For each step: instantiate the class, call `run(ctx, **params)`; on an
exception retry up to `retries` more times (sleeping `retry_delay`, same
instance reused); if it still fails, apply the policy —

* `ABORT` — stop immediately (the default; fail-safe for emergencies).
* `CONTINUE` — record the failure and move to the next step.
* `ROLLBACK` — call `undo(ctx)` on completed steps in reverse order, then
  stop. An exception inside `undo` is recorded but never masks the original
  failure.

Every attempt lands in a `ChecklistReport` (`.ok`, `.results`,
`.rolled_back`, `.duration`, `.summary()`). A policy passed to `run()`
overrides the one declared on the checklist.

## Cryptography

* **Cipher: AES-GCM-SIV** (RFC 8452). Each entry's **name is bound as associated data**, so a ciphertext cannot
  be moved to another slot in the bundle unnoticed.
* **Key derivation** (`crypto.derive_key`) — Argon2id with `t=3` iterations,
  `p=4` lanes, `m=2^16 KiB` (64 MiB), producing 64 bytes, then HKDF-SHA3-512
  down to the requested length. The `info` argument (default
  `b"checklists-engine/v1/bundle-key"`) binds the key to a purpose.

  ```python
  key = crypto.derive_key(passphrase, salt, info=b"my-fleet/v2")
  ```

  Argon2id needs 64 MiB of RAM per derivation — verify the target board can
  spare it. Store the salt (16 bytes) next to the bundle; it need not be
  secret, only unique.
* `encrypt`/`decrypt` take a raw 16/24/32-byte key.

### Trust model

The key is the only boundary. Decrypted contract code runs with full
privileges, like any other module in the process: this gives contracts
**confidentiality and integrity, not a sandbox**. Anyone who can supply the
key can run arbitrary code, so protect the key accordingly.

A bundle file is **parsed, never executed** (`vault.read_bundle_file` reads
only the literal `BUNDLE`/`META` assignments via `ast`). Executing it would
let anyone who can write to the file run code before a single key check.

## Authoring rules

`inspect.getsource` captures only the class body, not the module's `import`
lines. The loader pre-injects `Step`, `Checklist`, `Context`, `OnError`,
`StepResult`, `ChecklistReport` and the modules `time`, `os`, `json`,
`struct`, `hashlib`, `hmac`, `binascii`, `math`, `random`. **Anything else
must be imported inside a method.** Each bundle entry must define exactly one
`Step` or `Checklist` subclass, and the class must live in a real `.py` file
(source cannot be read from a REPL).

## Notes

* Decryption is lazy and cached: an entry is decrypted the first time it is
  requested and the class object is reused afterwards.
