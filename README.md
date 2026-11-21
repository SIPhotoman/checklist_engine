# Checklist Engine 0.3.0

[Русский](README.ru.md)

Checklist Engine compiles trusted Python contract classes into encrypted
bundles and runs named or inline checklists. The package release is 0.3.0.
The bundle format is 2. The monotonic release number inside each bundle is
an independent integer.

## Run the offline example

Install on Python 3.12 or later and choose a fresh output directory.

~~~console
python -m pip install --only-binary=:all: -r requirements.txt
PYTHONPATH=src python examples/example.py --output demo-run
~~~

In PowerShell use the equivalent environment setting and invocation.

~~~powershell
$env:PYTHONPATH = "src"
python examples/example.py --output demo-run
~~~

The example performs a complete offline build, execution, retry, timeout
and compensation. It writes two separate bundle files and a SQLite state
database to the new directory. Its transport and session keys are
simulated.

## Build and load a release

Author a real Python class derived from Step or Checklist. Provide the
complete mapping of classes to build_bundle, including every step named
by each checklist. The compiler checks the captured class and declared
references before publication. Put required imports inside methods.
Compiled class snippets have the injected contract API, builtins and
the standard modules listed in vault.py. Class bodies and annotation
expressions need to be compatible with that namespace. The compiler
preserves the author's module-level future import for annotations.

~~~python
from engine import ChecklistRunner
from vault import SQLiteReleaseState, load_release_bundle

state = SQLiteReleaseState("private/accepted.sqlite3", "dispatch")
registry = load_release_bundle("bundles/current.py", key, state=state)
report = ChecklistRunner(registry).run("secure_dispatch")
~~~

Set allow_initial=True only for explicit enrolment in trusted state.
Subsequent loads use the default. The state transaction rejects lower
versions and conflicting authenticated contents at the same version.
For an eligible release, it loads every class and checks checklist
names, default policies, plans and referenced steps before committing.
For referenced steps it checks synchronous methods and whether an
inspectable constructor accepts a zero-argument call. Direct
instantiation supports arguments. Class bodies run with the process's
privileges while the write transaction is open, including when reloading
the accepted digest. SQLite can roll back the release record. The host
manages any external effects of trusted class code.
Custom release stores implement accept(release, *, prepare), compare
the release before calling prepare once, and commit after it succeeds.
Keep the state database and deployment directory under the application's
control. The host retains accepted bundle files and coordinates which
registry it activates.

The strict file loader accepts str and PathLike[str]. It parses the
generated file's literal data and checks the manifest before exposing
the registry. BundleLimits controls resource budgets. The default
limits are 1 MiB per file, 4096 entries, 256 UTF-8 bytes per name and
256 KiB of encoded data per entry. The legacy load_bundle path
supports min_version and also accepts trusted dict and module inputs.
Use load_release_bundle for deployed files.

build_bundle creates an exclusive temporary file in the destination
directory. It syncs the file, replaces the destination and syncs
directory metadata on POSIX. Simultaneous builders publish complete
files in replacement order. Release-state admission separately
controls which versions can run.

## Execution

The runner validates the entire plan before the first action. An entry
can be a name, a one-item sequence or a name-and-parameters pair.
Parameters become keyword arguments to run. The Context is shared
within a run.

- ABORT stops on failure. CONTINUE proceeds. ROLLBACK runs available
  compensation for completed steps in reverse order.
- Set retry_safe=True only for steps whose repeats are safe. A trusted
  caller can opt into legacy retries with allow_unsafe_retries=True.
- step_timeout limits a run attempt. step_total_timeout covers one
  step's loading, construction, attempts and delays. undo_timeout
  limits each compensation. The policy is copied when a run starts.
- Context.time_left() supplies the remaining monotonic budget. The
  engine can borrow a free Unix timer on the main thread. SecureRegistry
  defers engine interrupts during class lookup. A waiting caller uses its
  remaining budget, and the loading caller checks expiry at lookup
  boundaries. A Context deadline also covers lookup of a named checklist.
  Outside the Unix signal path, steps use cooperative limits.
  An expired result fails even when a step handled StepTimeout. A hard
  cut-off for arbitrary blocking code requires process supervision.
- Reports retain one final outcome per step and the number of actual
  attempts. Compensation has its own phase and can fail or be skipped.
  Diagnostic codes help keep contract exception text out of the report.

## Cryptography

AES-GCM-SIV encrypts contract source using a random 12-byte nonce.
The entry name is authenticated as associated data. The format-2
manifest binds format, cipher, creation time, release number and
canonical name-to-ciphertext digests. Names are sorted when computing
the manifest. Published bundles require an AEAD backend that supports
empty plaintext for the manifest.

Passwords can be converted using derive_bundle_key or the general
derive_key function. Argon2id defaults to three passes, four lanes
and 64 MiB. HKDF-SHA3-512 applies context binding. Keep the unique salt
and KDF parameters with the release configuration. Use the pinned
PyCA wheel and verify normal encryption, manifest and KDF operations
on the target platform.
