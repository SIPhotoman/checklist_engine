"""Compile, publish and load authenticated Python contracts."""

from __future__ import annotations

import ast
import base64
import binascii
import builtins
import hashlib
import inspect
import os
import re
import sqlite3
import stat
import symtable
import tempfile
import textwrap
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from concurrent.futures import Future, wait
from contextlib import closing
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from threading import TIMEOUT_MAX, Lock, get_ident
from types import ModuleType
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Protocol,
    TypedDict,
    TypeGuard,
    cast,
)

import crypto
from contracts import (
    Checklist,
    ChecklistReport,
    Context,
    OnError,
    Step,
    StepPlan,
    StepResult,
    StepTimeout,
    _checklist_name,
    _execution_budget,
    _is_synchronous_method,
    _snapshot_policy,
    is_class,
    normalise_steps,
)
from crypto import InvalidTag

if TYPE_CHECKING:
    from typing import BinaryIO

__all__ = [
    "BundleError",
    "BundleLimits",
    "BundlePublicationError",
    "ReleaseIdentity",
    "ReleaseStateError",
    "SQLiteReleaseState",
    "SecureRegistry",
    "build_bundle",
    "load_bundle",
    "load_release_bundle",
    "read_bundle_file",
]

BUNDLE_FORMAT = 2
CIPHER_NAME = "AES-GCM-SIV"
_MAX_VERSION = 2**63 - 1
_MAX_VERSION_DIGITS = len(str(_MAX_VERSION))
_B64_CHUNK = 64
_TAG_LENGTH = 4 * ((crypto.MESSAGE_OVERHEAD + 2) // 3)
_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_META_FIELDS = frozenset(
    {"format", "cipher", "created", "version", "manifest", "entries"}
)
_META_NAME_LENGTH = max(map(len, _META_FIELDS))
_TOKEN = re.compile(
    r"""(?P<space>[ \t\r\n]+|\#[^\r\n]*)"""
    r"""|(?P<string>'(?:[^'\\\r\n]++|\\[^\r\n])*+'"""
    r"""|"(?:[^"\\\r\n]++|\\[^\r\n])*+")"""
    r"""|(?P<identifier>[A-Za-z_][A-Za-z_0-9]*)"""
    r"""|(?P<number>[0-9]+)|(?P<delimiter>[{}()[\],:=])""",
)

type PathInput = str | os.PathLike[str]
type Contract = Step | Checklist
type ContractClass = type[Step | Checklist]

_CONTRACT_API: dict[str, object] = {
    "Step": Step,
    "StepPlan": StepPlan,
    "ClassVar": ClassVar,
    "Checklist": Checklist,
    "Context": Context,
    "OnError": OnError,
    "StepResult": StepResult,
    "StepTimeout": StepTimeout,
    "ChecklistReport": ChecklistReport,
}
_CONTRACT_MODULES = (
    "time",
    "os",
    "json",
    "struct",
    "hashlib",
    "hmac",
    "binascii",
    "math",
    "random",
)
_ALLOWED_GLOBALS = (
    frozenset(dir(builtins)) | _CONTRACT_API.keys() | set(_CONTRACT_MODULES)
)


class BundleError(Exception):
    """Report an invalid bundle or contract."""


class BundlePublicationError(OSError):
    """Report an uncertain commit after replacing a bundle."""


class ReleaseStateError(BundleError):
    """Report a refusal or error in the trusted release state."""


@dataclass(frozen=True)
class BundleLimits:
    """Set resource limits for both file reading and publication."""

    file_bytes: int = 1024 * 1024
    entries: int = 4096
    name_bytes: int = 256
    entry_chars: int = 256 * 1024

    def __post_init__(self) -> None:
        """Reject unusable resource limits."""
        for value in (
            self.file_bytes,
            self.entries,
            self.name_bytes,
            self.entry_chars,
        ):
            if type(value) is not int or not 1 <= value <= 2**31 - 1:
                raise ValueError(
                    "Bundle limits must be positive in-range integers"
                )


DEFAULT_LIMITS = BundleLimits()


@dataclass(frozen=True)
class ReleaseIdentity:
    """Identify the authenticated contents of a particular release."""

    version: int
    digest: str

    def __post_init__(self) -> None:
        """Validate the stored version and canonical digest."""
        _version(self.version)
        if (
            not isinstance(self.digest, str)
            or _DIGEST.fullmatch(self.digest) is None
        ):
            raise ReleaseStateError("Invalid release digest")


class ReleaseState(Protocol):
    """Serialise checks, preparation and release acceptance."""

    def accept(
        self, release: ReleaseIdentity, *, prepare: Callable[[], None]
    ) -> None:
        """Check eligibility, run prepare and commit on success.

        Call prepare once for each eligible release, including a repeat
        of the accepted digest. Propagate any preparation failure.
        """
        ...


class _ContractFactory(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> Contract: ...


class BundleMetadata(TypedDict):
    """Literal metadata carried by a format-2 bundle."""

    format: int
    cipher: str
    created: str
    version: int
    manifest: str
    entries: list[str]


def _version(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BundleError("Release version must be an integer")
    if not 0 <= value <= _MAX_VERSION:
        raise BundleError("Release version is out of range")
    return int(value)


def _dict(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, dict)


def _entries(value: object) -> TypeGuard[list[object] | tuple[object, ...]]:
    return isinstance(value, (list, tuple))


def _pathlike(
    value: object,
) -> TypeGuard[str | os.PathLike[str] | os.PathLike[bytes]]:
    return isinstance(value, (str, os.PathLike))


def _text_path(value: str | os.PathLike[str] | os.PathLike[bytes]) -> str:
    path = os.fspath(value)
    if not isinstance(path, str):
        raise BundleError("File path must resolve to str")
    return path


def _entry_name(value: object, limits: BundleLimits) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limits.name_bytes
    ):
        raise BundleError(
            "Bundle entry name must be a bounded nonempty string"
        )
    name = str.__str__(value)
    try:
        if len(name.encode("utf-8")) <= limits.name_bytes:
            return name
    except UnicodeEncodeError as exc:
        raise BundleError("Bundle entry name must be valid UTF-8") from exc
    raise BundleError("Bundle entry name exceeds its byte limit")


def _ciphertext(value: object, limits: BundleLimits) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limits.entry_chars
        or not value.isascii()
    ):
        raise BundleError("Bundle ciphertext must be a bounded ASCII string")
    return str.__str__(value)


def _checked_bundle(value: object, limits: BundleLimits) -> dict[str, str]:
    if not _dict(value) or len(value) > limits.entries:
        raise BundleError("BUNDLE must be a bounded dictionary")
    return {
        _entry_name(name, limits): _ciphertext(text, limits)
        for name, text in value.items()
    }


def _metadata(
    value: object,
    names: tuple[str, ...],
    limits: BundleLimits,
) -> BundleMetadata:
    if not _dict(value) or value.keys() != _META_FIELDS:
        raise BundleError("META must have exactly the fields of format 2")
    format_number = _version(value["format"])
    cipher = value["cipher"]
    created = value["created"]
    manifest = value["manifest"]
    entries = value["entries"]
    version = _version(value["version"])

    if format_number != BUNDLE_FORMAT or cipher != CIPHER_NAME:
        raise BundleError("Unsupported bundle format or cipher")
    if not isinstance(created, str) or _UTC.fullmatch(created) is None:
        raise BundleError("Invalid bundle creation timestamp")
    if not isinstance(manifest, str) or len(manifest) != _TAG_LENGTH:
        raise BundleError("Invalid manifest tag length")
    if not _entries(entries) or len(entries) != len(names):
        raise BundleError("META entries have an invalid length or type")
    entry_names = [_entry_name(name, limits) for name in entries]
    if set(entry_names) != set(names):
        raise BundleError("META entries differ from BUNDLE")
    return {
        "format": format_number,
        "cipher": CIPHER_NAME,
        "created": str.__str__(created),
        "version": version,
        "manifest": str.__str__(manifest),
        "entries": entry_names,
    }


class _LiteralBundle:
    """Parse the literal grammar emitted by the format-2 writer."""

    def __init__(self, text: str, limits: BundleLimits) -> None:
        self._text = text
        self._limits = limits
        self._offset = 0
        self._tokens = 0
        self._token_limit = 6 * limits.entries + limits.file_bytes // 20 + 128
        self._token = self._scan()

    def _scan(self) -> tuple[str, str]:
        while self._offset < len(self._text):
            token = _TOKEN.match(self._text, self._offset)
            if token is None or token.lastgroup is None:
                raise BundleError("Unexpected token in bundle data")
            self._offset = token.end()
            if token.lastgroup != "space":
                self._tokens += 1
                if self._tokens > self._token_limit:
                    raise BundleError("Bundle token limit exceeded")
                return token.lastgroup, token[0]
        return "end", ""

    def _consume(self, kind: str, value: str) -> bool:
        if self._token != (kind, value):
            return False
        self._token = self._scan()
        return True

    def _take(self, kind: str) -> str:
        actual, value = self._token
        if actual != kind:
            raise BundleError(f"Expected a bundle {kind}")
        self._token = self._scan()
        return value

    def _delimiter(self, value: str) -> None:
        if not self._consume("delimiter", value):
            raise BundleError("Invalid bundle delimiter")

    def _literal(self, limit: int) -> str:
        raw = self._take("string")
        if len(raw) > 10 * limit + 2:
            raise BundleError("Bundle literal is too long")
        if "\\" not in raw:
            return raw[1:-1]
        # Only a length-checked string token reaches literal_eval.
        try:
            decoded = cast("object", ast.literal_eval(raw))
        except (SyntaxError, ValueError) as exc:
            raise BundleError("Invalid bundle string literal") from exc
        if not isinstance(decoded, str):
            raise BundleError("Bundle literal must be a string")
        return decoded

    def _mapping[Value](
        self,
        value_for: Callable[[str], Value],
        maximum: int,
        *,
        metadata: bool = False,
    ) -> dict[str, Value]:
        values: dict[str, Value] = {}
        self._delimiter("{")
        while not self._consume("delimiter", "}"):
            name = (
                self._literal(_META_NAME_LENGTH) if metadata else self._name()
            )
            if name in values or len(values) >= maximum:
                raise BundleError(
                    "Repeated field or bundle entry limit exceeded"
                )
            self._delimiter(":")
            values[name] = value_for(name)
            if not self._consume("delimiter", ","):
                self._delimiter("}")
                break
        return values

    def _name(self) -> str:
        return _entry_name(
            self._literal(self._limits.name_bytes), self._limits
        )

    def _entry(self, _name: str) -> str:
        if not self._consume("delimiter", "("):
            return _ciphertext(
                self._literal(self._limits.entry_chars), self._limits
            )
        parts: list[str] = []
        length = 0
        while not self._consume("delimiter", ")"):
            part = self._literal(self._limits.entry_chars)
            length += len(part)
            if length > self._limits.entry_chars or not part:
                raise BundleError("Invalid ciphertext chunk length")
            parts.append(part)
        return _ciphertext("".join(parts), self._limits)

    def _meta_value(self, name: str) -> object:
        if name not in _META_FIELDS:
            raise BundleError("Unknown META field")
        if name in {"format", "version"}:
            raw = self._take("number")
            if len(raw) > _MAX_VERSION_DIGITS:
                raise BundleError("Release version is out of range")
            return _version(int(raw))
        if name == "entries":
            self._delimiter("[")
            names: list[str] = []
            while not self._consume("delimiter", "]"):
                if len(names) >= self._limits.entries:
                    raise BundleError("META entry limit exceeded")
                names.append(self._name())
                if not self._consume("delimiter", ","):
                    self._delimiter("]")
                    break
            return names
        return self._literal(max(_TAG_LENGTH, len(CIPHER_NAME)))

    def parse(self) -> tuple[dict[str, str], BundleMetadata]:
        """Return BUNDLE and validated META literals from the file."""
        bundle: dict[str, str] | None = None
        metadata: dict[str, object] | None = None
        while self._token[0] != "end":
            target = self._take("identifier")
            self._delimiter("=")
            if target == "BUNDLE" and bundle is None:
                bundle = self._mapping(self._entry, self._limits.entries)
            elif target == "META" and metadata is None:
                metadata = self._mapping(
                    self._meta_value, len(_META_FIELDS), metadata=True
                )
            else:
                raise BundleError("Unexpected or repeated bundle assignment")
        if bundle is None or metadata is None:
            raise BundleError("Bundle file requires BUNDLE and META")
        return bundle, _metadata(metadata, tuple(bundle), self._limits)


def _open_regular(path: str, flags: int) -> int:
    if os.name == "posix":
        flags |= os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except BaseException:
        os.close(fd)
        raise
    if not regular:
        os.close(fd)
        raise BundleError("Bundle path must refer to a regular file")
    return fd


def read_bundle_file(
    path: PathInput,
    *,
    limits: BundleLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, str], BundleMetadata]:
    """Read bounded bundle data without importing a Python file."""
    try:
        with open(_text_path(path), "rb", opener=_open_regular) as stream:
            raw = stream.read(limits.file_bytes + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise BundleError("Cannot read the bundle file") from exc
    if len(raw) > limits.file_bytes:
        raise BundleError("Bundle exceeds its file size limit")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError("Bundle must be valid UTF-8") from exc
    return _LiteralBundle(content, limits).parse()


def _manifest_bytes(
    meta: BundleMetadata,
    encrypted: Mapping[str, str],
    names: Iterable[str],
) -> bytes:
    lines = [
        "checklists-engine-manifest",
        f"format={meta['format']}",
        f"cipher={meta['cipher']}",
        f"created={meta['created']}",
        f"version={meta['version']}",
    ]
    lines.extend(
        f"entry={name!r}={hashlib.sha3_256(encrypted[name].encode('ascii')).hexdigest()}"
        for name in names
    )
    return "\n".join(lines).encode("utf-8")


def _authenticate(
    bundle: Mapping[str, str],
    meta: BundleMetadata,
    names: tuple[str, ...],
    key: bytes,
) -> ReleaseIdentity:
    canonical = _manifest_bytes(meta, bundle, names)
    try:
        blob = base64.b64decode(meta["manifest"], validate=True)
        if len(blob) != crypto.MESSAGE_OVERHEAD:
            raise BundleError("Invalid decoded manifest tag length")
        if crypto.decrypt(key, blob, aad=canonical):
            raise BundleError("Invalid manifest plaintext")
    except InvalidTag as exc:
        raise BundleError("Bundle manifest failed authentication") from exc
    except (binascii.Error, ValueError) as exc:
        raise BundleError("Invalid manifest encoding") from exc
    digest = hashlib.sha3_256(canonical).hexdigest()
    return ReleaseIdentity(meta["version"], digest)


def _bundle_lines(
    encrypted: Mapping[str, str],
    meta: BundleMetadata,
) -> Iterator[str]:
    yield "# Encrypted bundle in format 2. Load it as data.\n"
    yield "META = {\n"
    yield f"    'format': {meta['format']},\n"
    yield f"    'cipher': {meta['cipher']!r},\n"
    yield f"    'created': {meta['created']!r},\n"
    yield f"    'version': {meta['version']},\n"
    yield f"    'manifest': {meta['manifest']!r},\n"
    yield "    'entries': [\n"
    for name in meta["entries"]:
        yield f"        {name!r},\n"
    yield "    ],\n}\n\nBUNDLE = {\n"
    for name in meta["entries"]:
        yield f"    {name!r}: (\n"
        text = encrypted[name]
        for start in range(0, len(text), _B64_CHUNK):
            yield f"        {text[start : start + _B64_CHUNK]!r}\n"
        yield "    ),\n"
    yield "}\n"


def _fsync_directory(directory: Path) -> None:
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_chunks(
    stream: BinaryIO, lines: Iterator[str], byte_limit: int
) -> None:
    size = 0
    for line in lines:
        block = line.encode("utf-8")
        size += len(block)
        if size > byte_limit:
            raise BundleError("Encoded bundle exceeds its file size limit")
        stream.write(block)
    stream.flush()
    os.fsync(stream.fileno())


def _write_bundle_module(
    out_path: PathInput,
    encrypted: Mapping[str, str],
    meta: BundleMetadata,
    limits: BundleLimits,
) -> None:
    destination = Path(_text_path(out_path)).absolute()
    parent = destination.parent
    created: list[Path] = []
    for directory in (parent, *parent.parents):
        if directory.is_dir():
            break
        created.append(directory)
    parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".checklist-",
        suffix=".tmp",
        dir=parent,
    )
    published = False
    try:
        try:
            stream = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            _write_chunks(
                stream, _bundle_lines(encrypted, meta), limits.file_bytes
            )
        Path(temporary).replace(destination)
        published = True
        try:
            _fsync_directory(parent)
            for directory in created:
                _fsync_directory(directory.parent)
        except OSError as exc:
            raise BundlePublicationError(
                "Bundle was replaced but its directory could not be synced",
            ) from exc
    except BaseException as exc:
        if not published:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                exc.add_note("The owned temporary file could not be removed")
        raise


def _is_contract(value: object) -> TypeGuard[ContractClass]:
    return (
        is_class(value)
        and issubclass(value, (Step, Checklist))
        and value not in (Step, Checklist)
        and not inspect.isabstract(value)
    )


def _uses_deferred_annotations(module: ModuleType | None) -> bool:
    if module is None:
        return False
    try:
        source = inspect.getsource(module)
        if "__future__" not in source:
            return False
        tree = ast.parse(source)
    except (OSError, SyntaxError, TypeError):
        return False
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and statement.level == 0
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in tree.body
    )


def _contract_source(cls: ContractClass, *, defer_annotations: bool) -> str:
    try:
        source = textwrap.dedent(inspect.getsource(cls))
        tree = ast.parse(source)
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.ClassDef):
            raise BundleError("Contract source must define one class")
        if defer_annotations:
            source = "from __future__ import annotations\n\n" + source
        compile(source, "<contract>", "exec", dont_inherit=True)
        symbols = symtable.symtable(source, "<contract>", "exec")
    except (OSError, SyntaxError, TypeError, ValueError) as exc:
        raise BundleError("Cannot compile the contract source") from exc

    allowed = _ALLOWED_GLOBALS | {tree.body[0].name}
    scopes = [symbols]
    while scopes:
        scope = scopes.pop()
        scopes.extend(scope.get_children())
        for symbol in scope.get_symbols():
            if (
                symbol.is_global()
                and symbol.is_referenced()
                and not symbol.is_assigned()
                and symbol.get_name() not in allowed
            ):
                unavailable = symbol.get_name()
                raise BundleError(
                    f"Contract relies on unavailable name {unavailable!r}"
                )
    return source


def _validate_checklists(sources: Mapping[str, ContractClass]) -> None:
    checked: set[str] = set()
    for cls in sources.values():
        if not issubclass(cls, Checklist):
            continue
        try:
            _checklist_name(cls)
            _snapshot_policy(cls.on_error)
            steps = normalise_steps(cls.steps)
        except (ValueError, TypeError) as exc:
            raise BundleError("Invalid checklist configuration") from exc
        for name, _ in steps:
            if name not in checked:
                _validate_referenced_step(name, sources)
                checked.add(name)


def _validate_referenced_step(
    name: str, sources: Mapping[str, ContractClass]
) -> None:
    step = sources.get(name)
    if step is None or not issubclass(step, Step):
        raise BundleError(f"Checklist references a missing step {name!r}")
    action = step.run
    if not _is_synchronous_method(action):
        raise BundleError(f"Checklist step {name!r} must run synchronously")
    # A custom constructor can supply run on the instance.
    if (
        action is Step.run
        and step.__init__ is object.__init__
        and step.__new__ is object.__new__
        and cast("object", step.__getattribute__)
        is cast("object", object.__getattribute__)
    ):
        raise BundleError(f"Checklist step {name!r} must implement run")
    try:
        signature = inspect.signature(step, follow_wrapped=False)
    except (TypeError, ValueError):
        return
    try:
        signature.bind()
    except TypeError as exc:
        raise BundleError(
            f"Checklist step {name!r} requires constructor arguments"
        ) from exc


def build_bundle(
    sources: Mapping[str, ContractClass],
    key: crypto.Buffer,
    out_path: PathInput,
    version: int = 1,
    *,
    limits: BundleLimits = DEFAULT_LIMITS,
) -> PathInput:
    """Publish a format-2 bundle from trusted class sources."""
    raw_key = crypto.check_key(key)
    checked_version = _version(version)
    if not isinstance(sources, Mapping) or len(sources) > limits.entries:
        raise BundleError("Sources must be a bounded mapping")

    classes: dict[str, ContractClass] = {}
    for name, cls in sources.items():
        normalised = _entry_name(name, limits)
        if not _is_contract(cls):
            raise BundleError(
                "Each source must be a concrete contract subclass"
            )
        classes[normalised] = cls

    _validate_checklists(classes)
    encrypted: dict[str, str] = {}
    annotation_modes: dict[ModuleType | None, bool] = {}
    for name, cls in classes.items():
        module = inspect.getmodule(cls)
        if module not in annotation_modes:
            annotation_modes[module] = _uses_deferred_annotations(module)
        payload = _contract_source(
            cls, defer_annotations=annotation_modes[module]
        ).encode("utf-8")
        expected = 4 * ((len(payload) + crypto.MESSAGE_OVERHEAD + 2) // 3)
        if expected > limits.entry_chars:
            raise BundleError("Encoded contract exceeds its size limit")
        blob = crypto.encrypt(raw_key, payload, aad=name.encode("utf-8"))
        encrypted[name] = base64.b64encode(blob).decode("ascii")

    names = sorted(encrypted)
    meta: BundleMetadata = {
        "format": BUNDLE_FORMAT,
        "cipher": CIPHER_NAME,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": checked_version,
        "manifest": "",
        "entries": names,
    }
    canonical = _manifest_bytes(meta, encrypted, names)
    manifest = crypto.encrypt(raw_key, b"", aad=canonical)
    meta["manifest"] = base64.b64encode(manifest).decode("ascii")
    _write_bundle_module(out_path, encrypted, meta, limits)
    return out_path


class SecureRegistry:
    """Authenticate bundles and load trusted contracts on demand."""

    def __init__(
        self,
        bundle: object,
        key: crypto.Buffer,
        meta: object = None,
        min_version: int = 0,
        *,
        limits: BundleLimits = DEFAULT_LIMITS,
    ) -> None:
        """Copy the bundle and authenticate it before entries load."""
        self._bundle = _checked_bundle(bundle, limits)
        self._key = crypto.check_key(key)
        self._names = tuple(sorted(self._bundle))
        self._cache: dict[str, ContractClass] = {}
        self._pending: dict[str, Future[ContractClass]] = {}
        self._loading_threads: set[int] = set()
        self._lock = Lock()
        self.identity: ReleaseIdentity | None = None
        minimum = _version(min_version)
        if meta is not None:
            checked = _metadata(meta, self._names, limits)
            self.identity = _authenticate(
                self._bundle, checked, self._names, self._key
            )
        if minimum and (
            self.identity is None or self.identity.version < minimum
        ):
            raise BundleError(
                "Bundle fails the minimum release version requirement"
            )

    @property
    def version(self) -> int | None:
        """Return the authenticated release number when available."""
        return None if self.identity is None else self.identity.version

    def names(self) -> list[str]:
        """Return a copy of the sorted entry names."""
        return list(self._names)

    def __contains__(self, name: object) -> bool:
        """Return whether the registry has this string name."""
        return isinstance(name, str) and name in self._bundle

    def get(self, name: str) -> ContractClass:
        """Return one authenticated and cached class for this name."""
        if _execution_budget.deadline is None:
            return self._resolve_class(name)

        with _execution_budget.defer_interrupts():
            _execution_budget.remaining()
            result = self._resolve_class(name)
        _execution_budget.remaining()
        return result

    def _resolve_class(self, name: str) -> ContractClass:
        if name not in self._bundle:
            raise KeyError(f"No contract named {name!r}")
        caller = get_ident()
        with self._lock:
            cached = self._cache.get(name)
            if cached is not None:
                return cached
            if caller in self._loading_threads:
                raise BundleError("Recursive cold contract lookup")
            pending = self._pending.get(name)
            owner = pending is None
            if pending is None:
                pending = Future()
                self._pending[name] = pending
                self._loading_threads.add(caller)

        if not owner:
            return _await_class(pending)
        try:
            result = self._load_class(name)
            with self._lock:
                self._cache[name] = result
            pending.set_result(result)
        except BaseException as exc:
            if not pending.done():
                pending.set_exception(exc)
            raise
        finally:
            with self._lock:
                del self._pending[name]
                self._loading_threads.remove(caller)
        return result

    def instantiate(
        self, name: str, *args: object, **kwargs: object
    ) -> Contract:
        """Create a new instance of the named contract."""
        factory = cast("_ContractFactory", self.get(name))
        return factory(*args, **kwargs)

    def _load_class(self, name: str) -> ContractClass:
        try:
            blob = base64.b64decode(self._bundle[name], validate=True)
            plaintext = crypto.decrypt(
                self._key, blob, aad=name.encode("utf-8")
            )
            source = plaintext.decode("utf-8")
        except InvalidTag as exc:
            raise BundleError("Contract entry failed authentication") from exc
        except (binascii.Error, ValueError) as exc:
            raise BundleError("Invalid contract entry encoding") from exc

        namespace = _CONTRACT_API.copy()
        namespace.update(
            (module, import_module(module)) for module in _CONTRACT_MODULES
        )
        names_before = frozenset(namespace)
        try:
            code = compile(source, "<contract>", "exec", dont_inherit=True)
            # The publisher is trusted to run code in this process.
            exec(code, namespace)  # noqa: S102
        except StepTimeout:
            raise StepTimeout("Contract loading deadline expired") from None
        except Exception:  # noqa: BLE001 - Hide publisher error details.
            raise BundleError(
                "Cannot materialise authenticated contract"
            ) from None

        defined = [
            value
            for key, value in namespace.items()
            if key not in names_before and _is_contract(value)
        ]
        if len(defined) != 1:
            raise BundleError(
                "An entry must define exactly one contract class"
            )
        return defined[0]


def _await_class(pending: Future[ContractClass]) -> ContractClass:
    while (seconds := _execution_budget.remaining()) is not None:
        done, _ = wait((pending,), timeout=min(seconds, TIMEOUT_MAX))
        if done:
            break
    return pending.result()


def load_bundle(
    source: object,
    key: crypto.Buffer,
    min_version: int = 0,
    *,
    limits: BundleLimits = DEFAULT_LIMITS,
) -> SecureRegistry:
    """Load a file or a trusted bundle dictionary or module."""
    if _pathlike(source):
        bundle, meta = read_bundle_file(_text_path(source), limits=limits)
        return SecureRegistry(bundle, key, meta, min_version, limits=limits)
    if _dict(source):
        return SecureRegistry(
            source, key, min_version=min_version, limits=limits
        )
    if type(source) is ModuleType:
        fields = cast("Mapping[str, object]", vars(source))
        if "BUNDLE" not in fields:
            raise BundleError("Trusted module does not provide BUNDLE")
        return SecureRegistry(
            fields["BUNDLE"],
            key,
            fields.get("META"),
            min_version,
            limits=limits,
        )
    raise BundleError("Unsupported bundle source")


def load_release_bundle(
    path: PathInput,
    key: crypto.Buffer,
    *,
    state: ReleaseState,
    limits: BundleLimits = DEFAULT_LIMITS,
) -> SecureRegistry:
    """Authenticate and prepare a release before admission."""
    bundle, meta = read_bundle_file(path, limits=limits)
    registry = SecureRegistry(bundle, key, meta, limits=limits)
    identity = registry.identity
    if identity is None:
        raise BundleError("Release requires an authenticated manifest")

    def prepare() -> None:
        classes = {name: registry.get(name) for name in registry.names()}
        _validate_checklists(classes)

    state.accept(identity, prepare=prepare)
    return registry


class SQLiteReleaseState:
    """Persist release admission in a trusted local directory."""

    def __init__(
        self,
        path: PathInput,
        namespace: str,
        *,
        allow_initial: bool = False,
    ) -> None:
        """Select a database and a trusted release namespace."""
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("Expected a nonempty release namespace")
        if not isinstance(allow_initial, bool):
            raise TypeError("allow_initial must be bool")
        self._path = Path(_text_path(path)).absolute()
        self._namespace = namespace
        self._allow_initial = allow_initial

    def accept(
        self,
        release: ReleaseIdentity,
        *,
        prepare: Callable[[], None] | None = None,
    ) -> None:
        """Check and prepare a release in the acceptance transaction."""
        mode = "rwc" if self._allow_initial else "rw"
        uri = f"{self._path.as_uri()}?mode={mode}"
        try:
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                with connection:
                    self._accept(connection, release, prepare=prepare)
        except sqlite3.Error as exc:
            raise ReleaseStateError(
                "Cannot access trusted release state"
            ) from exc

    def _accept(
        self,
        connection: sqlite3.Connection,
        release: ReleaseIdentity,
        *,
        prepare: Callable[[], None] | None = None,
    ) -> None:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS accepted_releases ("
            "namespace TEXT PRIMARY KEY, version INTEGER NOT NULL, "
            "digest TEXT NOT NULL)",
        )
        current = self._current_release(connection)
        if current is None:
            if not self._allow_initial:
                raise ReleaseStateError(
                    "No enrolled release for this namespace"
                )
        elif release.version < current.version:
            raise ReleaseStateError(
                "Release is older than the accepted version"
            )
        elif (
            release.version == current.version
            and release.digest != current.digest
        ):
            raise ReleaseStateError(
                "Release conflicts with the accepted version"
            )

        if prepare is not None:
            prepare()
        if current is not None and release.version == current.version:
            return
        connection.execute(
            "INSERT INTO accepted_releases(namespace, version, digest) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(namespace) DO UPDATE SET version=excluded.version, "
            "digest=excluded.digest",
            (self._namespace, release.version, release.digest),
        )

    def _current_release(
        self, connection: sqlite3.Connection
    ) -> ReleaseIdentity | None:
        cursor = connection.execute(
            "SELECT version, digest FROM accepted_releases "
            "WHERE namespace = ?",
            (self._namespace,),
        )
        row = cast("tuple[object, object] | None", cursor.fetchone())
        if row is None:
            return None
        try:
            return ReleaseIdentity(_version(row[0]), _stored_digest(row[1]))
        except BundleError as exc:
            raise ReleaseStateError("Invalid stored release identity") from exc


def _stored_digest(value: object) -> str:
    if not isinstance(value, str):
        raise ReleaseStateError("Invalid digest in trusted state")
    return value
