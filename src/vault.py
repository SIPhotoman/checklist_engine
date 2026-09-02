"""Compiler and secure loader for encrypted contract classes.

Two halves:

* :func:`build_bundle` -- the *offline* tool. Give it ``{name: class}``
  and a key; it captures each class's source, encrypts it and writes an
  importable ``.py`` file holding a ``{name: ciphertext}`` dictionary.
  Source code never appears in that file.

* :class:`SecureRegistry` (via :func:`load_bundle`) -- the *runtime* half.
  It decrypts an entry on first use, executes it in a dedicated namespace
  and returns the live class object, caching it.

Each entry is authenticated on its own, and a manifest tag authenticates
the bundle as a whole -- its format, timestamp, version number and the
exact set of ciphertexts. Pair it with ``min_version`` on the device to
refuse a bundle that was rolled back to an older release.

Trust model: the key is the only boundary. Decrypted contract code runs
with full privileges, like any other module in the process -- this gives
the contracts confidentiality and integrity, not a sandbox.

Authoring rules for classes that will be encrypted:

* Each entry must contain exactly one top-level class, a subclass of
  :class:`contracts.Step` or :class:`contracts.Checklist`.
* :func:`inspect.getsource` captures only the class body, not the
  module's ``import`` lines. The loader pre-injects the contract API and
  a few standard modules (see :data:`_CONTRACT_MODULES`); anything else
  must be imported *inside* a method, where the source is captured.
"""

import ast
import base64
import binascii
import hashlib
import inspect
import os
import textwrap
import time

from cryptography.exceptions import InvalidTag

import crypto
from contracts import (
    Checklist,
    Context,
    ChecklistReport,
    OnError,
    Step,
    StepResult,
    StepTimeout,
)

__all__ = [
    "build_bundle",
    "load_bundle",
    "read_bundle_file",
    "SecureRegistry",
    "BundleError",
]

BUNDLE_FORMAT = 2
CIPHER_NAME = "AES-GCM-SIV"

# Base64 chunk width that keeps the generated module inside 79 columns.
_B64_CHUNK = 64

# Always visible to decrypted contract code, so a step body can use
# ``Step`` or ``time.sleep`` without a top-level import.
_CONTRACT_API = {
    "Step": Step,
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


class BundleError(Exception):
    """Raised for malformed bundles or contract source problems."""


# Offline half: turn plaintext classes into an encrypted bundle file.
def build_bundle(sources, key, out_path, version=1):
    """Encrypt ``sources`` into an importable bundle module at ``out_path``.

    :param sources: mapping ``{name: class}``; ``name`` is the lookup key,
        ``class`` any :class:`~contracts.Step` or
        :class:`~contracts.Checklist` subclass defined in a real ``.py``
        file (``inspect`` cannot read source from a REPL).
    :param key: raw AES-GCM-SIV key (16, 24 or 32 bytes).
    :param out_path: path of the ``.py`` file to (over)write.
    :param version: version number recorded in the manifest. Raise it on
        every release and have the device pass the last version it
        accepted as ``load_bundle(..., min_version=...)``, so an older
        bundle cannot be put back in place unnoticed.
    :returns: the ``out_path`` written.
    """
    key = crypto.check_key(key)
    if not isinstance(version, int) or isinstance(version, bool) \
            or version < 0:
        raise BundleError("version must be a non-negative integer")
    encrypted = {}
    for name, cls in sources.items():
        if not isinstance(name, str) or not name:
            raise BundleError("entry names must be non-empty strings")
        if not (isinstance(cls, type) and issubclass(cls, (Step, Checklist))):
            raise BundleError(
                "entry %r must be a Step or Checklist subclass, got %r"
                % (name, cls)
            )
        try:
            source = textwrap.dedent(inspect.getsource(cls))
        except (OSError, TypeError) as exc:
            raise BundleError("cannot read source for %r: %s" % (name, exc))
        # The name is bound as associated data, so a ciphertext encrypted
        # for "connect" will not authenticate in the "send" slot.
        blob = crypto.encrypt(
            key, source.encode("utf-8"), aad=name.encode("utf-8")
        )
        encrypted[name] = base64.b64encode(blob).decode("ascii")

    meta = {
        "format": BUNDLE_FORMAT,
        "cipher": CIPHER_NAME,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": version,
        "entries": sorted(encrypted),
    }
    meta["manifest"] = base64.b64encode(
        crypto.encrypt(key, b"", aad=_manifest_bytes(meta, encrypted))
    ).decode("ascii")
    _write_bundle_module(out_path, encrypted, meta)
    return out_path


def _manifest_bytes(meta, encrypted):
    """Serialise what the manifest tag authenticates, canonically.

    Covers the bundle's format, cipher, timestamp and version, plus the
    digest of every ciphertext under its own name in sorted order, so any
    added, removed, reordered or substituted entry changes the result.
    """
    for field in ("format", "cipher", "created", "version"):
        if field not in meta:
            raise BundleError("bundle META is missing %r" % (field,))
    if not isinstance(meta["format"], int) \
            or not isinstance(meta["version"], int):
        raise BundleError("bundle format and version must be integers")
    lines = [
        "checklists-engine-manifest",
        "format=%d" % meta["format"],
        "cipher=%s" % (meta["cipher"],),
        "created=%s" % (meta["created"],),
        "version=%d" % meta["version"],
    ]
    lines.extend(
        "entry=%r=%s"
        % (name, hashlib.sha3_256(encrypted[name].encode("utf-8")).hexdigest())
        for name in sorted(encrypted)
    )
    return "\n".join(lines).encode("utf-8")


def _verify_manifest(bundle, meta, key):
    """Authenticate a bundle as a whole before anything is decrypted.

    :raises BundleError: the tag is missing or does not match, which means
        entries were added, removed or replaced, META was edited, or the
        key belongs to a different bundle.
    """
    tag = meta.get("manifest")
    if not tag:
        raise BundleError(
            "bundle has no manifest tag; rebuild it with build_bundle"
        )
    if sorted(meta.get("entries", [])) != sorted(bundle):
        raise BundleError("bundle META lists different entries than BUNDLE")
    try:
        blob = base64.b64decode(tag, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise BundleError("manifest tag is not valid base64: %s" % exc)
    try:
        crypto.decrypt(key, blob, aad=_manifest_bytes(meta, bundle))
    except InvalidTag:
        raise BundleError(
            "bundle manifest failed authentication (wrong key, edited "
            "META, or entries added, removed or replaced)"
        )
    except ValueError as exc:
        raise BundleError("manifest tag is malformed: %s" % exc)


def _write_bundle_module(out_path, encrypted, meta):
    """Serialise the bundle as an importable module, atomically.

    The module is written to a temporary file in the same directory,
    flushed to disk and only then renamed over ``out_path``: a crash or a
    power cut mid-write leaves the previous bundle intact instead of a
    truncated one.
    """
    out_path = os.path.abspath(out_path)
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    lines = [
        "# -*- coding: utf-8 -*-",
        "# AUTO-GENERATED by vault.build_bundle -- do not edit by hand.",
        "# Each value is base64( nonce || AES-GCM-SIV ciphertext ) of one",
        "# contract class's source. The entry name is the associated data.",
        "# META is authenticated by the manifest tag it carries.",
        "",
        "META = {",
        "    \"format\": %d," % meta["format"],
        "    \"cipher\": \"%s\"," % meta["cipher"],
        "    \"created\": \"%s\"," % meta["created"],
        "    \"version\": %d," % meta["version"],
        "    \"manifest\": \"%s\"," % meta["manifest"],
        "    \"entries\": [",
    ]
    lines.extend("        %r," % (name,) for name in sorted(encrypted))
    lines += [
        "    ],",
        "}",
        "",
        "BUNDLE = {",
    ]
    for name in sorted(encrypted):
        lines.append("    %r: (" % (name,))
        text = encrypted[name]
        for start in range(0, len(text), _B64_CHUNK):
            lines.append("        %r" % text[start:start + _B64_CHUNK])
        lines.append("    ),")
    lines.append("}")
    lines.append("")

    temp_path = "%s.tmp-%d" % (out_path, os.getpid())
    try:
        with open(temp_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, out_path)
    except BaseException:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


# Runtime half: decrypt and materialise classes on demand.
class SecureRegistry:
    """Lazily decrypts and instantiates contract classes from a bundle.

    Decryption happens the first time a name is requested; the resulting
    class object is then cached for the lifetime of the registry.
    """

    def __init__(self, bundle, key, meta=None, min_version=0):
        """:param bundle: ``{name: base64_ciphertext}`` mapping.
        :param key: raw AES-GCM-SIV key.
        :param meta: the bundle's ``META`` dict. When given, its manifest
            tag is verified against every ciphertext up front, so a
            tampered bundle is rejected before anything is decrypted.
        :param min_version: refuse a bundle older than this. Record the
            version last accepted on the device and pass it here; without
            it nothing stops an old bundle being put back in place.
        """
        if not isinstance(bundle, dict):
            raise BundleError(
                "bundle must be a dict, got %r" % (type(bundle),)
            )
        for name, value in bundle.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise BundleError(
                    "bundle must map str names to str ciphertexts"
                )
        self._bundle = dict(bundle)
        self._key = crypto.check_key(key)
        self._class_cache = {}
        self.version = None
        if meta is not None:
            _verify_manifest(self._bundle, meta, self._key)
            self.version = meta["version"]
        if min_version:
            if self.version is None:
                raise BundleError(
                    "min_version needs a bundle with a manifest; load it "
                    "from a generated file rather than a bare dict"
                )
            if self.version < min_version:
                raise BundleError(
                    "bundle version %d is older than the minimum accepted "
                    "version %d (rollback refused)"
                    % (self.version, min_version)
                )

    def names(self):
        """Return the sorted contract names available in the bundle."""
        return sorted(self._bundle)

    def __contains__(self, name):
        return name in self._bundle

    def get(self, name):
        """Return the live class object for ``name``, decrypting if needed.

        :raises KeyError: ``name`` is not in the bundle.
        :raises BundleError: the entry is malformed, wrong-keyed, tampered
            with, or does not define exactly one contract class.
        """
        if name in self._class_cache:
            return self._class_cache[name]
        if name not in self._bundle:
            raise KeyError("no contract named %r in bundle" % (name,))

        try:
            blob = base64.b64decode(self._bundle[name], validate=True)
        except (binascii.Error, TypeError, ValueError) as exc:
            raise BundleError("entry %r is not valid base64: %s" % (name, exc))
        try:
            plaintext = crypto.decrypt(
                self._key, blob, aad=name.encode("utf-8")
            )
        except InvalidTag:
            raise BundleError(
                "entry %r failed authentication (wrong key or tampered data)"
                % (name,)
            )
        except ValueError as exc:
            raise BundleError("entry %r is malformed: %s" % (name, exc))
        try:
            source = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError("entry %r is not valid UTF-8: %s" % (name, exc))

        cls = self._materialise(name, source)
        self._class_cache[name] = cls
        return cls

    def instantiate(self, name, *args, **kwargs):
        """Return a fresh instance of the contract class ``name``."""
        return self.get(name)(*args, **kwargs)

    def _materialise(self, name, source):
        """Execute decrypted ``source``; return its one contract class."""
        namespace = self._fresh_namespace()
        before = set(namespace)
        try:
            exec(compile(source, "<contract:%s>" % name, "exec"), namespace)
        except Exception as exc:
            raise BundleError("error executing contract %r: %r" % (name, exc))

        defined = [
            value
            for key, value in namespace.items()
            if key not in before
            and isinstance(value, type)
            and issubclass(value, (Step, Checklist))
        ]
        if len(defined) != 1:
            raise BundleError(
                "entry %r must define exactly one contract class, found %d"
                % (name, len(defined))
            )
        return defined[0]

    @staticmethod
    def _fresh_namespace():
        """Build the globals dict used to exec one contract class."""
        namespace = dict(_CONTRACT_API)
        for module_name in _CONTRACT_MODULES:
            namespace[module_name] = __import__(module_name)
        return namespace


def load_bundle(source, key, min_version=0):
    """Convenience constructor for :class:`SecureRegistry`.

    :param source: a ``{name: base64}`` dict, a module object exposing
        ``BUNDLE``, or a path to a generated bundle ``.py`` file. A bare
        dict carries no ``META``, so it can be neither manifest-checked
        nor version-checked; prefer the path form on a device.
    :param key: raw AES-GCM-SIV key.
    :param min_version: lowest bundle version this device will accept.
    """
    meta = None
    if isinstance(source, dict):
        bundle = source
    elif hasattr(source, "BUNDLE"):
        bundle = source.BUNDLE
        meta = getattr(source, "META", None)
    elif isinstance(source, str):
        bundle, meta = read_bundle_file(source)
    else:
        raise BundleError("unsupported bundle source: %r" % (type(source),))
    return SecureRegistry(bundle, key, meta, min_version)


def read_bundle_file(path):
    """Extract the ``BUNDLE`` and ``META`` literals from a bundle module.

    The file is parsed, never executed: only literal ``BUNDLE`` and
    ``META`` assignments are read. Executing it would let anyone who can
    write to the file run code before a single key check, which would
    defeat the point of the vault. Authenticating what is read is the
    caller's job -- see :func:`_verify_manifest`.

    :returns: a ``(bundle, meta)`` pair.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
    except (OSError, SyntaxError, ValueError) as exc:
        raise BundleError("cannot read bundle %r: %s" % (path, exc))

    literals = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id in ("BUNDLE", "META"):
                try:
                    literals[target.id] = ast.literal_eval(node.value)
                except ValueError as exc:
                    raise BundleError(
                        "%s in %r is not a literal: %s"
                        % (target.id, path, exc)
                    )

    meta = literals.get("META") or {}
    if meta.get("format", BUNDLE_FORMAT) != BUNDLE_FORMAT:
        raise BundleError(
            "bundle %r has format %r, expected %d"
            % (path, meta.get("format"), BUNDLE_FORMAT)
        )
    if "BUNDLE" not in literals:
        raise BundleError("file %r does not define BUNDLE" % (path,))
    return literals["BUNDLE"], meta
