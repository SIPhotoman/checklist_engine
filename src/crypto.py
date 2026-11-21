"""Authenticated encryption and key derivation for format 2."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12
TAG_SIZE = 16
MESSAGE_OVERHEAD = NONCE_SIZE + TAG_SIZE
KEY_SIZE = 32
VALID_KEY_SIZES = (16, 24, 32)
SALT_SIZE = 16
_MIN_SALT_SIZE = 8

ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_KIB = 2**16
ARGON2_OUTPUT = 64
MAX_KDF_LENGTH = 255 * hashes.SHA3_512.digest_size
MAX_KDF_ITERATIONS = 10
MAX_KDF_LANES = 16
MAX_KDF_MEMORY_KIB = 2**18
DEFAULT_INFO = b"checklists-engine/v1/bundle-key"

type Buffer = bytes | bytearray | memoryview

__all__ = [
    "DEFAULT_INFO",
    "KEY_SIZE",
    "MESSAGE_OVERHEAD",
    "NONCE_SIZE",
    "SALT_SIZE",
    "TAG_SIZE",
    "VALID_KEY_SIZES",
    "InvalidTag",
    "check_key",
    "decrypt",
    "derive_bundle_key",
    "derive_key",
    "encrypt",
]


def check_key(key: object) -> bytes:
    """Normalise a supported AES key and reject other lengths."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise ValueError("Key must be a bytes-like object")  # noqa: TRY004
    size = key.nbytes if isinstance(key, memoryview) else len(key)
    if size not in VALID_KEY_SIZES:
        raise ValueError("Key must be 16, 24 or 32 bytes")
    raw = bytes(key)
    if len(raw) not in VALID_KEY_SIZES:
        raise ValueError("Key length changed during conversion")
    return raw


def _utf8(value: object) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError("Passphrase and context must be str or bytes")


def _check_integer(value: object, lower: int, upper: int, name: str) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not lower <= value <= upper
    ):
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")


def derive_key(  # noqa: PLR0913 - Preserve explicit legacy KDF settings.
    passphrase: str | bytes,
    salt: bytes | bytearray,
    *,
    length: int = KEY_SIZE,
    info: str | bytes = DEFAULT_INFO,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_kib: int = ARGON2_MEMORY_KIB,
) -> bytes:
    """Derive an arbitrary-length output using Argon2id and HKDF."""
    _check_integer(length, 0, MAX_KDF_LENGTH, "length")
    _check_integer(iterations, 1, MAX_KDF_ITERATIONS, "iterations")
    _check_integer(lanes, 1, MAX_KDF_LANES, "lanes")
    _check_integer(memory_kib, 8 * lanes, MAX_KDF_MEMORY_KIB, "memory_kib")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < _MIN_SALT_SIZE:
        raise ValueError("Salt must contain at least eight bytes")

    password = _utf8(passphrase)
    context = _utf8(info)
    raw_salt = bytes(salt)
    secret = Argon2id(
        salt=raw_salt,
        length=ARGON2_OUTPUT,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_kib,
    ).derive(password)
    return HKDF(
        algorithm=hashes.SHA3_512(),
        length=length,
        salt=raw_salt,
        info=context,
    ).derive(secret)


def derive_bundle_key(  # noqa: PLR0913 - Match derive_key's parameters.
    passphrase: str | bytes,
    salt: bytes | bytearray,
    *,
    length: int = KEY_SIZE,
    info: str | bytes = DEFAULT_INFO,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_kib: int = ARGON2_MEMORY_KIB,
) -> bytes:
    """Derive a supported AES key from validated KDF parameters."""
    if type(length) is not int or length not in VALID_KEY_SIZES:
        raise ValueError("Bundle key length must be 16, 24 or 32 bytes")
    return derive_key(
        passphrase,
        salt,
        length=length,
        info=info,
        iterations=iterations,
        lanes=lanes,
        memory_kib=memory_kib,
    )


def encrypt(
    key: Buffer, plaintext: Buffer, aad: Buffer | None = None
) -> bytes:
    """Return a fresh nonce followed by ciphertext and its tag."""
    aead = AESGCMSIV(check_key(key))
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aead.encrypt(nonce, plaintext, aad)


def decrypt(key: Buffer, blob: Buffer, aad: Buffer | None = None) -> bytes:
    """Return verified plaintext and reject truncated inputs early."""
    raw_key = check_key(key)
    payload = bytes(blob)
    if len(payload) < NONCE_SIZE:
        raise ValueError("Ciphertext is shorter than its nonce")
    if len(payload) < MESSAGE_OVERHEAD:
        raise InvalidTag
    aead = AESGCMSIV(raw_key)
    return aead.decrypt(payload[:NONCE_SIZE], payload[NONCE_SIZE:], aad)
