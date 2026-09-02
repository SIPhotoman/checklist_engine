"""Authenticated encryption and key derivation for the checklist engine.

Contracts are protected with AES-GCM-SIV (RFC 8452): an authenticated
cipher that also tolerates nonce reuse, which matters on boards without a
dependable random source. Tampering is detected at decryption time and
reported as ``InvalidTag``.

:func:`derive_key` turns a passphrase into a key in two stages -- Argon2id
to absorb the cost of guessing, then HKDF-SHA3-512 to bind the result to a
purpose.
:func:`encrypt` and :func:`decrypt` take an already-derived raw key.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12
KEY_SIZE = 32
VALID_KEY_SIZES = (16, 24, 32)
SALT_SIZE = 16

ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_KIB = 2 ** 16
ARGON2_OUTPUT = 64

# Domain separator for the HKDF stage
DEFAULT_INFO = b"checklists-engine/v1/bundle-key"

__all__ = [
    "NONCE_SIZE",
    "KEY_SIZE",
    "VALID_KEY_SIZES",
    "SALT_SIZE",
    "DEFAULT_INFO",
    "InvalidTag",
    "check_key",
    "derive_key",
    "encrypt",
    "decrypt",
]


def check_key(key):
    """Return ``key`` as bytes, raising ``ValueError`` if it is unusable."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise ValueError("key must be bytes, got %s" % type(key).__name__)
    key = bytes(key)
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("key must be 16, 24 or 32 bytes, got %d" % len(key))
    return key


def derive_key(passphrase, salt, *, length=KEY_SIZE, info=DEFAULT_INFO,
               iterations=ARGON2_ITERATIONS, lanes=ARGON2_LANES,
               memory_kib=ARGON2_MEMORY_KIB):
    """Derive a key from a passphrase with Argon2id, then HKDF-SHA3-512.

    The Argon2id defaults (t=3, p=4, m=64 MiB) suit a single-board
    computer. A board that cannot spare 64 MiB may lower ``memory_kib``,
    at the cost of weaker resistance to offline guessing; every parameter
    used at derivation time must be repeated to re-derive the same key.

    :param passphrase: ``str`` or ``bytes`` secret.
    :param salt: at least 8 bytes (:data:`SALT_SIZE` recommended). Need
        not be secret, only unique; store it next to the bundle so the
        same key can be re-derived.
    :param length: key length in bytes.
    :param info: ``str`` or ``bytes`` context binding for the HKDF stage.
    :param iterations: Argon2id time cost.
    :param lanes: Argon2id parallelism.
    :param memory_kib: Argon2id memory cost in KiB, at least ``8 * lanes``.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if isinstance(info, str):
        info = info.encode("utf-8")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    if iterations < 1 or lanes < 1:
        raise ValueError("iterations and lanes must be >= 1")
    if memory_kib < 8 * lanes:
        raise ValueError(
            "memory_kib must be at least 8 * lanes (%d)" % (8 * lanes)
        )
    salt = bytes(salt)

    secret = Argon2id(
        salt=salt,
        length=ARGON2_OUTPUT,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_kib,
    ).derive(passphrase)
    return HKDF(
        algorithm=hashes.SHA3_512(),
        length=length,
        salt=salt,
        info=info,
    ).derive(secret)


def encrypt(key, plaintext, aad=None):
    """Encrypt ``plaintext``; return ``nonce || ciphertext``.

    :param aad: associated data -- authenticated but not encrypted. The
        vault binds each entry's name here so a ciphertext cannot be moved
        to another slot in the bundle unnoticed.
    """
    aead = AESGCMSIV(check_key(key))
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aead.encrypt(nonce, plaintext, aad)


def decrypt(key, blob, aad=None):
    """Reverse :func:`encrypt`.

    :param blob: ``nonce || ciphertext`` produced by :func:`encrypt`.
    :param aad: must match the value used at encryption time.
    :raises InvalidTag: wrong key or tampered data.
    :raises ValueError: blob too short, or unusable key.
    """
    aead = AESGCMSIV(check_key(key))
    if len(blob) < NONCE_SIZE:
        raise ValueError("ciphertext blob is shorter than the nonce")
    return aead.decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
