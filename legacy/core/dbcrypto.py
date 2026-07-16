"""
legacy/core/dbcrypto.py
========================
Application-level field encryption for SQLite columns — closes the
database-encryption part of KL-001.

The problem: `memory.db` is a SQLite WAL database with frequent reads and
writes. Encrypting the entire file requires SQLCipher (commercial) or breaks
WAL atomicity guarantees. The correct zero-dependency alternative is to encrypt
sensitive VALUES before writing them: the database remains normal SQLite
(storing opaque text), WAL remains intact, and content at rest is no longer
plaintext.

Primitive: AES-256-GCM with a random nonce per value. The key (a 32-byte
database key) lives inside the encrypted vault, like the store key. They share
the same trust boundary: anyone who opens the vault can decrypt the database.

Token format (str, suitable for TEXT columns):

    gcmf1:<base64url(nonce(12) || ciphertext || tag(16))>

AAD (associated data): each value is bound to its CONTEXT, typically
`"<row_id>:<column>"`. Thus an attacker with write access to the database
cannot move an encrypted value to another row or column without invalidating
the tag. AAD is NOT encrypted; the caller must provide a stable, unique context.

Plaintext/ciphertext coexistence (transparent migration):
  - `is_encrypted(v)` identifies an encrypted token by its prefix.
  - `decrypt_field` returns plaintext values unchanged (a pre-migration
    database remains readable while it is being migrated).
  - `maybe_decrypt` is the read helper: decrypt if needed, otherwise return
    the value unchanged.

Pure module except for `secrets`, used for nonces.
"""
from __future__ import annotations

import base64
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

import secrets

FIELD_PREFIX = "gcmf1:"          # ciphertext
PLAIN_ESCAPE = "gcmf0:"          # plaintext escapado (ver escape_plaintext)
_NONCE_LEN = 12
_KEY_LEN = 32
_TAG_LEN = 16


class FieldCryptoError(ValueError):
    """Decryption failed: incorrect key, incorrect AAD, or tampered data."""


def is_encrypted(value: Optional[str]) -> bool:
    """Return True if `value` is a token encrypted by this module."""
    return isinstance(value, str) and value.startswith(FIELD_PREFIX)


# Plaintext collision escaping.

def escape_plaintext(value: str) -> str:
    """Return a plaintext storage form unambiguous with ciphertext."""
    if value.startswith(FIELD_PREFIX) or value.startswith(PLAIN_ESCAPE):
        return PLAIN_ESCAPE + value
    return value


def unescape_plaintext(stored: str) -> str:
    """Reverse escape_plaintext and recover the logical plaintext value."""
    if stored.startswith(PLAIN_ESCAPE):
        return stored[len(PLAIN_ESCAPE):]
    return stored


class FieldCipher:
    """
    Encrypt and decrypt column values with a 32-byte database key.

    key : 32 bytes. Kept only in memory while the vault is open; never
          persisted outside the encrypted vault.
    """

    def __init__(self, key: bytes) -> None:
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "The 'cryptography' package is required for field encryption."
            )
        if len(key) != _KEY_LEN:
            raise ValueError(f"The database key must be {_KEY_LEN} bytes, got {len(key)}.")
        self._aes = AESGCM(key)

    # Encryption and decryption.

    def encrypt_field(self, plaintext: str, aad: str) -> str:
        """
        Encrypt `plaintext`, binding it to `aad` (row:column context).

        ALWAYS encrypt the input as plaintext. Do NOT attempt to detect whether
        `plaintext` "already looks encrypted" (FIX R5-001): that heuristic
        misclassifies plaintext beginning with the ciphertext prefix and leaves
        it unencrypted. Migration idempotence is the caller's responsibility;
        callers skip columns already encrypted by checking `is_encrypted()` on
        the STORED form, not the logical value.
        """
        nonce = secrets.token_bytes(_NONCE_LEN)
        ct = self._aes.encrypt(
            nonce, plaintext.encode("utf-8"), aad.encode("utf-8")
        )
        return FIELD_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt_field(self, token: str, aad: str) -> str:
        """
        Decrypt a token. If `token` is plaintext (without the prefix), return it
        unchanged so a partially migrated database remains readable.
        Raise FieldCryptoError if a prefixed token cannot be decrypted.
        """
        if not is_encrypted(token):
            return token
        try:
            blob = base64.urlsafe_b64decode(token[len(FIELD_PREFIX):])
            nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            if len(nonce) != _NONCE_LEN or len(ct) < _TAG_LEN:
                raise ValueError("truncated token")
            return self._aes.decrypt(nonce, ct, aad.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            raise FieldCryptoError(
                f"Could not decrypt field (incorrect key/AAD or tampered "
                f"data): {exc}"
            ) from exc

    def maybe_decrypt(self, value: Optional[str], aad: str) -> Optional[str]:
        """Decrypt tokens; otherwise return the value unchanged. Preserve None."""
        if value is None:
            return None
        return self.decrypt_field(value, aad)
