"""
legacy/vault/artifact_store.py
===============================
Encrypted store for raw artifacts — closes KL-002.

The vault (`locker.py`) protects the index; this module protects the files
themselves. Each artifact is encrypted with AES-256-GCM and content-addressed:
the identifier is the SHA-256 of the plaintext, the same `content_hash` already
recorded by the vault index.

Properties:
  - Content-addressed : same content → same id; put() is idempotent.
  - Double integrity  : the GCM tag authenticates ciphertext; after decryption,
                        the plaintext SHA-256 must match the id.
  - AAD               : the id is associated data; an envelope cannot be
                        renamed to another id without invalidating the tag.
  - Atomic write      : tmp + rename(2), like the vault.

Binary envelope format (without JSON: artifacts can be large and hex would
double the size):

  MAGIC(8) | salt(32) | nonce(12) | ciphertext+tag(resto)

Key derivation: PBKDF2-SHA256, 260,000 iterations (same as the vault), with a
random per-file salt. The passphrase is never persisted.

Disk layout: <store_dir>/<id[:2]>/<id>.enc — two levels prevent filesystem
degradation when a directory contains thousands of files.
"""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Dict, List

from legacy.vault.locker import (
    VaultAuthError,
    VaultCorruptError,
    VaultNotFoundError,
    _derive_key,
    _require_crypto,
)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # _require_crypto() reports the error when the store is used.
    AESGCM = None  # type: ignore[assignment]

STORE_MAGIC = b"LGCYART1"       # v1: passphrase-derived key (PBKDF2)
STORE_MAGIC_V2 = b"LGCYART2"    # v2: raw 32-byte store key from the vault.
_SALT_LEN = 32
_NONCE_LEN = 12
_HEADER_LEN = len(STORE_MAGIC) + _SALT_LEN + _NONCE_LEN
_HEADER_V2_LEN = len(STORE_MAGIC_V2) + _NONCE_LEN
_GCM_TAG_LEN = 16
_KEY_LEN = 32

# Secret validation helpers.
Secret = "str | bytes"


def _require_str(secret, artifact_hash: str) -> str:
    if not isinstance(secret, str):
        raise VaultAuthError(
            f"Artifact {artifact_hash[:16]}… is v1 — requires a passphrase "
            f"(str), not a raw key."
        )
    return secret


def _require_key(secret, artifact_hash: str) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != _KEY_LEN:
        raise VaultAuthError(
            f"Artifact {artifact_hash[:16]}… is v2 — requires the {_KEY_LEN}-byte "
            f"store key (stored in the vault), not a passphrase."
        )
    return bytes(secret)


class ArtifactStore:
    """
    Content-addressed encrypted store.

    store_dir : store root directory (created if it does not exist).
    """

    def __init__(self, store_dir: Path) -> None:
        _require_crypto()
        self._dir = store_dir

    # Path and envelope helpers.

    def _path_for(self, artifact_hash: str) -> Path:
        return self._dir / artifact_hash[:2] / f"{artifact_hash}.enc"

    # Encryption and storage.

    def _write_envelope(self, artifact_hash: str, data: bytes, secret) -> None:
        """
        Encrypt `data` and write the envelope atomically, replacing any file.
        str secret → v1 envelope (PBKDF2); bytes(32) → v2 envelope (raw key).
        """
        nonce = secrets.token_bytes(_NONCE_LEN)
        if isinstance(secret, str):
            salt = secrets.token_bytes(_SALT_LEN)
            key = _derive_key(secret, salt)
            header = STORE_MAGIC + salt + nonce
        else:
            key = _require_key(secret, artifact_hash)
            header = STORE_MAGIC_V2 + nonce
        ct_and_tag = AESGCM(key).encrypt(nonce, data, artifact_hash.encode("ascii"))

        dest = self._path_for(artifact_hash)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(header + ct_and_tag)
        tmp.replace(dest)

    def put_bytes(self, data: bytes, secret) -> str:
        """
        Encrypt and store `data`. Return its plaintext SHA-256 hex identifier.
        Idempotent: if the id already exists, do not rewrite it.
        secret: passphrase (str, v1 envelope) or store key (bytes, v2 envelope).
        """
        artifact_hash = hashlib.sha256(data).hexdigest()
        if self._path_for(artifact_hash).exists():
            return artifact_hash
        self._write_envelope(artifact_hash, data, secret)
        return artifact_hash

    def put(self, path: Path, secret) -> str:
        """Encrypt and store the complete file at `path`."""
        return self.put_bytes(path.read_bytes(), secret)

    # Envelope inspection and reads.

    def envelope_version(self, artifact_hash: str) -> str:
        """Return '1' (passphrase) or '2' (store key); raise if missing."""
        src = self._path_for(artifact_hash)
        if not src.exists():
            raise VaultNotFoundError(
                f"Artifact {artifact_hash[:16]}… is not in the store."
            )
        with src.open("rb") as f:
            magic = f.read(8)
        if magic == STORE_MAGIC:
            return "1"
        if magic == STORE_MAGIC_V2:
            return "2"
        raise VaultCorruptError(
            f"Damaged or unknown envelope format: {src.name}"
        )

    def get(self, artifact_hash: str, secret) -> bytes:
        """
        Decrypt and return the artifact plaintext. The secret type must match
        the envelope: passphrase (str) for v1, store key (bytes) for v2.
        Raises VaultNotFoundError, VaultCorruptError, or VaultAuthError.
        """
        src = self._path_for(artifact_hash)
        if not src.exists():
            raise VaultNotFoundError(
                f"Artifact {artifact_hash[:16]}… is not in the store."
            )

        raw = src.read_bytes()
        if raw.startswith(STORE_MAGIC) and len(raw) >= _HEADER_LEN + _GCM_TAG_LEN:
            passphrase = _require_str(secret, artifact_hash)
            salt = raw[len(STORE_MAGIC): len(STORE_MAGIC) + _SALT_LEN]
            nonce = raw[len(STORE_MAGIC) + _SALT_LEN: _HEADER_LEN]
            ct_and_tag = raw[_HEADER_LEN:]
            key = _derive_key(passphrase, salt)
        elif raw.startswith(STORE_MAGIC_V2) and len(raw) >= _HEADER_V2_LEN + _GCM_TAG_LEN:
            key = _require_key(secret, artifact_hash)
            nonce = raw[len(STORE_MAGIC_V2): _HEADER_V2_LEN]
            ct_and_tag = raw[_HEADER_V2_LEN:]
        else:
            raise VaultCorruptError(
                f"Damaged or unknown envelope format: {src.name}"
            )

        try:
            plaintext = AESGCM(key).decrypt(
                nonce, ct_and_tag, artifact_hash.encode("ascii")
            )
        except Exception:
            raise VaultAuthError(
                "Incorrect secret or tampered envelope "
                f"(artifact {artifact_hash[:16]}…)."
            )

        actual = hashlib.sha256(plaintext).hexdigest()
        if actual != artifact_hash:
            # The authenticated plaintext must also match the content address.
            raise VaultCorruptError(
                f"Plaintext hash does not match the id: expected "
                f"{artifact_hash[:16]}…, got {actual[:16]}…"
            )
        return plaintext

    def restore(self, artifact_hash: str, dest: Path, secret) -> Path:
        """Decrypt the artifact and write it to `dest` atomically."""
        data = self.get(artifact_hash, secret)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        return dest

    # Queries and verification.

    def exists(self, artifact_hash: str) -> bool:
        return self._path_for(artifact_hash).exists()

    def list_hashes(self) -> List[str]:
        """Return stored ids in deterministic order."""
        if not self._dir.exists():
            return []
        return sorted(p.stem for p in self._dir.glob("*/*.enc"))

    def verify(self, artifact_hash: str, secret) -> bool:
        """Return True if the artifact decrypts and its hash matches the id."""
        try:
            self.get(artifact_hash, secret)
            return True
        except (VaultAuthError, VaultCorruptError, VaultNotFoundError):
            return False

    # Key rotation and envelope conversion.

    def rekey(self, old_passphrase: str, new_passphrase: str) -> Dict[str, int]:
        """
        Re-encrypt v1 artifacts with the new passphrase. v2 artifacts do not
        depend on the passphrase and are untouched (counted as skipped).
        Each envelope is rewritten atomically; the id does not change.

        Repeatable after a crash during rotation: a v1 artifact that no longer
        decrypts with the old passphrase is tried with the new one. If it works,
        it was already rotated and is skipped. If neither works, abort
        (incorrect passphrase or corrupted envelope).
        """
        rotated = 0
        skipped = 0
        for h in self.list_hashes():
            if self.envelope_version(h) == "2":
                skipped += 1            # v2: independent of the passphrase.
                continue
            try:
                data = self.get(h, old_passphrase)
            except VaultAuthError:
                if self.verify(h, new_passphrase):
                    skipped += 1        # Already rotated in a previous run.
                    continue
                raise VaultAuthError(
                    f"Artifact {h[:16]}… decrypts with neither passphrase — "
                    f"corrupted or incorrect passphrase. Rotation aborted."
                )
            self._write_envelope(h, data, new_passphrase)
            rotated += 1
        return {"rotated": rotated, "skipped": skipped}

    def convert_to_key(self, passphrase: str, store_key: bytes) -> Dict[str, int]:
        """
        Migrate all v1 (passphrase) envelopes to v2 (store key).
        After conversion, artifacts no longer depend on the passphrase:
        passphrase rotation leaves them untouched and custody recovery can
        decrypt them because the store key travels inside the vault.

        Repeatable: existing v2 envelopes are skipped. A v1 envelope that cannot
        be decrypted with the passphrase aborts conversion (fail closed).
        """
        converted = 0
        skipped = 0
        for h in self.list_hashes():
            if self.envelope_version(h) == "2":
                skipped += 1
                continue
            data = self.get(h, passphrase)      # VaultAuthError  aborta
            self._write_envelope(h, data, store_key)
            converted += 1
        return {"converted": converted, "skipped": skipped}
