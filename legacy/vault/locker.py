"""
legacy/vault/locker.py
=======================
AES-256-GCM encrypted vault for a digital legacy.

The vault stores legacy metadata (artifact index, access policy, and heir list)
as encrypted JSON. Raw artifacts are NOT stored in the vault; only their paths
and hashes are stored. The vault is the index, not the store.

v2 keyslot scheme (LUKS style):

  The payload is encrypted with a random 32-byte DATA KEY that never leaves
  the envelope in plaintext. The data key is wrapped in one or more independent
  keyslots:

    - slot "passphrase": data_key encrypted with AES-GCM under a key derived
      from the passphrase (PBKDF2-SHA256, 260,000 iterations).
    - slot "recovery":   data_key encrypted with a 32-byte recovery key,
      intended for Shamir distribution among custodians (see
      legacy/core/shamir.py).

  Advantages over v1 (one key derived from the passphrase):
    - rotating the passphrase rewraps one slot without re-encrypting the
      payload or invalidating other slots (custody survives rekey);
    - custodian recovery is cryptographic: without K shares, the recovery key
      does not exist anywhere.

  {
    "version":    "2",
    "nonce":      hex(12),           nonce of the payload
    "ciphertext": hex,               payload encrypted with the data key
    "tag":        hex(16),
    "vault_hash": sha256(plaintext),
    "keyslots": [
      {"type":"passphrase","kdf":"pbkdf2-sha256","iterations":260000,
       "salt":hex(32),"nonce":hex(12),"wrapped":hex},
      {"type":"recovery","nonce":hex(12),"wrapped":hex}
    ]
  }

Compatibility: open() reads v1 envelopes (the original format with a key
derived directly from the passphrase). The first seal() on a v1 vault
transparently migrates it to v2.

The passphrase, data key, and recovery key are never persisted in plaintext.

Dependency: `cryptography` (`pip install cryptography`).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

VAULT_VERSION = "2"
_PBKDF2_ITERATIONS = 260_000
_KEY_LEN = 32   # 256 bits
_NONCE_LEN = 12  # 96 bits  NIST recommendation for GCM
_SALT_LEN = 32

# Vault constants and authenticated-data domains.
_PAYLOAD_AAD = b"legacy-vault-payload-v2"
_SLOT_AAD = b"legacy-vault-keyslot-v2"


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required for the vault. "
            "Install it with: pip install cryptography"
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_KEY_LEN,
    )


# Keyslot wrapping and unwrapping.

def _wrap_passphrase_slot(data_key: bytes, passphrase: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    kek = _derive_key(passphrase, salt)
    wrapped = AESGCM(kek).encrypt(nonce, data_key, _SLOT_AAD)
    return {
        "type": "passphrase",
        "kdf": "pbkdf2-sha256",
        "iterations": _PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "wrapped": wrapped.hex(),
    }


def _wrap_recovery_slot(data_key: bytes, recovery_key: bytes) -> Dict[str, Any]:
    if len(recovery_key) != _KEY_LEN:
        raise ValueError(f"The recovery key must be {_KEY_LEN} bytes.")
    nonce = secrets.token_bytes(_NONCE_LEN)
    wrapped = AESGCM(recovery_key).encrypt(nonce, data_key, _SLOT_AAD)
    return {"type": "recovery", "nonce": nonce.hex(), "wrapped": wrapped.hex()}


def _unwrap_passphrase(envelope: Dict[str, Any], passphrase: str) -> bytes:
    """Try all passphrase slots; raise VaultAuthError if none opens."""
    for slot in envelope.get("keyslots", []):
        if slot.get("type") != "passphrase":
            continue
        try:
            kek = hashlib.pbkdf2_hmac(
                "sha256",
                passphrase.encode("utf-8"),
                bytes.fromhex(slot["salt"]),
                int(slot.get("iterations", _PBKDF2_ITERATIONS)),
                dklen=_KEY_LEN,
            )
            return AESGCM(kek).decrypt(
                bytes.fromhex(slot["nonce"]),
                bytes.fromhex(slot["wrapped"]),
                _SLOT_AAD,
            )
        except Exception:
            continue
    raise VaultAuthError("Incorrect passphrase or damaged vault.")


def _unwrap_recovery(envelope: Dict[str, Any], recovery_key: bytes) -> bytes:
    for slot in envelope.get("keyslots", []):
        if slot.get("type") != "recovery":
            continue
        try:
            return AESGCM(recovery_key).decrypt(
                bytes.fromhex(slot["nonce"]),
                bytes.fromhex(slot["wrapped"]),
                _SLOT_AAD,
            )
        except Exception:
            continue
    raise VaultAuthError(
        "Incorrect recovery key or the vault has no recovery slot."
    )


def _wrap_timelock_slot(
    data_key: bytes, squarings: int, modulus_bits: int
) -> Dict[str, Any]:
    """The puzzle wraps the data key directly; its AEAD is the wrap."""
    from legacy.core.timelock import create_puzzle
    return {"type": "timelock",
            "puzzle": create_puzzle(data_key, squarings, modulus_bits=modulus_bits)}


def _unwrap_timelock(envelope: Dict[str, Any], progress=None) -> bytes:
    from legacy.core.timelock import TimeLockError, solve_puzzle
    for slot in envelope.get("keyslots", []):
        if slot.get("type") != "timelock":
            continue
        try:
            return solve_puzzle(slot["puzzle"], progress=progress)
        except (TimeLockError, KeyError):
            continue
    raise VaultAuthError("The vault has no valid time-lock slot.")


class Vault:
    """
    AES-256-GCM encrypted vault with keyslots (v2).

    vault_path : .vault file where the envelope is persisted.
    If the file does not exist, the vault is empty and ready to create.
    """

    def __init__(self, vault_path: Path) -> None:
        _require_crypto()
        self._path = vault_path

    # File loading and atomic persistence.

    def _load_raw(self) -> Dict[str, Any]:
        if not self._path.exists():
            raise VaultNotFoundError(f"Vault not found: {self._path}")
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        _validate_envelope(raw)
        return raw

    def _write_raw(self, envelope: Dict[str, Any]) -> None:
        # Write to a temporary file, then replace atomically.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    @staticmethod
    def _decrypt_payload(raw: Dict[str, Any], data_key: bytes) -> Dict[str, Any]:
        ct = bytes.fromhex(raw["ciphertext"])
        tag = bytes.fromhex(raw["tag"])
        nonce = bytes.fromhex(raw["nonce"])
        try:
            plaintext = AESGCM(data_key).decrypt(nonce, ct + tag, _PAYLOAD_AAD)
        except Exception:
            raise VaultAuthError("Incorrect passphrase or damaged vault.")
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != raw["vault_hash"]:
            raise VaultCorruptError(
                f"vault_hash mismatch: expected {raw['vault_hash'][:16]}…, "
                f"got {actual_hash[:16]}…"
            )
        return json.loads(plaintext.decode("utf-8"))

    # Sealing and migration.

    def seal(self, data: Dict[str, Any], passphrase: str) -> None:
        """
        Encrypt and persist the data dictionary (v2 envelope).

        On an existing v2 vault, the passphrase must open one of its slots;
        the data key and all keyslots are preserved (custody survives every
        re-seal). On v1, the passphrase is validated and the envelope migrates
        to v2.

        FIX R4-001 (fail closed): sealing a READABLE envelope with a
        non-matching passphrase raises VaultAuthError instead of replacing it.
        The previous silent-overwrite behavior destroyed the payload and
        recovery slot, leaving custodian shares unusable without warning.
        Overwrite is allowed only when the envelope is corrupt or unreadable
        (disaster-recovery path), or when the file does not exist.
        """
        plaintext = json.dumps(data, sort_keys=True, ensure_ascii=True).encode("utf-8")
        vault_hash = hashlib.sha256(plaintext).hexdigest()

        data_key: Optional[bytes] = None
        keyslots: Optional[List[Dict[str, Any]]] = None
        if self._path.exists():
            raw: Optional[Dict[str, Any]] = None
            try:
                raw = self._load_raw()
            except (VaultCorruptError, json.JSONDecodeError, OSError):
                raw = None    # Unreadable envelope: replacement is allowed.
            if raw is not None:
                if raw.get("version") == "2":
                    # Preserve the data key and every existing keyslot.
                    data_key = _unwrap_passphrase(raw, passphrase)
                    keyslots = raw["keyslots"]
                else:
                    # Validate and migrate the legacy v1 envelope.
                    self._open_v1(raw, passphrase)

        if data_key is None:
            data_key = secrets.token_bytes(_KEY_LEN)
            keyslots = [_wrap_passphrase_slot(data_key, passphrase)]

        nonce = secrets.token_bytes(_NONCE_LEN)
        ct_and_tag = AESGCM(data_key).encrypt(nonce, plaintext, _PAYLOAD_AAD)

        self._write_raw({
            "version": VAULT_VERSION,
            "nonce": nonce.hex(),
            "ciphertext": ct_and_tag[:-16].hex(),
            "tag": ct_and_tag[-16:].hex(),
            "vault_hash": vault_hash,
            "keyslots": keyslots,
        })

    # Opening and recovery.

    def open(self, passphrase: str) -> Dict[str, Any]:
        """
        Decrypt and return the data dictionary (v1 or v2).
        Raise VaultAuthError if the passphrase is incorrect.
        Raise VaultCorruptError if the envelope is damaged.
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            return self._open_v1(raw, passphrase)
        data_key = _unwrap_passphrase(raw, passphrase)
        return self._decrypt_payload(raw, data_key)

    def _open_v1(self, raw: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
        """Open the original format with a key derived from the passphrase."""
        salt = bytes.fromhex(raw["salt"])
        nonce = bytes.fromhex(raw["nonce"])
        ct = bytes.fromhex(raw["ciphertext"])
        tag = bytes.fromhex(raw["tag"])
        key = _derive_key(passphrase, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ct + tag, None)
        except Exception:
            raise VaultAuthError("Incorrect passphrase or damaged vault.")
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != raw["vault_hash"]:
            raise VaultCorruptError(
                f"vault_hash mismatch: expected {raw['vault_hash'][:16]}…, "
                f"got {actual_hash[:16]}…"
            )
        return json.loads(plaintext.decode("utf-8"))

    def open_with_recovery(self, recovery_key: bytes) -> Dict[str, Any]:
        """
        Decrypt the vault with a recovery key reconstructed by custodians
        through Shamir. Available only for v2 vaults with a recovery slot.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError(
                "The vault is v1 and has no recovery keyslots. "
                "Open it with the passphrase to migrate it."
            )
        data_key = _unwrap_recovery(raw, recovery_key)
        return self._decrypt_payload(raw, data_key)

    # Recovery and time-lock keyslot management.

    def add_recovery_slot(self, passphrase: str, recovery_key: bytes) -> None:
        """
        Add or replace the recovery slot. Replacing it invalidates any previous
        share split; old custodians are effectively revoked. A v1 vault is
        migrated to v2 during this process.
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            data = self._open_v1(raw, passphrase)
            self.seal(data, passphrase)          # Migrate to v2.
            raw = self._load_raw()

        data_key = _unwrap_passphrase(raw, passphrase)
        slots = [s for s in raw["keyslots"] if s.get("type") != "recovery"]
        slots.append(_wrap_recovery_slot(data_key, recovery_key))
        raw["keyslots"] = slots
        self._write_raw(raw)

    def add_timelock_slot(
        self, passphrase: str, squarings: int, *, modulus_bits: int = 2048
    ) -> None:
        """
        Add or replace the time-lock slot: the data key also remains recoverable
        by solving a puzzle requiring `squarings` sequential squarings (KL-011,
        offline component). Migrate v1 to v2 when needed.

        This does NOT replace the passphrase or custody; it is an additional,
        independent path. It provides a work floor, not a wall clock (see
        legacy/core/timelock.py).
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            data = self._open_v1(raw, passphrase)
            self.seal(data, passphrase)
            raw = self._load_raw()
        data_key = _unwrap_passphrase(raw, passphrase)
        slots = [s for s in raw["keyslots"] if s.get("type") != "timelock"]
        slots.append(_wrap_timelock_slot(data_key, squarings, modulus_bits))
        raw["keyslots"] = slots
        self._write_raw(raw)

    def open_with_timelock(self, *, progress=None) -> Dict[str, Any]:
        """
        Decrypt the vault by SOLVING the time-lock puzzle. Slow by design
        (T sequential squarings). Available only for v2 vaults with a time-lock slot.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("The vault is v1 and has no time-lock slot.")
        data_key = _unwrap_timelock(raw, progress=progress)
        return self._decrypt_payload(raw, data_key)

    def remove_timelock_slot(self, passphrase: str) -> bool:
        """Remove the time-lock slot; return True if it existed."""
        raw = self._load_raw()
        if raw.get("version") != "2":
            return False
        _unwrap_passphrase(raw, passphrase)      # Authorize the operation.
        before = len(raw["keyslots"])
        raw["keyslots"] = [s for s in raw["keyslots"] if s.get("type") != "timelock"]
        if len(raw["keyslots"]) == before:
            return False
        self._write_raw(raw)
        return True

    def set_passphrase_with_timelock(
        self, new_passphrase: str, *, progress=None
    ) -> None:
        """
        Reset the passphrase by solving the time-lock puzzle once: the heir path
        to take possession without the passphrase or custodians. Solve the
        puzzle (slowly) and rewrap the passphrase slot with the recovered data key.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("The vault is v1 and has no time-lock slot.")
        data_key = _unwrap_timelock(raw, progress=progress)
        slots = [s for s in raw["keyslots"] if s.get("type") != "passphrase"]
        slots.insert(0, _wrap_passphrase_slot(data_key, new_passphrase))
        raw["keyslots"] = slots
        self._write_raw(raw)

    def timelock_info(self) -> Optional[Dict[str, Any]]:
        """Return time-lock slot parameters without solving the puzzle."""
        if not self._path.exists():
            return None
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        for slot in raw.get("keyslots", []):
            if slot.get("type") == "timelock":
                pz = slot.get("puzzle", {})
                return {"squarings": pz.get("squarings"),
                        "modulus_bits": pz.get("modulus_bits")}
        return None

    def has_timelock_slot(self) -> bool:
        return "timelock" in self.info().get("keyslots", [])

    def remove_recovery_slot(self, passphrase: str) -> bool:
        """Remove the recovery slot; return True if it existed."""
        raw = self._load_raw()
        if raw.get("version") != "2":
            return False
        _unwrap_passphrase(raw, passphrase)      # Authorize the operation.
        before = len(raw["keyslots"])
        raw["keyslots"] = [
            s for s in raw["keyslots"] if s.get("type") != "recovery"
        ]
        if len(raw["keyslots"]) == before:
            return False
        self._write_raw(raw)
        return True

    def rewrap_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        """
        Rotate the passphrase by rewrapping its keyslot. The payload and
        recovery slot remain intact (custody survives). A v1 vault is migrated
        by opening it with the old passphrase and re-sealing it as v2 with the new one.
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            data = self._open_v1(raw, old_passphrase)
            self._path.unlink()                  # force envelope v2 new
            self.seal(data, new_passphrase)
            return

        data_key = _unwrap_passphrase(raw, old_passphrase)
        slots = [s for s in raw["keyslots"] if s.get("type") != "passphrase"]
        slots.insert(0, _wrap_passphrase_slot(data_key, new_passphrase))
        raw["keyslots"] = slots
        self._write_raw(raw)

    def set_passphrase_with_recovery(
        self, recovery_key: bytes, new_passphrase: str
    ) -> None:
        """
        Reset the passphrase using the recovery key: the path for an owner who
        forgot it or for heirs after reconstruction by custodians.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("The vault is v1 and has no recovery slot.")
        data_key = _unwrap_recovery(raw, recovery_key)
        slots = [s for s in raw["keyslots"] if s.get("type") != "passphrase"]
        slots.insert(0, _wrap_passphrase_slot(data_key, new_passphrase))
        raw["keyslots"] = slots
        self._write_raw(raw)

    # Status and metadata.

    def exists(self) -> bool:
        return self._path.exists()

    def envelope_hash(self) -> Optional[str]:
        """Return the plaintext SHA-256 without decrypting it (the vault_hash field)."""
        if not self._path.exists():
            return None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return raw.get("vault_hash")

    def info(self) -> Dict[str, Any]:
        """Return envelope metadata without decrypting anything."""
        if not self._path.exists():
            return {"exists": False}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"exists": True, "version": None, "error": "envelope unreadable"}
        return {
            "exists": True,
            "version": raw.get("version"),
            "keyslots": [
                s.get("type") for s in raw.get("keyslots", [])
            ] if raw.get("version") == "2" else ["passphrase"],
        }

    def has_recovery_slot(self) -> bool:
        return "recovery" in self.info().get("keyslots", [])


# Envelope validation and error types.

def _validate_envelope(raw: Dict[str, Any]) -> None:
    version = raw.get("version")
    if version == "1":
        required = {"version", "salt", "nonce", "ciphertext", "tag", "vault_hash"}
    elif version == "2":
        required = {"version", "nonce", "ciphertext", "tag", "vault_hash", "keyslots"}
    else:
        raise VaultCorruptError(f"Unsupported vault version: {version!r}")
    missing = required - set(raw.keys())
    if missing:
        raise VaultCorruptError(f"Invalid envelope — missing fields: {missing}")
    if version == "2":
        slots = raw.get("keyslots")
        if not isinstance(slots, list) or not slots:
            raise VaultCorruptError("Envelope v2 without keyslots.")


# Implementation note.
# Implementation note.
# Implementation note.

class VaultError(Exception):
    pass

class VaultAuthError(VaultError):
    """Incorrect passphrase or invalid authentication tag."""

class VaultCorruptError(VaultError):
    """The envelope is structurally damaged."""

class VaultNotFoundError(VaultError):
    """The vault file does not exist."""
