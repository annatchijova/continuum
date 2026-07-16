"""
legacy/vault/locker.py
=======================
Vault encrypted AES-256-GCM for the legado digital.

the vault almacena the metadatos of the legado (index of artifacts,
politica of acceso, lista of heirs) as JSON encrypted.
the artifacts crudos NO is almacenan in the vault  only sus
rutas and hashes. the vault is the index, no the store.

Esquema v2  keyslots (style LUKS):

  the payload is encrypts with a DATA KEY aleatoria of 32 bytes that nunca
  sale of the envelope in plaintext. the data key is "envuelve" (wrap) in uno o
  more keyslots independientes:

    - slot "passphrase": data_key encrypted with AES-GCM under a key
      derivada of the passphrase (PBKDF2-SHA256, 260 000 iteraciones).
    - slot "recovery":   data_key encrypted with AES-GCM under a key of
      recovery of 32 bytes (pensada for repartirse between custodios
      with Shamir  ver legacy/core/shamir.py).

  Ventajas over v1 (a sola key derivada of the passphrase):
    - rotar the passphrase = re-envolver a slot (rewrap), without re-encrypt
      the payload ni invalidar the demas slots (the custodia sobrevive
      to the rekey);
    - the recovery by custodios is criptografica: without K shares the
      recovery key does not exist in no lado.

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

Compatibilidad: open() reads envelopes v1 (formato original with the key
derivada directamente of the passphrase). the primer seal() over a vault
v1 it migra a v2 of forma transparente.

the passphrase, the data key and the recovery key nunca is persisten in plaintext.

Dependencia: `cryptography` (pip install cryptography).
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

# Implementation note.
# Implementation note.
_PAYLOAD_AAD = b"legacy-vault-payload-v2"
_SLOT_AAD = b"legacy-vault-keyslot-v2"


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "the paquete 'cryptography' is required for the vault. "
            "install with: pip install cryptography"
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_KEY_LEN,
    )


# Implementation note.
# Implementation note.
# Implementation note.

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
        raise ValueError(f"La recovery key debe tener {_KEY_LEN} bytes.")
    nonce = secrets.token_bytes(_NONCE_LEN)
    wrapped = AESGCM(recovery_key).encrypt(nonce, data_key, _SLOT_AAD)
    return {"type": "recovery", "nonce": nonce.hex(), "wrapped": wrapped.hex()}


def _unwrap_passphrase(envelope: Dict[str, Any], passphrase: str) -> bytes:
    """Prueba all the slots of passphrase; VaultAuthError if ninguno opens."""
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
    raise VaultAuthError("Passphrase incorrect o vault damaged.")


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
        "Recovery key incorrect o the vault does not have slot of recovery."
    )


def _wrap_timelock_slot(
    data_key: bytes, squarings: int, modulus_bits: int
) -> Dict[str, Any]:
    """the puzzle envuelve the data key directamente (su AEAD is the wrap)."""
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
    raise VaultAuthError("the vault does not have a slot time-lock valid.")


class Vault:
    """
    Vault encrypted AES-256-GCM with keyslots (v2).

    vault_path : file .vault where is persiste the envelope.
    if the file does not exist, the vault is empty and listo for crear.
    """

    def __init__(self, vault_path: Path) -> None:
        _require_crypto()
        self._path = vault_path

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _load_raw(self) -> Dict[str, Any]:
        if not self._path.exists():
            raise VaultNotFoundError(f"Vault no encontrado: {self._path}")
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        _validate_envelope(raw)
        return raw

    def _write_raw(self, envelope: Dict[str, Any]) -> None:
        # Implementation note.
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
            raise VaultAuthError("Passphrase incorrect o vault damaged.")
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != raw["vault_hash"]:
            raise VaultCorruptError(
                f"vault_hash no coincide: esperado {raw['vault_hash'][:16]}…, "
                f"obtenido {actual_hash[:16]}…"
            )
        return json.loads(plaintext.decode("utf-8"))

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def seal(self, data: Dict[str, Any], passphrase: str) -> None:
        """
        encrypts and persiste the dict of data (envelope v2).

        over a vault v2 existente, the passphrase must open alguno of
        sus slots: the data key and all the keyslots is preservan (the
        custodia sobrevive a each re-sellado). over a v1, the passphrase
        is valida and the envelope is migra a v2.

        FIX R4-001 (fail closed): seal over a envelope LEGIBLE with a
        passphrase that no corresponde lanza VaultAuthError instead of
        reemplazarlo  the semantica previous of overwrite silenciosa
        destruia the payload and the slot of recovery (the shares of the
        custodios quedaban inservibles without no ruido). the overwrite
        only is allows if the envelope is corrupto o unreadable (camino of
        recovery of desastre) o if the file does not exist.
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
                raw = None    # envelope unreadable  is allows replace
            if raw is not None:
                if raw.get("version") == "2":
                    # Implementation note.
                    data_key = _unwrap_passphrase(raw, passphrase)
                    keyslots = raw["keyslots"]
                else:
                    # Implementation note.
                    # Implementation note.
                    # Implementation note.
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

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def open(self, passphrase: str) -> Dict[str, Any]:
        """
        decrypts and returns the dict of data (v1 o v2).
        Lanza VaultAuthError if the passphrase is incorrect.
        Lanza VaultCorruptError if the envelope is damaged.
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            return self._open_v1(raw, passphrase)
        data_key = _unwrap_passphrase(raw, passphrase)
        return self._decrypt_payload(raw, data_key)

    def _open_v1(self, raw: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
        """Formato original: key derivada directamente of the passphrase."""
        salt = bytes.fromhex(raw["salt"])
        nonce = bytes.fromhex(raw["nonce"])
        ct = bytes.fromhex(raw["ciphertext"])
        tag = bytes.fromhex(raw["tag"])
        key = _derive_key(passphrase, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ct + tag, None)
        except Exception:
            raise VaultAuthError("Passphrase incorrect o vault damaged.")
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != raw["vault_hash"]:
            raise VaultCorruptError(
                f"vault_hash no coincide: esperado {raw['vault_hash'][:16]}…, "
                f"obtenido {actual_hash[:16]}…"
            )
        return json.loads(plaintext.decode("utf-8"))

    def open_with_recovery(self, recovery_key: bytes) -> Dict[str, Any]:
        """
        decrypts the vault with the key of recovery (reconstruida by
        the custodios via Shamir). only disponible in vaults v2 with slot
        of recovery configurado.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError(
                "the vault is v1  does not have keyslots of recovery. "
                "Abrilo with the passphrase for migrarlo."
            )
        data_key = _unwrap_recovery(raw, recovery_key)
        return self._decrypt_payload(raw, data_key)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def add_recovery_slot(self, passphrase: str, recovery_key: bytes) -> None:
        """
        adds (o replaces) the slot of recovery. replace invalida
        any reparto of shares previous  the custodios old remain
        revocados of facto.
        a vault v1 is migra a v2 in the proceso.
        """
        raw = self._load_raw()
        if raw.get("version") == "1":
            data = self._open_v1(raw, passphrase)
            self.seal(data, passphrase)          # migra a v2
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
        adds (o replaces) the slot time-lock: the data key remains ademas
        recuperable resolviendo a puzzle of `squarings` cuadraturas
        secuenciales (KL-011, componente offline). Migra v1v2 if does missing.

        NO replaces a the passphrase ni a the custodia  is a camino
        ADICIONAL e independiente. Piso of trabajo, no reloj of pared (ver
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
        decrypts the vault RESOLVIENDO the time-lock puzzle. slow by design
        (T cuadraturas secuenciales). only in vaults v2 with slot time-lock.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("the vault is v1  without slot time-lock.")
        data_key = _unwrap_timelock(raw, progress=progress)
        return self._decrypt_payload(raw, data_key)

    def remove_timelock_slot(self, passphrase: str) -> bool:
        """removes the slot time-lock. returns True if existed."""
        raw = self._load_raw()
        if raw.get("version") != "2":
            return False
        _unwrap_passphrase(raw, passphrase)      # autoriza
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
        Restablece the passphrase resolviendo the time-lock puzzle once 
        the camino of the heirs for tomar posesion without the passphrase ni
        custodios. Resuelve the puzzle (slow) and re-envuelve the slot of
        passphrase with the data key recuperada.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("the vault is v1  without slot time-lock.")
        data_key = _unwrap_timelock(raw, progress=progress)
        slots = [s for s in raw["keyslots"] if s.get("type") != "passphrase"]
        slots.insert(0, _wrap_passphrase_slot(data_key, new_passphrase))
        raw["keyslots"] = slots
        self._write_raw(raw)

    def timelock_info(self) -> Optional[Dict[str, Any]]:
        """parameters of the slot time-lock (squarings, modulus_bits) without resolverlo."""
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
        """removes the slot of recovery. returns True if existed."""
        raw = self._load_raw()
        if raw.get("version") != "2":
            return False
        _unwrap_passphrase(raw, passphrase)      # autoriza the operation
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
        Rota the passphrase re-envolviendo su keyslot  the payload and the
        slot of recovery remain intactos (the custodia sobrevive).
        a vault v1 is migra: is opens with the old and is re-seals v2 with
        the new.
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
        Restablece the passphrase usando the key of recovery  the
        camino for the owner that the olvido o for the heirs
        tras the reconstruccion by custodios.
        """
        raw = self._load_raw()
        if raw.get("version") != "2":
            raise VaultAuthError("the vault is v1  without slot of recovery.")
        data_key = _unwrap_recovery(raw, recovery_key)
        slots = [s for s in raw["keyslots"] if s.get("type") != "passphrase"]
        slots.insert(0, _wrap_passphrase_slot(data_key, new_passphrase))
        raw["keyslots"] = slots
        self._write_raw(raw)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def exists(self) -> bool:
        return self._path.exists()

    def envelope_hash(self) -> Optional[str]:
        """SHA-256 of the plaintext, without descifrarlo (of the field vault_hash)."""
        if not self._path.exists():
            return None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return raw.get("vault_hash")

    def info(self) -> Dict[str, Any]:
        """Metadatos of the envelope without decrypt nada."""
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


# Implementation note.
# Implementation note.
# Implementation note.

def _validate_envelope(raw: Dict[str, Any]) -> None:
    version = raw.get("version")
    if version == "1":
        required = {"version", "salt", "nonce", "ciphertext", "tag", "vault_hash"}
    elif version == "2":
        required = {"version", "nonce", "ciphertext", "tag", "vault_hash", "keyslots"}
    else:
        raise VaultCorruptError(f"Versión de vault no soportada: {version!r}")
    missing = required - set(raw.keys())
    if missing:
        raise VaultCorruptError(f"Envelope inválido — campos faltantes: {missing}")
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
    """Passphrase incorrect o tag of autenticacion invalid."""

class VaultCorruptError(VaultError):
    """the envelope is estructuralmente damaged."""

class VaultNotFoundError(VaultError):
    """does not exist the file of vault."""
