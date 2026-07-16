"""
legacy/vault/artifact_store.py
===============================
store encrypted of artifacts crudos  closes the brecha KL-002.

the vault (`locker.py`) protege the index; este module protege the files
in si. each artifact is encrypts with AES-256-GCM and is almacena direccionado
by content: the identificador is the SHA-256 of the plaintext, the same
`content_hash` that the vault index already registra by artifact.

Propiedades:
  - Content-addressed : same content  same id  put() is idempotente.
  - Integridad doble  : the tag GCM autentica the ciphertext; tras decrypt,
                        the SHA-256 of the plaintext must match with the id.
  - AAD               : the id is usa as associated data  a envelope no
                        can be renombrado a another id without invalidar the tag.
  - Escritura atomica : tmp + rename(2), igual that the vault.

Formato binario of the envelope (without JSON  the artifacts can be grandes
and hex duplicaria the size):

  MAGIC(8) | salt(32) | nonce(12) | ciphertext+tag(resto)

Derivacion of key: PBKDF2-SHA256, 260 000 iteraciones (identico to the vault),
with salt aleatorio by file. the passphrase nunca is persiste.

Layout in disco: <store_dir>/<id[:2]>/<id>.enc  dos niveles for no
degradar the filesystem with miles of files in a directory.
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
except ImportError:  # _require_crypto() reporta the error to the usar the store
    AESGCM = None  # type: ignore[assignment]

STORE_MAGIC = b"LGCYART1"       # v1: key derivada of passphrase (PBKDF2)
STORE_MAGIC_V2 = b"LGCYART2"    # v2: store key cruda of 32 bytes (of the vault)
_SALT_LEN = 32
_NONCE_LEN = 12
_HEADER_LEN = len(STORE_MAGIC) + _SALT_LEN + _NONCE_LEN
_HEADER_V2_LEN = len(STORE_MAGIC_V2) + _NONCE_LEN
_GCM_TAG_LEN = 16
_KEY_LEN = 32

# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
Secret = "str | bytes"


def _require_str(secret, artifact_hash: str) -> str:
    if not isinstance(secret, str):
        raise VaultAuthError(
            f"El artifact {artifact_hash[:16]}… es v1 — requiere la "
            f"passphrase (str), no una clave cruda."
        )
    return secret


def _require_key(secret, artifact_hash: str) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != _KEY_LEN:
        raise VaultAuthError(
            f"El artifact {artifact_hash[:16]}… es v2 — requiere la store "
            f"key de {_KEY_LEN} bytes (guardada en el vault), no una passphrase."
        )
    return bytes(secret)


class ArtifactStore:
    """
    store encrypted content-addressed.

    store_dir : directory raiz of the store (is crea if does not exist).
    """

    def __init__(self, store_dir: Path) -> None:
        _require_crypto()
        self._dir = store_dir

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _path_for(self, artifact_hash: str) -> Path:
        return self._dir / artifact_hash[:2] / f"{artifact_hash}.enc"

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _write_envelope(self, artifact_hash: str, data: bytes, secret) -> None:
        """
        encrypts `data` and writes the envelope (atomico, sobreescribe).
        secret str  envelope v1 (PBKDF2); bytes(32)  envelope v2 (key cruda).
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
        encrypts and almacena `data`. returns the id (SHA-256 hex of the plaintext).
        Idempotente: if the id already exists in the store, no re-writes.
        secret: passphrase (str, envelope v1) o store key (bytes, envelope v2).
        """
        artifact_hash = hashlib.sha256(data).hexdigest()
        if self._path_for(artifact_hash).exists():
            return artifact_hash
        self._write_envelope(artifact_hash, data, secret)
        return artifact_hash

    def put(self, path: Path, secret) -> str:
        """encrypts and almacena the file complete in `path`."""
        return self.put_bytes(path.read_bytes(), secret)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def envelope_version(self, artifact_hash: str) -> str:
        """'1' (passphrase) o '2' (store key). VaultNotFoundError if does not exist."""
        src = self._path_for(artifact_hash)
        if not src.exists():
            raise VaultNotFoundError(
                f"Artifact {artifact_hash[:16]}… no está en el store."
            )
        with src.open("rb") as f:
            magic = f.read(8)
        if magic == STORE_MAGIC:
            return "1"
        if magic == STORE_MAGIC_V2:
            return "2"
        raise VaultCorruptError(
            f"Envelope dañado o formato desconocido: {src.name}"
        )

    def get(self, artifact_hash: str, secret) -> bytes:
        """
        decrypts and returns the plaintext of the artifact. the tipo of secreto
        must corresponder to the envelope: passphrase (str) for v1, store key
        (bytes) for v2.
        Lanza VaultNotFoundError / VaultCorruptError / VaultAuthError.
        """
        src = self._path_for(artifact_hash)
        if not src.exists():
            raise VaultNotFoundError(
                f"Artifact {artifact_hash[:16]}… no está en el store."
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
                f"Envelope dañado o formato desconocido: {src.name}"
            )

        try:
            plaintext = AESGCM(key).decrypt(
                nonce, ct_and_tag, artifact_hash.encode("ascii")
            )
        except Exception:
            raise VaultAuthError(
                "Secreto incorrect o envelope tampered "
                f"(artifact {artifact_hash[:16]}…)."
            )

        actual = hashlib.sha256(plaintext).hexdigest()
        if actual != artifact_hash:
            # Implementation note.
            # Implementation note.
            # Implementation note.
            raise VaultCorruptError(
                f"Hash del plaintext no coincide con el id: "
                f"esperado {artifact_hash[:16]}…, obtenido {actual[:16]}…"
            )
        return plaintext

    def restore(self, artifact_hash: str, dest: Path, secret) -> Path:
        """decrypts the artifact and it writes in `dest` (atomico)."""
        data = self.get(artifact_hash, secret)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        return dest

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def exists(self, artifact_hash: str) -> bool:
        return self._path_for(artifact_hash).exists()

    def list_hashes(self) -> List[str]:
        """Ids almacenados, ordenados (determinista)."""
        if not self._dir.exists():
            return []
        return sorted(p.stem for p in self._dir.glob("*/*.enc"))

    def verify(self, artifact_hash: str, secret) -> bool:
        """True if the artifact decrypts and su hash matches with the id."""
        try:
            self.get(artifact_hash, secret)
            return True
        except (VaultAuthError, VaultCorruptError, VaultNotFoundError):
            return False

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def rekey(self, old_passphrase: str, new_passphrase: str) -> Dict[str, int]:
        """
        Re-encripta the artifacts v1 with the passphrase new. the v2 no
        dependen of the passphrase and no is tocan (cuentan as skipped).
        each envelope is reescribe atomicamente; the id no cambia.

        RE-EJECUTABLE tras a crash a mitad of rotation: a artifact v1
        that already no decrypts with the old is prueba with the new  if
        decrypts, already fue rotado and is skips. if no decrypts with no,
        is aborta (passphrase incorrect o envelope corrupto).
        """
        rotated = 0
        skipped = 0
        for h in self.list_hashes():
            if self.envelope_version(h) == "2":
                skipped += 1            # v2: independiente of the passphrase
                continue
            try:
                data = self.get(h, old_passphrase)
            except VaultAuthError:
                if self.verify(h, new_passphrase):
                    skipped += 1        # already rotado in a corrida previous
                    continue
                raise VaultAuthError(
                    f"Artifact {h[:16]}… no descifra con ninguna de las dos "
                    f"passphrases — corrupto o passphrase incorrecta. "
                    f"Rotación abortada."
                )
            self._write_envelope(h, data, new_passphrase)
            rotated += 1
        return {"rotated": rotated, "skipped": skipped}

    def convert_to_key(self, passphrase: str, store_key: bytes) -> Dict[str, int]:
        """
        Migra all the envelopes v1 (passphrase) a v2 (store key).
        Tras the conversion, the artifacts dejan of depender of the
        passphrase: the rotation of passphrase already no the toca and the
        recovery by custodios can descifrarlos (the store key
        viaja dentro of the vault).

        RE-EJECUTABLE: the v2 existentes is are skipped. a v1 that no decrypts
        with the passphrase aborta the conversion (fail closed).
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
