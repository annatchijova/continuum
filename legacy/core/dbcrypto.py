"""
legacy/core/dbcrypto.py
========================
encrypted of field (application-level) for columns SQLite  closes the
parte of recall of KL-001.

the problema: `memory.db` is SQLite WAL with lecturas/escrituras frecuentes.
encrypt the file entero requires SQLCipher (comercial) o break the
garantias of atomicidad of WAL. the alternativa correcta and of dependencia
cero is encrypt the VALORES sensibles before of escribirlos: the database sigue
siendo SQLite normal (guarda text opaco), WAL intacto, and the content in
rest deja of estar in plaintext.

Primitiva: AES-256-GCM with nonce aleatorio by valor. the key (db key of
32 bytes) vive dentro of the vault encrypted, igual that the store key  same
frontera of confianza: quien opens the vault can decrypt the database.

Formato of the token (str, apto for columns TEXT):

    gcmf1:<base64url(nonce(12) || ciphertext || tag(16))>

AAD (associated data): each valor is liga a su CONTEXTO  tipicamente
`"<row_id>:<column>"`. Asi a attacker with acceso of escritura a the DB no
can mover a valor encrypted of a row/column a another (ni of a registro
a another) without invalidar the tag. the AAD NO is encrypts; is responsabilidad of the
caller pasar a contexto estable and unico.

Coexistencia plaintext / ciphertext (migracion transparente):
  - `is_encrypted(v)` distingue a token of a valor in plaintext by the prefijo.
  - `decrypt_field` returns the valores in plaintext tal cual (a database
    pre-encrypted sigue siendo legible mientras is migra).
  - `maybe_decrypt` is the helper of lectura: decrypts if does missing, if no
    returns the valor as is.

module puro salvo `secrets` for the nonces.
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
    """decrypted fallido: key incorrect, AAD equivocado o dato tampered."""


def is_encrypted(value: Optional[str]) -> bool:
    """True if `value` is a token encrypted by este module."""
    return isinstance(value, str) and value.startswith(FIELD_PREFIX)


# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.

def escape_plaintext(value: str) -> str:
    """Forma of storage of a valor in plaintext (no ambigua with ciphertext)."""
    if value.startswith(FIELD_PREFIX) or value.startswith(PLAIN_ESCAPE):
        return PLAIN_ESCAPE + value
    return value


def unescape_plaintext(stored: str) -> str:
    """Inversa of escape_plaintext: recupera the valor logico in plaintext."""
    if stored.startswith(PLAIN_ESCAPE):
        return stored[len(PLAIN_ESCAPE):]
    return stored


class FieldCipher:
    """
    encrypts/decrypts valores of column with a db key of 32 bytes.

    key : 32 bytes. is keeps only in memory mientras the vault is
          abierto; nunca is persiste fuera of the vault encrypted.
    """

    def __init__(self, key: bytes) -> None:
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "the paquete 'cryptography' is required for the encrypted of field."
            )
        if len(key) != _KEY_LEN:
            raise ValueError(f"La db key debe tener {_KEY_LEN} bytes, tiene {len(key)}.")
        self._aes = AESGCM(key)

    # Implementation note.

    def encrypt_field(self, plaintext: str, aad: str) -> str:
        """
        encrypts `plaintext` ligandolo a `aad` (contexto row:column).

        SIEMPRE encrypts su entry as text in plaintext  NO intenta detect
        if `plaintext` "already parece encrypted" (FIX R5-001): esa heuristica
        misfirea over content in plaintext that starts with the prefijo of
        ciphertext and it dejaba without encrypt. the idempotencia in migraciones is
        responsabilidad of the caller, that skips the columns already encrypted with
        is_encrypted() over the forma ALMACENADA (no over the valor logico).
        """
        nonce = secrets.token_bytes(_NONCE_LEN)
        ct = self._aes.encrypt(
            nonce, plaintext.encode("utf-8"), aad.encode("utf-8")
        )
        return FIELD_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt_field(self, token: str, aad: str) -> str:
        """
        decrypts a token. if `token` is in plaintext (without prefijo) it
        returns tal cual  allows leer a database a medio migrar.
        Lanza FieldCryptoError if the token is of the prefijo pero no decrypts.
        """
        if not is_encrypted(token):
            return token
        try:
            blob = base64.urlsafe_b64decode(token[len(FIELD_PREFIX):])
            nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            if len(nonce) != _NONCE_LEN or len(ct) < _TAG_LEN:
                raise ValueError("token truncado")
            return self._aes.decrypt(nonce, ct, aad.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            raise FieldCryptoError(
                f"No se pudo descifrar el campo (clave/AAD incorrecto o dato "
                f"manipulado): {exc}"
            ) from exc

    def maybe_decrypt(self, value: Optional[str], aad: str) -> Optional[str]:
        """decrypts if is a token; if no, returns the valor without tocar. NoneNone."""
        if value is None:
            return None
        return self.decrypt_field(value, aad)
