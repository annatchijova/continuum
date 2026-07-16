"""
legacy/core/hash_chain.py
==========================
Hash chain tamper-evident for Digital Legacy.

design dual hash/HMAC (identico a vigia-repo v2 + janus):
  entry_hash = SHA-256( canonical( payload  {seq, prev_hash} ) )
  entry_hmac = HMAC-SHA256( key, entry_hash )   [opcional]

  - entry_hash without a key: verificacion independiente by heirs
    without acceso a the key  cumple the requisito of terceros.
  - entry_hmac with key: detects to the attacker interno that recomputa
    toda the chain (SHA-256 puro is recomputable, HMAC no).

verify_chain acumula all the errores  the auditor ve the mapa
complete of the dano, no only the primer link invalid.

module puro: without I/O, without DB, without state.
Variables of entorno:
  LEGACY_HMAC_KEY       hex string ( 32 bytes recomendado)
  LEGACY_HMAC_KEY_FILE  ruta a bytes crudos
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from legacy.core.canonicalize import _canonicalize

CHAIN_SCHEMA_VERSION: str = "2"
GENESIS_HASH: str = "0" * 64

_HMAC_KEY_ENV = "LEGACY_HMAC_KEY"
_HMAC_KEY_FILE_ENV = "LEGACY_HMAC_KEY_FILE"


# Implementation note.
# Implementation note.
# Implementation note.

def canonical_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 of the payload in forma canonica v1."""
    canonical = json.dumps(
        _canonicalize(payload), sort_keys=True, ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_entry_hash(seq: int, prev_hash: str, payload: Dict[str, Any]) -> str:
    """Hash of a link: payload complete + seq + prev_hash."""
    return canonical_hash({**payload, "seq": seq, "prev_hash": prev_hash})


def compute_entry_hmac(key: bytes, entry_hash: str) -> str:
    """HMAC-SHA256 of the entry_hash."""
    return _hmac.new(key, entry_hash.encode("utf-8"), "sha256").hexdigest()


def resolve_hmac_key() -> Optional[bytes]:
    """
    Resuelve the key HMAC of the entorno.
    returns None if no hay key  modo hash-only, documentado, no error.
    NO generates key efimera: chain firmada with key irrecuperable is
    indistinguible of a manipulada.
    """
    key_hex = os.getenv(_HMAC_KEY_ENV, "").strip()
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) < 32:
                print(
                    f"[LEGACY][hash_chain] WARNING: {_HMAC_KEY_ENV} tiene "
                    f"{len(key)} bytes — mínimo recomendado 32.",
                    file=sys.stderr, flush=True,
                )
            return key
        except ValueError:
            print(
                f"[LEGACY][hash_chain] WARNING: {_HMAC_KEY_ENV} no es hex válido.",
                file=sys.stderr, flush=True,
            )

    key_file = os.getenv(_HMAC_KEY_FILE_ENV, "").strip()
    if key_file:
        try:
            p = Path(key_file)
            if p.is_file():
                key = p.read_bytes().strip()
                if len(key) >= 32:
                    return key
                print(
                    f"[LEGACY][hash_chain] WARNING: {key_file} solo tiene "
                    f"{len(key)} bytes — mínimo 32. Ignorada.",
                    file=sys.stderr, flush=True,
                )
        except OSError as exc:
            print(
                f"[LEGACY][hash_chain] WARNING: no se pudo leer {key_file}: {exc}",
                file=sys.stderr, flush=True,
            )
    return None


# Implementation note.
# Implementation note.
# Implementation note.

@dataclass(frozen=True)
class ChainLink:
    seq: int
    prev_hash: str
    entry_hash: str
    payload: Dict[str, Any]
    entry_hmac: Optional[str] = None


@dataclass
class ChainVerification:
    """
    result of verificacion with acumulacion complete of errores.
    valid=True only if all the categorias are vacias.
    """
    valid: bool
    length: int
    first_invalid_seq: Optional[int] = None
    seq_discontinuities: List[Dict[str, Any]] = field(default_factory=list)
    broken_links: List[Dict[str, Any]] = field(default_factory=list)
    tampered_content: List[Dict[str, Any]] = field(default_factory=list)
    hmac_failures: List[Dict[str, Any]] = field(default_factory=list)
    hmac_checked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "length": self.length,
            "first_invalid_seq": self.first_invalid_seq,
            "seq_discontinuities": self.seq_discontinuities,
            "broken_links": self.broken_links,
            "tampered_content": self.tampered_content,
            "hmac_failures": self.hmac_failures,
            "hmac_checked": self.hmac_checked,
            "summary": {
                "seq_discontinuities": len(self.seq_discontinuities),
                "broken_links": len(self.broken_links),
                "tampered_content": len(self.tampered_content),
                "hmac_failures": len(self.hmac_failures),
            },
        }


# Implementation note.
# Implementation note.
# Implementation note.

def build_link(
    seq: int,
    prev_hash: str,
    payload: Dict[str, Any],
    hmac_key: Optional[bytes] = None,
) -> ChainLink:
    """Construye the link siguiente (puro  the caller persiste)."""
    entry_hash = compute_entry_hash(seq, prev_hash, payload)
    entry_hmac = compute_entry_hmac(hmac_key, entry_hash) if hmac_key else None
    return ChainLink(
        seq=seq, prev_hash=prev_hash, entry_hash=entry_hash,
        payload=payload, entry_hmac=entry_hmac,
    )


# Implementation note.
# Implementation note.
# Implementation note.

def verify_chain(
    links: Sequence[ChainLink],
    *,
    first_seq: int = 1,
    hmac_key: Optional[bytes] = None,
) -> ChainVerification:
    """
    Verifica the chain complete (ordenada by seq ascendente).
    Acumula all the errores  no is detiene in the first.
    """
    result = ChainVerification(
        valid=True, length=len(links), hmac_checked=hmac_key is not None,
    )
    expected_prev = GENESIS_HASH
    expected_seq = first_seq

    def _flag(seq: int) -> None:
        result.valid = False
        if result.first_invalid_seq is None or seq < result.first_invalid_seq:
            result.first_invalid_seq = seq

    for link in links:
        if link.seq != expected_seq:
            result.seq_discontinuities.append({
                "expected_seq": expected_seq,
                "found_seq": link.seq,
                "note": f"eslabón borrado o insertado entre {expected_seq} y {link.seq}",
            })
            _flag(link.seq)
            expected_seq = link.seq

        if link.prev_hash != expected_prev:
            result.broken_links.append({
                "seq": link.seq,
                "stored_prev": link.prev_hash[:16] + "...",
                "expected_prev": expected_prev[:16] + "...",
                "note": "prev_hash no matches with the entry_hash of the link previous",
            })
            _flag(link.seq)

        recomputed = compute_entry_hash(link.seq, link.prev_hash, link.payload)
        if recomputed != link.entry_hash:
            result.tampered_content.append({
                "seq": link.seq,
                "stored": link.entry_hash[:16] + "...",
                "recomputed": recomputed[:16] + "...",
                "note": "content modificado after of the sellado",
            })
            _flag(link.seq)

        if hmac_key is not None:
            if not link.entry_hmac:
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "entry_hmac ausente  link escrito without a key",
                })
                _flag(link.seq)
            elif not _hmac.compare_digest(
                link.entry_hmac,
                compute_entry_hmac(hmac_key, link.entry_hash),
            ):
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "chain recomputada without the key  intento of manipulacion",
                })
                _flag(link.seq)

        expected_prev = link.entry_hash
        expected_seq = link.seq + 1

    return result
