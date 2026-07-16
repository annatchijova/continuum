"""
legacy/core/hash_chain.py
==========================
Tamper-evident hash chain for Digital Legacy.

Dual hash/HMAC design (matching vigia-repo v2 + janus):
  entry_hash = SHA-256(canonical(payload + {seq, prev_hash}))
  entry_hmac = HMAC-SHA256(key, entry_hash)   [optional]

  - entry_hash without a key: independent verification by heirs
    without access to the key, satisfying the third-party requirement.
  - entry_hmac with key: detects an internal attacker who recomputes
    the entire chain (plain SHA-256 can be recomputed; HMAC cannot).

verify_chain accumulates every error so the auditor sees the complete
damage map, not only the first invalid link.

Pure module: no I/O, database, or state.
Environment variables:
  LEGACY_HMAC_KEY       hex string (32 bytes recommended)
  LEGACY_HMAC_KEY_FILE  path to raw key bytes
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


# Canonical hashing primitives.

def canonical_hash(payload: Dict[str, Any]) -> str:
    """Return the SHA-256 hash of the payload in canonical v1 form."""
    canonical = json.dumps(
        _canonicalize(payload), sort_keys=True, ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_entry_hash(seq: int, prev_hash: str, payload: Dict[str, Any]) -> str:
    """Return a link hash over the complete payload, sequence, and predecessor."""
    return canonical_hash({**payload, "seq": seq, "prev_hash": prev_hash})


def compute_entry_hmac(key: bytes, entry_hash: str) -> str:
    """HMAC-SHA256 of the entry_hash."""
    return _hmac.new(key, entry_hash.encode("utf-8"), "sha256").hexdigest()


def resolve_hmac_key() -> Optional[bytes]:
    """
    Resolve the HMAC key from the environment.
    Return None for documented hash-only mode; this is not an error.
    Never generate an ephemeral key: a chain signed with an unrecoverable
    key is indistinguishable from a tampered chain.
    """
    key_hex = os.getenv(_HMAC_KEY_ENV, "").strip()
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) < 32:
                print(
                    f"[LEGACY][hash_chain] WARNING: {_HMAC_KEY_ENV} has "
                    f"{len(key)} bytes — 32 recommended minimum.",
                    file=sys.stderr, flush=True,
                )
            return key
        except ValueError:
            print(
                f"[LEGACY][hash_chain] WARNING: {_HMAC_KEY_ENV} is not valid hex.",
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
                    f"[LEGACY][hash_chain] WARNING: {key_file} has only "
                    f"{len(key)} bytes — 32 minimum. Ignored.",
                    file=sys.stderr, flush=True,
                )
        except OSError as exc:
            print(
                f"[LEGACY][hash_chain] WARNING: could not read {key_file}: {exc}",
                file=sys.stderr, flush=True,
            )
    return None


# Chain data structures.

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
    Verification result with complete error accumulation.
    valid=True only when every error category is empty.
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


# Chain construction.

def build_link(
    seq: int,
    prev_hash: str,
    payload: Dict[str, Any],
    hmac_key: Optional[bytes] = None,
) -> ChainLink:
    """Build the next link; persistence belongs to the caller."""
    entry_hash = compute_entry_hash(seq, prev_hash, payload)
    entry_hmac = compute_entry_hmac(hmac_key, entry_hash) if hmac_key else None
    return ChainLink(
        seq=seq, prev_hash=prev_hash, entry_hash=entry_hash,
        payload=payload, entry_hmac=entry_hmac,
    )


# Chain verification.

def verify_chain(
    links: Sequence[ChainLink],
    *,
    first_seq: int = 1,
    hmac_key: Optional[bytes] = None,
) -> ChainVerification:
    """
    Verify the complete chain (ordered by ascending sequence number).
    Accumulate every error instead of stopping at the first one.
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
                "note": f"link deleted or inserted between {expected_seq} and {link.seq}",
            })
            _flag(link.seq)
            expected_seq = link.seq

        if link.prev_hash != expected_prev:
            result.broken_links.append({
                "seq": link.seq,
                "stored_prev": link.prev_hash[:16] + "...",
                "expected_prev": expected_prev[:16] + "...",
                "note": "prev_hash does not match the previous link's entry_hash",
            })
            _flag(link.seq)

        recomputed = compute_entry_hash(link.seq, link.prev_hash, link.payload)
        if recomputed != link.entry_hash:
            result.tampered_content.append({
                "seq": link.seq,
                "stored": link.entry_hash[:16] + "...",
                "recomputed": recomputed[:16] + "...",
                "note": "content modified after sealing",
            })
            _flag(link.seq)

        if hmac_key is not None:
            if not link.entry_hmac:
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "entry_hmac missing — link was written without a key",
                })
                _flag(link.seq)
            elif not _hmac.compare_digest(
                link.entry_hmac,
                compute_entry_hmac(hmac_key, link.entry_hash),
            ):
                result.hmac_failures.append({
                    "seq": link.seq,
                    "note": "chain recomputed without the key — tampering attempt",
                })
                _flag(link.seq)

        expected_prev = link.entry_hash
        expected_seq = link.seq + 1

    return result
