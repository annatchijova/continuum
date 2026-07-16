"""
verify_legacy.py
=================
Standalone verifier for the digital legacy audit trail.

Standard-library only; it does not require installing the package or its
dependencies. It can be provided to heirs or auditors to verify that the
audit trail has not been tampered with.

Usage:
    python3 verify_legacy.py /path/to/audit.db
    python3 verify_legacy.py /path/to/audit.db --hmac-key-hex <hex>
    python3 verify_legacy.py /path/to/audit.db --hmac-key-file /path/to/key

Exit status:
    0  chain valid.
    1  chain invalid or error.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import os
import sqlite3
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        # Normalize text exactly as the audit trail implementation does.
        return unicodedata.normalize("NFC", obj)
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    return str(obj)


def _canonical_hash(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(
        _canonicalize(payload), sort_keys=True, ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_entry_hash(seq: int, prev_hash: str, payload: Dict[str, Any]) -> str:
    return _canonical_hash({**payload, "seq": seq, "prev_hash": prev_hash})


def _compute_hmac(key: bytes, entry_hash: str) -> str:
    return _hmac.new(key, entry_hash.encode("utf-8"), "sha256").hexdigest()


GENESIS_HASH = "0" * 64
_STRUCTURAL_FIELDS = frozenset({
    "seq", "prev_hash", "entry_hash", "entry_hmac", "chain_ver",
})


@dataclass
class VerifyError:
    seq: int
    kind: str
    detail: str


@dataclass
class VerifyResult:
    valid: bool
    length: int
    errors: List[VerifyError] = field(default_factory=list)
    hmac_checked: bool = False
    first_invalid_seq: Optional[int] = None


def _load_events(db_path: Path) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY seq ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def verify(
    events: List[Dict[str, Any]],
    *,
    hmac_key: Optional[bytes] = None,
) -> VerifyResult:
    result = VerifyResult(
        valid=True, length=len(events), hmac_checked=hmac_key is not None,
    )
    expected_prev = GENESIS_HASH
    expected_seq = 1

    def _flag(seq: int, kind: str, detail: str) -> None:
        result.valid = False
        result.errors.append(VerifyError(seq=seq, kind=kind, detail=detail))
        if result.first_invalid_seq is None or seq < result.first_invalid_seq:
            result.first_invalid_seq = seq

    for ev in events:
        seq = ev["seq"]
        prev_hash = ev["prev_hash"]
        entry_hash = ev["entry_hash"]
        entry_hmac = ev.get("entry_hmac") or None

        if seq != expected_seq:
            _flag(seq, "seq_discontinuity",
                  f"expected seq={expected_seq}, found seq={seq}")
            expected_seq = seq

        if prev_hash != expected_prev:
            _flag(seq, "broken_linkage",
                  f"prev_hash mismatch: stored={prev_hash[:16]}… "
                  f"expected={expected_prev[:16]}…")

        payload = {k: v for k, v in ev.items() if k not in _STRUCTURAL_FIELDS}
        recomputed = _compute_entry_hash(seq, prev_hash, payload)
        if recomputed != entry_hash:
            _flag(seq, "tampered_content",
                  f"entry_hash mismatch: "
                  f"stored={entry_hash[:16]}… recomputed={recomputed[:16]}…")

        if hmac_key is not None:
            if not entry_hmac:
                _flag(seq, "hmac_absent",
                      "entry_hmac missing: entry written without an HMAC key")
            elif not _hmac.compare_digest(
                entry_hmac, _compute_hmac(hmac_key, entry_hash)
            ):
                _flag(seq, "hmac_invalid",
                      "entry_hmac mismatch: possible manipulation with chain recomputation")

        expected_prev = entry_hash
        expected_seq = seq + 1

    return result


def resolve_key(
    hex_str: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Optional[bytes]:
    if hex_str:
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            print("ERROR: --hmac-key-hex is not valid hexadecimal.", file=sys.stderr)
            sys.exit(1)
    if key_file:
        p = Path(key_file)
        if not p.is_file():
            print(f"ERROR: {key_file} does not exist.", file=sys.stderr)
            sys.exit(1)
        return p.read_bytes().strip()
    env_hex = os.getenv("LEGACY_HMAC_KEY", "").strip()
    if env_hex:
        try:
            return bytes.fromhex(env_hex)
        except ValueError:
            pass
    env_file = os.getenv("LEGACY_HMAC_KEY_FILE", "").strip()
    if env_file:
        p = Path(env_file)
        if p.is_file():
            return p.read_bytes().strip()
    return None


def _print_result(result: VerifyResult, db_path: Path) -> None:
    print(f"\nLEGACY AUDIT TRAIL VERIFICATION")
    print(f"{'=' * 50}")
    print(f"Database      : {db_path}")
    print(f"Events        : {result.length}")
    print(f"HMAC checked  : {'yes' if result.hmac_checked else 'no (hash-only)'}")
    print()

    if result.valid:
        print(" chain valid  integrity verified")
        if not result.hmac_checked:
            print("  NOTE: hash-only verification. An attacker with write access to")
            print("  the database can recompute the chain without an HMAC key.")
            print("  For complete verification, provide --hmac-key-hex.")
    else:
        print(f"✗ INVALID CHAIN — first affected entry: seq={result.first_invalid_seq}")
        print()
        by_kind: Dict[str, List[VerifyError]] = {}
        for err in result.errors:
            by_kind.setdefault(err.kind, []).append(err)
        for kind, errs in by_kind.items():
            print(f"  [{kind}] — {len(errs)} error(s):")
            for e in errs:
                print(f"    seq={e.seq}: {e.detail}")
        print()
        print("  The audit trail was modified or truncated, or entries were")
        print("  inserted/deleted. The legacy data cannot be trusted.")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Standalone verifier for the Digital Legacy audit trail.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 verify_legacy.py /home/user/.legacy/audit.db
  python3 verify_legacy.py audit.db --hmac-key-hex deadbeef...
  python3 verify_legacy.py audit.db --hmac-key-file /ruta/a/key.bin

Exit status:
  0  chain valid
  1  chain invalid or error
        """,
    )
    parser.add_argument("db_path", help="Path to the audit.db file")
    parser.add_argument("--hmac-key-hex", help="key HMAC as hex string")
    parser.add_argument("--hmac-key-file", help="Path to a file containing the HMAC key")
    parser.add_argument(
        "--json", action="store_true", help="Salida in JSON (for procesamiento)"
    )
    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.is_file():
        print(f"ERROR: {db_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    hmac_key = resolve_key(
        hex_str=args.hmac_key_hex,
        key_file=args.hmac_key_file,
    )

    try:
        events = _load_events(db_path)
    except sqlite3.DatabaseError as exc:
        print(f"ERROR: could not read the database: {exc}", file=sys.stderr)
        sys.exit(1)

    result = verify(events, hmac_key=hmac_key)

    if args.json:
        output = {
            "valid": result.valid,
            "length": result.length,
            "hmac_checked": result.hmac_checked,
            "first_invalid_seq": result.first_invalid_seq,
            "errors": [
                {"seq": e.seq, "kind": e.kind, "detail": e.detail}
                for e in result.errors
            ],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        _print_result(result, db_path)

    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
