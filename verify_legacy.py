# Implementation note.
"""
verify_legacy.py
=================
Verificador standalone of the audit trail of the legado digital.

Stdlib-only  no requires instalar the paquete ni no dependencia.
can be entregado a heirs o auditores for verificar that
the audit trail no fue tampered.

Uso:
    python3 verify_legacy.py /ruta/a/audit.db
    python3 verify_legacy.py /ruta/a/audit.db --hmac-key-hex <hex>
    python3 verify_legacy.py /ruta/a/audit.db --hmac-key-file /ruta/a/key

Salida:
    code of salida 0  chain valid.
    code of salida 1  chain invalid o error.
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


# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.

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
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
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


# Implementation note.
# Implementation note.
# Implementation note.

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
                  f"esperado seq={expected_seq}, encontrado seq={seq}")
            expected_seq = seq

        if prev_hash != expected_prev:
            _flag(seq, "broken_linkage",
                  f"prev_hash no coincide: almacenado={prev_hash[:16]}… "
                  f"esperado={expected_prev[:16]}…")

        payload = {k: v for k, v in ev.items() if k not in _STRUCTURAL_FIELDS}
        recomputed = _compute_entry_hash(seq, prev_hash, payload)
        if recomputed != entry_hash:
            _flag(seq, "tampered_content",
                  f"entry_hash no recomputa: "
                  f"almacenado={entry_hash[:16]}… recomputado={recomputed[:16]}…")

        if hmac_key is not None:
            if not entry_hmac:
                _flag(seq, "hmac_absent",
                      "entry_hmac ausente  link escrito without a key HMAC")
            elif not _hmac.compare_digest(
                entry_hmac, _compute_hmac(hmac_key, entry_hash)
            ):
                _flag(seq, "hmac_invalid",
                      "entry_hmac no recomputa  possible manipulacion with recomputo of chain")

        expected_prev = entry_hash
        expected_seq = seq + 1

    return result


# Implementation note.
# Implementation note.
# Implementation note.

def resolve_key(
    hex_str: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Optional[bytes]:
    if hex_str:
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            print("ERROR: --hmac-key-hex no is hex valid.", file=sys.stderr)
            sys.exit(1)
    if key_file:
        p = Path(key_file)
        if not p.is_file():
            print(f"ERROR: {key_file} no existe.", file=sys.stderr)
            sys.exit(1)
        return p.read_bytes().strip()
    # Implementation note.
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


# Implementation note.
# Implementation note.
# Implementation note.

def _print_result(result: VerifyResult, db_path: Path) -> None:
    print(f"\nLEGACY AUDIT TRAIL VERIFICATION")
    print(f"{'=' * 50}")
    print(f"Base de datos : {db_path}")
    print(f"Eventos       : {result.length}")
    print(f"HMAC verificado: {'si' if result.hmac_checked else 'no (hash-only)'}")
    print()

    if result.valid:
        print(" chain valid  integridad verificada")
        if not result.hmac_checked:
            print("  NOTA: verificacion hash-only. a attacker with acceso of")
            print("  escritura a the DB can recomputar the chain without a key HMAC.")
            print("  for verificacion complete, provide the key with --hmac-key-hex.")
    else:
        print(f"✗ CADENA INVÁLIDA — primer eslabón afectado: seq={result.first_invalid_seq}")
        print()
        by_kind: Dict[str, List[VerifyError]] = {}
        for err in result.errors:
            by_kind.setdefault(err.kind, []).append(err)
        for kind, errs in by_kind.items():
            print(f"  [{kind}] — {len(errs)} error(es):")
            for e in errs:
                print(f"    seq={e.seq}: {e.detail}")
        print()
        print("  the audit trail fue modificado, truncado, o eslabones fueron")
        print("  insertados/borrados. the data of the legado no are confiables.")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verificador standalone of the audit trail of Digital Legacy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 verify_legacy.py /home/user/.legacy/audit.db
  python3 verify_legacy.py audit.db --hmac-key-hex deadbeef...
  python3 verify_legacy.py audit.db --hmac-key-file /ruta/a/key.bin

code of salida:
  0  chain valid
  1  chain invalid o error
        """,
    )
    parser.add_argument("db_path", help="Ruta to the file audit.db")
    parser.add_argument("--hmac-key-hex", help="key HMAC as hex string")
    parser.add_argument("--hmac-key-file", help="Ruta a file with key HMAC")
    parser.add_argument(
        "--json", action="store_true", help="Salida in JSON (for procesamiento)"
    )
    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.is_file():
        print(f"ERROR: {db_path} no existe.", file=sys.stderr)
        sys.exit(1)

    hmac_key = resolve_key(
        hex_str=args.hmac_key_hex,
        key_file=args.hmac_key_file,
    )

    try:
        events = _load_events(db_path)
    except sqlite3.DatabaseError as exc:
        print(f"ERROR: no se pudo leer la base de datos: {exc}", file=sys.stderr)
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
