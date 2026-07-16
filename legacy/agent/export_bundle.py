"""
legacy/agent/export_bundle.py
==============================
Paquete of exportacion portable for heirs.

the heir no should tener that navegar the data_dir of the owner:
recibe a directory autocontenido (for a USB, a backup notarial)
with todo it required for entender and verificar the legado:

  bundle/
   GUIA_DEL_HEREDERO.md   guia priorizada (heir_guide)
   LEEME.txt              what is esto and como usarlo
   audit.db               copy of the audit trail (backup WAL-safe)
   verify_legacy.py       verificador stdlib-only (if is disponible)
   artifacts/             artifacts encrypted (AES-256-GCM, tal cual)
   MANIFEST.json          SHA-256 of each file of the bundle

Decisiones:
  - audit.db is copy with the API of backup of SQLite, no with a copy
    of file: in modo WAL, copiar the file can perder the ultimas
    transacciones that still viven in the -wal.
  - the evento BUNDLE_EXPORTED is seals before of the backup, asi the propio
    bundle registra su exportacion in the chain that transporta.
  - the artifacts viajan encrypted: the bundle can perderse without exponer
    content. Recuperarlos requires the passphrase (ver LEEME).
  - if is provee the passphrase, each artifact is verifica before of
    exportar  a bundle corrupto no is entrega (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BUNDLE_VERSION = "1"

_LEEME = """\
LEGADO DIGITAL  PAQUETE for heirs
========================================

Este directory fue generado by Digital Legacy the {ts}
for the legado of: {owner}

content:
  GUIA_DEL_HEREDERO.md   lee esto first: what hay and by where empezar.
  audit.db               registro sellado of each operation over the legado.
  verify_legacy.py       verificador independiente (only requires Python 3).
  artifacts/             copies encrypted of the documents archivados.
  MANIFEST.json          huella SHA-256 of each file of este paquete.

Verificar that the registro no fue tampered:

    python3 verify_legacy.py audit.db

recover a document encrypted (requires the software Digital Legacy and the
passphrase of the vault, entregada by the canal that definio the owner):

    legacy restore <hash> --output <destination>

if a hash of the MANIFEST no matches with the file, the paquete fue
altered after of su creation: no trust in el and request a copy new.
"""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def export_bundle(
    agent,
    dest: Path,
    *,
    actor: str,
    passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Exporta the bundle a `dest` (directory new o empty).

    agent      : LegacyAgent with the vault ABIERTO.
    actor      : who exporta (remains in the audit trail).
    passphrase : if is provee, each artifact archivado is verifica before
                 of incluirlo; a artifact corrupto aborta the exportacion.

    returns the manifest (also escrito as MANIFEST.json).
    """
    if not agent._unlocked or agent._index is None:
        raise RuntimeError("Vault cerrado. Abri the vault before of exportar.")

    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"Destination {dest} exists and is not empty.")
    dest.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).isoformat()

    # Implementation note.
    guide = agent.heir_guide(actor=actor)
    (dest / "GUIA_DEL_HEREDERO.md").write_text(guide, encoding="utf-8")

    # Implementation note.
    (dest / "LEEME.txt").write_text(
        _LEEME.format(ts=ts, owner=agent._index.owner_id), encoding="utf-8"
    )

    # Implementation note.
    # Implementation note.
    hashes: List[str] = agent._store.list_hashes()
    if passphrase is not None or agent._index.store_key_hex:
        bad = [h for h in hashes if not agent.verify_artifact(h, passphrase)]
        if bad:
            raise ValueError(
                "Exportacion abortada  artifacts corruptos o tampered: "
                + ", ".join(h[:16] + "..." for h in bad)
            )
    for h in hashes:
        src = agent._store._path_for(h)
        out = dest / "artifacts" / h[:2] / f"{h}.enc"
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, out)

    # Implementation note.
    verify_src = Path(__file__).resolve().parents[2] / "verify_legacy.py"
    verify_included = verify_src.is_file()
    if verify_included:
        shutil.copyfile(verify_src, dest / "verify_legacy.py")

    # Implementation note.
    # Implementation note.
    # Implementation note.
    agent._audit.append(
        "BUNDLE_EXPORTED",
        actor=actor,
        detail=f"dest={dest.name} artifacts={len(hashes)} "
               f"verified={passphrase is not None}",
    )
    src_conn = sqlite3.connect(agent._data_dir / "audit.db")
    dst_conn = sqlite3.connect(dest / "audit.db")
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    # Implementation note.
    files = {
        str(p.relative_to(dest)): _sha256_file(p)
        for p in sorted(dest.rglob("*"))
        if p.is_file() and p.name != "MANIFEST.json"
    }
    manifest: Dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": ts,
        "owner_id": agent._index.owner_id,
        "actor": actor,
        "audit": {
            "length": agent._audit.length,
            "tip_hash": agent._audit.tip_hash,
        },
        "artifacts_included": len(hashes),
        "artifacts_verified": passphrase is not None or bool(agent._index.store_key_hex),
        "verify_script_included": verify_included,
        "files": files,
    }
    (dest / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return manifest


def check_manifest(bundle_dir: Path) -> List[str]:
    """
    Reverifica the hashes of the MANIFEST.json of a bundle existente.
    returns the lista of problemas (empty = integro).
    """
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        return ["MANIFEST.json ausente"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"MANIFEST.json ilegible: {exc}"]

    problems: List[str] = []
    for rel, expected in manifest.get("files", {}).items():
        p = bundle_dir / rel
        if not p.is_file():
            problems.append(f"falta {rel}")
        elif _sha256_file(p) != expected:
            problems.append(f"hash no coincide: {rel}")
    return problems
