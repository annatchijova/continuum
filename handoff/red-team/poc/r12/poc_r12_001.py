"""
R12-001 PoC: ArtifactStore._path_for traversal via a crafted artifact id.

Run against the VULNERABLE state (before the fix in artifact_store.py) to
reproduce; run as-is against the current tree to confirm it is fixed (it
will print "FIXED: ...").

    python3 -I handoff/red-team/poc/r12/poc_r12_001.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from legacy.vault.artifact_store import ArtifactStore  # noqa: E402
from legacy.vault.locker import VaultNotFoundError  # noqa: E402

SECRET = b"\x11" * 32

tmp = Path(tempfile.mkdtemp())
store_dir = tmp / "store"
outside = tmp / "outside_target.enc"

store = ArtifactStore(store_dir)
evil_id = "..s/../outside_target"

print(f"store_dir = {store_dir}")
print(f"evil id   = {evil_id!r}")

try:
    store._write_envelope(evil_id, b"ESCAPED WRITE", SECRET)
except VaultNotFoundError as exc:
    print(f"FIXED: _write_envelope rejected the id before touching the filesystem ({exc})")
    assert not outside.exists()
else:
    print(f"VULNERABLE: wrote outside the store directory -> {outside}")
    print(f"outside.exists() = {outside.exists()}")
    assert outside.exists()
