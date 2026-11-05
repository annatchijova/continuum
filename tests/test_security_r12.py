"""
tests/test_security_r12.py
===========================
Red-team round R12. One finding, reproduced and fixed:

R12-001 (Medium, hardening) - `ArtifactStore._path_for` built the on-disk
path for an artifact as `store_dir / artifact_hash[:2] / f"{artifact_hash}.enc"`
with no validation that `artifact_hash` was the SHA-256 hex digest it is
supposed to be. An id containing path separators (for example
`"..s/../outside_target"`) resolved outside `store_dir`, and every method
built on `_path_for` - `get`, `restore`, `exists`, `envelope_version`,
`verify` - followed it there. Confirmed by induction: a crafted id made
`_write_envelope` write a file next to, not inside, the store directory.

Under the current call graph this is not reachable by an external attacker:
every caller (`cmd_restore` in the CLI, `rekey`, `convert_to_key`,
`export_bundle`) passes an id that already came from `list_hashes()` (a
disk enumeration) or from `hashlib.sha256(...).hexdigest()` computed
in-process, never raw external input. There is no Studio API route that
reaches `ArtifactStore` with a caller-supplied id. So this is hardening
against a latent primitive - closing it before any future caller (a new
API route, a heir-facing restore feature) turns it into a real traversal -
not a fix for an exploit reachable today.

Fix: `_path_for` rejects any `artifact_hash` that is not exactly 64
lowercase hex characters before building a path from it, so the one
choke point used by every read and write method is closed.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from legacy.vault.artifact_store import ArtifactStore
from legacy.vault.locker import VaultNotFoundError

_SECRET = b"\x01" * 32  # v2 store key


@pytest.fixture
def store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "store")


@pytest.mark.parametrize(
    "evil_id",
    [
        "..s/../outside_target",
        "../../../../etc/passwd",
        "ab/../../../outside",
        "../" * 20 + "x",
    ],
)
def test_r12_001_traversal_id_rejected(store: ArtifactStore, evil_id: str) -> None:
    """A crafted id must never resolve a path outside the store directory."""
    with pytest.raises(VaultNotFoundError):
        store._write_envelope(evil_id, b"payload", _SECRET)
    with pytest.raises(VaultNotFoundError):
        store.get(evil_id, _SECRET)
    with pytest.raises(VaultNotFoundError):
        store.restore(evil_id, Path(tempfile.mkdtemp()) / "out.bin", _SECRET)
    with pytest.raises(VaultNotFoundError):
        store.exists(evil_id)
    with pytest.raises(VaultNotFoundError):
        store.envelope_version(evil_id)
    assert store.verify(evil_id, _SECRET) is False


def test_r12_001_traversal_id_cannot_escape_store_dir(
    store: ArtifactStore, tmp_path: Path
) -> None:
    """
    Negative control proving the primitive is real before the fix is
    exercised through the public API: rejecting the crafted id must mean
    no file is ever created outside the store directory.
    """
    outside = tmp_path / "outside_target.enc"
    evil_id = "..s/../outside_target"

    with pytest.raises(VaultNotFoundError):
        store._write_envelope(evil_id, b"ESCAPED WRITE", _SECRET)

    assert not outside.exists()


def test_r12_001_legitimate_ids_unaffected(store: ArtifactStore) -> None:
    """Positive control: real content-addressed ids still round-trip."""
    data = b"a legitimate archived artifact"
    artifact_hash = store.put_bytes(data, _SECRET)

    assert store.exists(artifact_hash) is True
    assert store.get(artifact_hash, _SECRET) == data
    assert store.verify(artifact_hash, _SECRET) is True
    assert store.envelope_version(artifact_hash) == "2"


def test_r12_001_uppercase_or_wrong_length_rejected(store: ArtifactStore) -> None:
    """The id must be exactly 64 lowercase hex characters, not just hex-ish."""
    data = b"x"
    artifact_hash = store.put_bytes(data, _SECRET)

    with pytest.raises(VaultNotFoundError):
        store.get(artifact_hash.upper(), _SECRET)
    with pytest.raises(VaultNotFoundError):
        store.get(artifact_hash[:-1], _SECRET)
    with pytest.raises(VaultNotFoundError):
        store.get(artifact_hash + "0", _SECRET)
