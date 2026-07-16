"""
tests/test_export_bundle.py
============================
Export bundle: portable and verifiable package for heirs.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import verify_legacy as VL
from legacy.agent.export_bundle import check_manifest, export_bundle
from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.artifact_store import ArtifactStore

PASS = "pw"


@pytest.fixture
def agent(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    src = tmp_path / "testamento.txt"
    src.write_text("will and last wishes before the notary", encoding="utf-8")
    a.ingest(src)
    a.archive_artifact(src, PASS)
    a.add_heir("h1", "Olga")
    return a


def test_bundle_structure_and_manifest(agent, tmp_path):
    dest = tmp_path / "bundle"
    manifest = export_bundle(agent, dest, actor="anna", passphrase=PASS)

    assert (dest / "GUIA_DEL_HEREDERO.md").is_file()
    assert (dest / "LEEME.txt").is_file()
    assert (dest / "audit.db").is_file()
    assert (dest / "MANIFEST.json").is_file()
    assert manifest["verify_script_included"] is True
    assert (dest / "verify_legacy.py").is_file()
    assert manifest["artifacts_included"] == 1
    assert manifest["artifacts_verified"] is True

    # The manifest must verify every bundle file.
    assert check_manifest(dest) == []


def test_bundle_audit_is_valid_and_records_export(agent, tmp_path):
    dest = tmp_path / "bundle"
    export_bundle(agent, dest, actor="anna", passphrase=PASS)

    events = VL._load_events(dest / "audit.db")
    result = VL.verify(events, hmac_key=None)
    assert result.valid, [(e.seq, e.kind) for e in result.errors]
    # The copied chain must remain valid.
    assert "BUNDLE_EXPORTED" in [e["event_type"] for e in events]


def test_bundle_artifacts_are_directly_restorable(agent, tmp_path):
    dest = tmp_path / "bundle"
    manifest = export_bundle(agent, dest, actor="anna", passphrase=PASS)

    # The encrypted artifact must remain directly restorable.
    store = ArtifactStore(dest / "artifacts")
    [h] = store.list_hashes()
    store_key = bytes.fromhex(agent._index.store_key_hex)
    assert b"will" in store.get(h, store_key)


def test_manifest_detects_post_export_tampering(agent, tmp_path):
    dest = tmp_path / "bundle"
    export_bundle(agent, dest, actor="anna", passphrase=PASS)
    (dest / "GUIA_DEL_HEREDERO.md").write_text("forged guide", encoding="utf-8")
    problems = check_manifest(dest)
    assert any("GUIA_DEL_HEREDERO.md" in p for p in problems)


def test_export_aborts_on_corrupt_artifact(agent, tmp_path):
    enc = next((agent._data_dir / "artifacts").glob("*/*.enc"))
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0xFF
    enc.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="corrupt"):
        export_bundle(agent, tmp_path / "bundle", actor="anna", passphrase=PASS)


def test_export_refuses_non_empty_dest(agent, tmp_path):
    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "something.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="not empty"):
        export_bundle(agent, dest, actor="anna", passphrase=PASS)


def test_export_requires_unlocked(agent, tmp_path):
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        export_bundle(agent, tmp_path / "bundle", actor="anna")


def test_bundle_audit_copy_is_wal_safe(agent, tmp_path):
    """The backup must include transactions still present in the -wal."""
    dest = tmp_path / "bundle"
    export_bundle(agent, dest, actor="anna", passphrase=PASS)
    # The latest event must be present in the copied database.
    with sqlite3.connect(dest / "audit.db") as conn:
        last = conn.execute(
            "SELECT event_type FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()[0]
    assert last == "BUNDLE_EXPORTED"
