"""
tests/test_artifact_store.py
=============================
ArtifactStore: encrypted content-addressed storage for raw artifacts (KL-002).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from legacy.vault.artifact_store import ArtifactStore, STORE_MAGIC
from legacy.vault.locker import (
    VaultAuthError,
    VaultCorruptError,
    VaultNotFoundError,
)
from legacy.agent.memory_agent import LegacyAgent

PASS = "correcthorsebatterystaple"


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "artifacts")


# Basic storage behavior.

def test_roundtrip_bytes(store):
    data = b"content of the will \x00\xff including binary bytes"
    h = store.put_bytes(data, PASS)
    assert h == hashlib.sha256(data).hexdigest()
    assert store.get(h, PASS) == data


def test_roundtrip_file(store, tmp_path):
    src = tmp_path / "will.pdf"
    src.write_bytes(b"%PDF-1.4 test content" * 100)
    h = store.put(src, PASS)
    dest = tmp_path / "restored.pdf"
    store.restore(h, dest, PASS)
    assert dest.read_bytes() == src.read_bytes()


def test_put_is_idempotent(store):
    data = b"same content"
    h1 = store.put_bytes(data, PASS)
    h2 = store.put_bytes(data, PASS)
    assert h1 == h2
    assert store.list_hashes() == [h1]


def test_ciphertext_does_not_contain_plaintext(store):
    data = b"SECRETO-in-CLARO-NO-must-APARECER"
    h = store.put_bytes(data, PASS)
    raw = store._path_for(h).read_bytes()
    assert raw.startswith(STORE_MAGIC)
    assert data not in raw


# Error handling and tamper detection.

def test_wrong_passphrase_raises(store):
    h = store.put_bytes(b"data", PASS)
    with pytest.raises(VaultAuthError):
        store.get(h, "passphrase-incorrect")


def test_missing_artifact_raises(store):
    with pytest.raises(VaultNotFoundError):
        store.get("0" * 64, PASS)


def test_tampered_ciphertext_raises(store):
    h = store.put_bytes(b"content original", PASS)
    p = store._path_for(h)
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 0xFF                       # flip a bit in the GCM tag
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultAuthError):
        store.get(h, PASS)


def test_truncated_envelope_raises(store):
    h = store.put_bytes(b"content", PASS)
    p = store._path_for(h)
    p.write_bytes(p.read_bytes()[:20])    # shorter than the header
    with pytest.raises(VaultCorruptError):
        store.get(h, PASS)


def test_envelope_cannot_be_renamed_to_other_id(store):
    """The ID is AAD: moving the envelope to another ID invalidates the tag."""
    data_a = b"artifact A"
    data_b = b"artifact B"
    ha = store.put_bytes(data_a, PASS)
    hb = hashlib.sha256(data_b).hexdigest()
    # Copy the envelope under a different content ID.
    pb = store._path_for(hb)
    pb.parent.mkdir(parents=True, exist_ok=True)
    pb.write_bytes(store._path_for(ha).read_bytes())
    with pytest.raises(VaultAuthError):
        store.get(hb, PASS)


def test_verify(store):
    h = store.put_bytes(b"intact", PASS)
    assert store.verify(h, PASS) is True
    assert store.verify(h, "another") is False
    assert store.verify("f" * 64, PASS) is False


# Agent archive and restore behavior.

def test_agent_archive_and_restore_with_audit(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)

    src = tmp_path / "contract.txt"
    src.write_text("sales contract for the house", encoding="utf-8")
    h = agent.archive_artifact(src, PASS)

    src.unlink()                          # the original is removed
    dest = tmp_path / "restored.txt"
    agent.restore_artifact(h, dest, PASS, actor="heir_1")
    assert dest.read_text(encoding="utf-8") == "sales contract for the house"

    events = [e["event_type"] for e in agent._audit.events()]
    assert "ARTIFACT_ARCHIVED" in events
    assert "ARTIFACT_RESTORED" in events


def test_agent_archive_requires_unlocked(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        agent.archive_artifact(Path("/tmp/x"), PASS)
