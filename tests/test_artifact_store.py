"""
tests/test_artifact_store.py
=============================
ArtifactStore: encrypted content-addressed of artifacts crudos (KL-002).
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


# Implementation note.
# Implementation note.
# Implementation note.

def test_roundtrip_bytes(store):
    data = b"content of the testamento \x00\xff binario incluido"
    h = store.put_bytes(data, PASS)
    assert h == hashlib.sha256(data).hexdigest()
    assert store.get(h, PASS) == data


def test_roundtrip_file(store, tmp_path):
    src = tmp_path / "testamento.pdf"
    src.write_bytes(b"%PDF-1.4 content of prueba" * 100)
    h = store.put(src, PASS)
    dest = tmp_path / "restaurado.pdf"
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


# Implementation note.
# Implementation note.
# Implementation note.

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
    raw[-1] ^= 0xFF                       # flip in the tag GCM
    p.write_bytes(bytes(raw))
    with pytest.raises(VaultAuthError):
        store.get(h, PASS)


def test_truncated_envelope_raises(store):
    h = store.put_bytes(b"content", PASS)
    p = store._path_for(h)
    p.write_bytes(p.read_bytes()[:20])    # less that the header
    with pytest.raises(VaultCorruptError):
        store.get(h, PASS)


def test_envelope_cannot_be_renamed_to_other_id(store):
    """the id va as AAD: mover the envelope a another id invalida the tag."""
    data_a = b"artifact A"
    data_b = b"artifact B"
    ha = store.put_bytes(data_a, PASS)
    hb = hashlib.sha256(data_b).hexdigest()
    # Implementation note.
    pb = store._path_for(hb)
    pb.parent.mkdir(parents=True, exist_ok=True)
    pb.write_bytes(store._path_for(ha).read_bytes())
    with pytest.raises(VaultAuthError):
        store.get(hb, PASS)


def test_verify(store):
    h = store.put_bytes(b"integro", PASS)
    assert store.verify(h, PASS) is True
    assert store.verify(h, "another") is False
    assert store.verify("f" * 64, PASS) is False


# Implementation note.
# Implementation note.
# Implementation note.

def test_agent_archive_and_restore_with_audit(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)

    src = tmp_path / "contract.txt"
    src.write_text("contract of compraventa of the casa", encoding="utf-8")
    h = agent.archive_artifact(src, PASS)

    src.unlink()                          # the original desaparece
    dest = tmp_path / "recuperado.txt"
    agent.restore_artifact(h, dest, PASS, actor="heir_1")
    assert dest.read_text(encoding="utf-8") == "contract of compraventa of the casa"

    events = [e["event_type"] for e in agent._audit.events()]
    assert "ARTIFACT_ARCHIVED" in events
    assert "ARTIFACT_RESTORED" in events


def test_agent_archive_requires_unlocked(tmp_path):
    agent = LegacyAgent(tmp_path / "data", "owner")
    agent.initialize(PASS)
    agent.lock(PASS)
    with pytest.raises(RuntimeError):
        agent.archive_artifact(Path("/tmp/x"), PASS)
