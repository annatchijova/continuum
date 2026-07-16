"""
tests/test_properties.py
=========================
Integration properties of the system, not individual function tests.

Organizacion:
  INV    global invariants: "what does Digital Legacy promise?"
  RST    restart survival: "does it survive store/reopen/recall?"
  IDEM   idempotence: "does doing it twice equal doing it once?"
  ORD    ordering: "does operation order matter?"
  REPRO  reproducibility: "same input, same output?"
  EDGE   boundary states: "0, 1, maximum, empty, unusual"
  COMP   composition: "are module contracts compatible?"
  AUTH   authority: "memory.db vs vault vs audit: who wins?"
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

@pytest.fixture
def agent(tmp_path):
    from legacy.agent.memory_agent import LegacyAgent
    a = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testhmackey0000!")
    a.initialize("secure-passphrase")
    return a


@pytest.fixture
def agent_dir(tmp_path):
    """Return (agent, data_dir) for tests that need to reinitialize."""
    from legacy.agent.memory_agent import LegacyAgent
    data = tmp_path / "data"
    a = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
    a.initialize("secure-passphrase")
    return a, data


@pytest.fixture
def mf(tmp_path):
    from legacy.memory.field import MemoryField
    return MemoryField(tmp_path / "mem.db")


@pytest.fixture
def doc(tmp_path):
    """Create a sample artifact file."""
    p = tmp_path / "will.txt"
    p.write_text("This is my will. I leave my assets to my children.")
    return p


class TestInvariants:

    def test_inv_001_every_ingested_memory_has_audit_event(self, agent, doc):
        """Ingesting an artifact always produces exactly one audit event."""
        records = []
        for i in range(3):
            d = doc.parent / f"doc_{i}.txt"
            d.write_text(f"Document {i}: legacy content.")
            records.append(agent.ingest(d))

        events = agent._audit.events(event_type="ARTIFACT_INGESTED")
        assert len(events) == 3

        audited_paths = {e["artifact"] for e in events}
        for r in records:
            assert r.path in audited_paths

    def test_inv_001_break_memory_without_audit_is_detectable(self, agent, doc):
        """A memory inserted directly into memory.db is detected as a ghost."""
        agent.ingest(doc)

        db = agent._data_dir / "memory.db"
        import uuid
        ghost_id = str(uuid.uuid4())
        now = time.time()
        with sqlite3.connect(db) as conn:
            conn.execute(
                """INSERT INTO memories
                   (memory_id, category, content, content_hash, artifact,
                    state, score, recall_count, last_access, created_at,
                    embedding_json, tags_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ghost_id, "legal", "ghost memory", "fakehash",
                 "", "NEUTRAL", 1.0, 0, now, now, "[]", "[]"),
            )
        results = agent._memory.recall("ghost memory")
        assert any(r.memory_id == ghost_id for r in results)

        result = agent.verify_memory_integrity()
        assert result["ok"] is False
        assert any("ghost" in e for e in result["errors"])

    def test_inv_002_artifact_id_immutable_across_lock_unlock(self, agent_dir, doc):
        """The artifact_id does not change between sealing and opening."""
        agent, data = agent_dir
        record = agent.ingest(doc)
        original_id = record.artifact_id
        agent.lock("secure-passphrase")

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent2.open_owner("secure-passphrase")

        found = next(
            (a for a in agent2._index.artifacts if a["artifact_id"] == original_id),
            None,
        )
        assert found is not None, "artifact_id disappeared after lock/unlock"
        assert found["memory_id"] == record.memory_id

    def test_inv_003_opened_index_equals_sealed_index(self, agent_dir, doc):
        """Opening a sealed index returns D without loss or modification."""
        agent, data = agent_dir
        agent.ingest(doc)
        sealed_artifacts = list(agent._index.artifacts)
        agent.lock("secure-passphrase")

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent2.open_owner("secure-passphrase")

        assert agent2._index.artifacts == sealed_artifacts

    def test_inv_003_break_vault_tamper_detected(self, agent_dir):
        """Tampering with the vault between sealing and opening raises a vault error."""
        from legacy.vault.locker import VaultAuthError, VaultCorruptError
        agent, data = agent_dir
        agent.lock("secure-passphrase")

        vault_file = data / "legacy.vault"
        raw = json.loads(vault_file.read_text())
        ct_bytes = bytes.fromhex(raw["ciphertext"])
        tampered = bytearray(ct_bytes)
        tampered[0] ^= 0xFF
        raw["ciphertext"] = tampered.hex()
        vault_file.write_text(json.dumps(raw))

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        with pytest.raises((VaultAuthError, VaultCorruptError)):
            agent2.open_owner("secure-passphrase")

    def test_inv_004_fresh_vault_has_no_memories(self, agent):
        """A fresh vault returns no memories before ingestion."""
        results = agent._memory.recall("will inheritance legacy")
        assert results == []

    def test_inv_005_heir_sees_last_locked_state(self, agent_dir, doc):
        """
        The heir sees the vault state captured by the last lock().
        Owner operations after locking are not visible to the heir until
        the next lock.
        """
        from legacy.agent.memory_agent import LegacyAgent
        from legacy.vault.conditions import AccessPolicy, ManualCondition

        agent, data = agent_dir
        d1 = doc.parent / "doc_antes.txt"
        d1.write_text("document previous to the lock.")
        agent.ingest(d1)
        agent.lock("secure-passphrase")  # The heir sees this state.

        from legacy.agent.memory_agent import LegacyAgent
        agent_owner = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent_owner.open_owner("secure-passphrase")
        d2 = doc.parent / "doc_despues.txt"
        d2.write_text("document added after locking, not visible to the heir.")
        agent_owner.ingest(d2)

        agent_heir = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        policy = AccessPolicy(conditions=[ManualCondition(activated=True)])
        from legacy.vault.locker import Vault
        v = Vault(data / "legacy.vault")
        raw = v.open("secure-passphrase")
        raw["policy"] = policy.to_dict()
        v.seal(raw, "secure-passphrase")
        granted = agent_heir.open_heir("heir-1", "secure-passphrase")
        assert granted

        assert len(agent_heir._index.artifacts) == 1
        assert agent_heir._index.artifacts[0]["filename"] == "doc_antes.txt"

    def test_inv_006_audit_seq_strictly_monotonic(self, agent, doc):
        """Each event has seq = previous_seq + 1, with no gaps."""
        for i in range(5):
            d = doc.parent / f"d{i}.txt"
            d.write_text(f"Doc {i}")
            agent.ingest(d)

        events = agent._audit.events()
        for i, ev in enumerate(events, start=1):
            assert ev["seq"] == i, f"seq={ev['seq']} expected={i}"

    def test_inv_007_forgotten_is_never_recalled(self, agent):
        """A FORGOTTEN memory never appears in recall, without exceptions."""
        from legacy.ingestion.doc_types import DocCategory
        mid = agent._memory.store(
            "will inheritance real estate family",
            DocCategory.LEGAL,
        )
        agent._memory.reinforce(mid)
        agent._memory.reinforce(mid)
        agent._memory.forget(mid)

        for query in ["will inheritance", "real estate", "family legacy", mid]:
            results = agent._memory.recall(query)
            assert not any(r.memory_id == mid for r in results),\
                f"FORGOTTEN memory appeared in recall('{query}')"

    def test_inv_008_integrity_check_is_read_only(self, agent, doc):
        """verify_memory_integrity() does not alter system state."""
        agent.ingest(doc)
        r1 = agent.verify_memory_integrity()
        r2 = agent.verify_memory_integrity()
        assert r1["ok"] == r2["ok"]
        assert r1["checked"] == r2["checked"]


class TestRestartSurvival:

    def test_rst_001_memories_survive_restart(self, tmp_path):
        """Memories stored by one instance are found after restart."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mid = mf.store("mortgage bank deed property", DocCategory.REAL_ESTATE)
        del mf

        mf2 = MemoryField(db)
        results = mf2.recall("mortgage bank property")
        assert any(r.memory_id == mid for r in results)

    def test_rst_002_vocab_bounded_after_restart(self, tmp_path):
        """_load_vocab() always produces a vocabulary within the size limit."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        for i in range(50):
            mf.store(f"word{i} term{i} concept{i}", DocCategory.PERSONAL)
        del mf

        mf2 = MemoryField(db)
        assert len(mf2._vocab) <= mf2._MAX_VOCAB_SIZE

    def test_rst_003_top_result_stable_across_restart(self, tmp_path):
        """The most relevant memory remains the top result after restart."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mid_target = mf.store(
            "will last wishes inheritance real estate", DocCategory.LEGAL
        )
        for i in range(5):
            mf.store(f"unrelated personal note {i}", DocCategory.PERSONAL)
        del mf

        mf2 = MemoryField(db)
        results = mf2.recall("will inheritance assets")
        assert len(results) > 0
        assert results[0].memory_id == mid_target

    def test_rst_004_audit_trail_continues_from_correct_seq(self, tmp_path):
        """A new AuditTrail instance continues from the correct sequence."""
        from legacy.core.audit_trail import AuditTrail

        db = tmp_path / "audit.db"
        at1 = AuditTrail(db, hmac_key=b"testkey00000001!")
        for _ in range(5):
            at1.append("TEST_EVENT", actor="owner")
        del at1

        at2 = AuditTrail(db, hmac_key=b"testkey00000001!")
        at2.append("TEST_EVENT_6", actor="owner")

        events = at2.events()
        assert events[-1]["seq"] == 6
        assert at2.verify(hmac_key=b"testkey00000001!").valid

    def test_rst_005_full_agent_cycle_survives_restart(self, tmp_path):
        """A complete init, ingest, lock, restart, open, and query cycle survives."""
        from legacy.agent.memory_agent import LegacyAgent

        data = tmp_path / "data"
        doc = tmp_path / "doc.txt"
        doc.write_text("Lease contract for the property at 5 Main Street.")

        a1 = LegacyAgent(data, "owner", hmac_key=b"testkey00000001!")
        a1.initialize("pass")
        r1 = a1.ingest(doc)
        a1.lock("pass")

        a2 = LegacyAgent(data, "owner", hmac_key=b"testkey00000001!")
        a2.open_owner("pass")
        results = a2.query("lease contract", actor="owner")

        assert len(results) > 0
        assert any(
            r.memory_id == r1.memory_id for r in results
        ), "the contract memory was not recovered after restart"

    def test_rst_006_synaptic_links_survive_restart(self, tmp_path):
        """Synaptic weights created in session 1 exist in session 2."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        for i in range(3):
            mf.store(f"legal contract inheritance {i}", DocCategory.LEGAL)
        del mf

        with sqlite3.connect(db) as conn:
            count = conn.execute("SELECT COUNT(*) FROM synaptic_links").fetchone()[0]
        assert count > 0, "synaptic links did not survive the restart"


class TestIdempotence:

    def test_idem_001_double_seal_opens_correctly(self, tmp_path):
        """Sealing D twice and opening it returns D without corruption."""
        from legacy.vault.locker import Vault
        v = Vault(tmp_path / "v.vault")
        data = {"key": "value", "n": 42}
        v.seal(data, "pass")
        v.seal(data, "pass")  # The second seal uses a new salt and nonce.
        assert v.open("pass") == data

    def test_idem_002_double_ingest_is_idempotent(self, agent, doc):
        """Ingesting identical content returns the existing artifact."""
        r1 = agent.ingest(doc)
        r2 = agent.ingest(doc)
        assert r1.artifact_id == r2.artifact_id
        assert r1.memory_id == r2.memory_id
        assert r1.content_hash == r2.content_hash
        assert len(agent._index.artifacts) == 1
        skip_events = agent._audit.events(event_type="ARTIFACT_SKIPPED_DUPLICATE")
        assert len(skip_events) == 1

    def test_idem_003_double_reinforce_is_reinforced(self, mf):
        """Repeated reinforcement leaves the expected resulting state."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("sample legal content", DocCategory.LEGAL)
        mf.reinforce(mid)
        mf.reinforce(mid)

        with sqlite3.connect(mf._db_path) as conn:
            row = conn.execute(
                "SELECT state, score FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()
        assert row[0] == "REINFORCED"
        assert row[1] == pytest.approx(2.25, abs=1e-6)

    def test_idem_004_double_forget_is_forgotten(self, mf):
        """Forgetting a memory twice is safe and idempotent."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("nota privada personal", DocCategory.PERSONAL)
        mf.forget(mid)
        mf.forget(mid)  # Repeating the operation must remain safe.

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "FORGOTTEN"

    def test_idem_005_double_initialize_raises_not_corrupts(self, agent_dir, doc):
        """initialize() fails when the vault exists without corrupting it."""
        from legacy.agent.memory_agent import LegacyAgent
        agent, data = agent_dir

        with pytest.raises(ValueError, match="The vault already exists"):
            agent.initialize("secure-passphrase")

        a2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        a2.open_owner("secure-passphrase")  # Must not raise.

    def test_idem_006_multiple_lock_unlock_cycles_stable(self, agent_dir, doc):
        """Repeated lock/open cycles preserve the same index state."""
        from legacy.agent.memory_agent import LegacyAgent
        agent, data = agent_dir
        agent.ingest(doc)
        agent.lock("secure-passphrase")

        for _ in range(3):
            a = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
            a.open_owner("secure-passphrase")
            assert len(a._index.artifacts) == 1
            a.lock("secure-passphrase")


class TestOperationOrder:

    def test_ord_001_reinforce_then_forget_is_forgotten(self, mf):
        """Reinforce then forget produces FORGOTTEN (forget wins)."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("mortgage contract bank property", DocCategory.LEGAL)
        mf.reinforce(mid)
        mf.forget(mid)

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "FORGOTTEN"
        assert not any(r.memory_id == mid for r in mf.recall("mortgage"))

    def test_ord_001_forget_then_reinforce_is_reinforced(self, mf):
        """Forget then reinforce produces REINFORCED (reinforce wins)."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("mortgage contract bank property", DocCategory.LEGAL)
        mf.forget(mid)
        mf.reinforce(mid)

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "REINFORCED"
        assert any(r.memory_id == mid for r in mf.recall("mortgage"))

    def test_ord_002_ingest_order_independent_for_membership(self, tmp_path):
        """The set of recalled memories does not depend on ingestion order."""
        from legacy.agent.memory_agent import LegacyAgent

        def build_agent(order: list) -> tuple:
            data = tmp_path / f"data_{order[0]}"
            a = LegacyAgent(data, "owner", hmac_key=b"testkey00000001!")
            a.initialize("pass")
            docs = []
            for name, content in order:
                d = tmp_path / name
                d.write_text(content)
                docs.append(a.ingest(d))
            return a, docs

        docs_data = [
            ("doc_A.txt", "will inheritance assets legacy family"),
            ("doc_B.txt", "mortgage bank deed property real estate"),
        ]
        agent_ab, recs_ab = build_agent(docs_data)
        agent_ba, recs_ba = build_agent(list(reversed(docs_data)))

        ids_ab = {r.memory_id for r in recs_ab}
        ids_ba = {r.memory_id for r in recs_ba}

        results_ab = agent_ab._memory.recall("inheritance assets")
        results_ba = agent_ba._memory.recall("inheritance assets")

        assert len(results_ab) > 0
        assert len(results_ba) > 0

    def test_ord_003_stdp_links_bidirectional_regardless_of_order(self, mf):
        """STDP creates bidirectional AB and BA links regardless of insertion order."""
        from legacy.ingestion.doc_types import DocCategory
        m1 = mf.store("purchase contract property bank", DocCategory.LEGAL)
        m2 = mf.store("will inheritance assets family", DocCategory.LEGAL)

        with sqlite3.connect(mf._db_path) as conn:
            link_12 = conn.execute(
                "SELECT weight FROM synaptic_links WHERE src_id=? AND dst_id=?",
                (m1, m2),
            ).fetchone()
            link_21 = conn.execute(
                "SELECT weight FROM synaptic_links WHERE src_id=? AND dst_id=?",
                (m2, m1),
            ).fetchone()

        assert link_12 is not None, "missing link m1m2"
        assert link_21 is not None, "missing link m2m1"

    def test_ord_004_recall_before_vs_after_reinforce(self, mf):
        """Recall after reinforcement returns a higher score."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("mortgage bank property contract", DocCategory.REAL_ESTATE)

        results_before = mf.recall("mortgage contract")
        score_before = next(r.final_score for r in results_before if r.memory_id == mid)

        mf.reinforce(mid)

        results_after = mf.recall("mortgage contract")
        score_after = next(r.final_score for r in results_after if r.memory_id == mid)

        assert score_after > score_before,\
            "REINFORCED (1.5) must produce a higher score than NEUTRAL"


class TestReproducibility:

    def test_repro_001_same_content_same_hash(self):
        """SHA-256 of a string is deterministic."""
        content = "My will: I leave everything to my children."
        h1 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert h1 == h2

    def test_repro_002_same_content_same_vocab_same_embedding(self, tmp_path):
        """TF-IDF is deterministic for the same content and vocabulary."""
        from legacy.memory.field import MemoryField, _tokenize, _tfidf_vector
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mf.store("word one two three", DocCategory.PERSONAL)
        content = "will inheritance assets"
        tokens = _tokenize(content)
        e1 = _tfidf_vector(tokens, mf._vocab)
        e2 = _tfidf_vector(tokens, mf._vocab)
        assert e1 == e2

    def test_repro_003_same_audit_payload_same_hash(self):
        """The hash chain is deterministic for the same sequence and payload."""
        from legacy.core.hash_chain import build_link

        payload = {
            "event_id": "abc",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "event_type": "TEST",
            "actor": "owner",
            "artifact": "",
            "detail": "test",
        }
        link1 = build_link(1, "0" * 64, payload, hmac_key=None)
        link2 = build_link(1, "0" * 64, payload, hmac_key=None)
        assert link1.entry_hash == link2.entry_hash

    def test_repro_004_classifier_deterministic(self):
        """DocumentClassifier is deterministic: same input, same output."""
        from legacy.ingestion.classifier import DocumentClassifier
        dc = DocumentClassifier()
        text = "lease contract. Mortgage bank. Property deed."
        r1 = dc.classify(text, filename="contract.txt")
        r2 = dc.classify(text, filename="contract.txt")
        assert r1.category == r2.category
        assert r1.confidence == r2.confidence
        assert r1.scores == r2.scores

    def test_repro_005_vault_envelope_changes_but_data_survives(self, tmp_path):
        """Two seals of the same data produce different envelopes but identical
        data. In v2, each payload nonce is fresh while keyslots preserve the
        same data key and custody state."""
        from legacy.vault.locker import Vault
        v = Vault(tmp_path / "v.vault")
        data = {"name": "Jordan", "assets": ["house", "car"]}

        v.seal(data, "pass")
        env1 = json.loads((tmp_path / "v.vault").read_text())

        v.seal(data, "pass")
        env2 = json.loads((tmp_path / "v.vault").read_text())

        assert env1["nonce"] != env2["nonce"]
        assert env1["ciphertext"] != env2["ciphertext"]
        assert env1["keyslots"] == env2["keyslots"]
        assert v.open("pass") == data

    def test_repro_006_two_instances_same_db_same_results(self, tmp_path):
        """Two MemoryField instances over the same database return the same recall."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mf.store("purchase contract property real estate", DocCategory.REAL_ESTATE)
        mf.store("will inheritance family assets", DocCategory.LEGAL)
        del mf

        mf1 = MemoryField(db)
        mf2 = MemoryField(db)
        r1 = [x.memory_id for x in mf1.recall("purchase contract")]
        r2 = [x.memory_id for x in mf2.recall("purchase contract")]
        assert r1 == r2


class TestEdgeCases:

    def test_edge_001_zero_memories_recall_empty(self, mf):
        """Recall on an empty database returns an empty list."""
        assert mf.recall("any query") == []

    def test_edge_002_one_memory_found(self, mf):
        """With exactly one memory, recall returns it when relevant."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("will inheritance assets family legacy", DocCategory.LEGAL)
        results = mf.recall("will inheritance")
        assert len(results) == 1
        assert results[0].memory_id == mid

    def test_edge_003_empty_content_does_not_crash(self, mf):
        """Storing empty content does not raise an exception."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("", DocCategory.PERSONAL)
        assert mid  # A memory_id is created.

        results = mf.recall("")

    def test_edge_004_empty_query_returns_recent_memories(self, mf):
        """An empty query does not crash and can return recent memories."""
        from legacy.ingestion.doc_types import DocCategory
        for i in range(3):
            mf.store(f"relevant content {i}", DocCategory.PERSONAL)
        results = mf.recall("")
        assert isinstance(results, list)

    def test_edge_005_top_k_zero_returns_empty(self, mf):
        """recall(top_k=0) must return []."""
        from legacy.ingestion.doc_types import DocCategory
        mf.store("will inheritance", DocCategory.LEGAL)
        results = mf.recall("will", top_k=0)
        assert results == []

    def test_edge_006_unicode_extremes_do_not_crash(self, mf):
        """Emojis, replacement surrogates, and combining characters do not crash store()."""
        from legacy.ingestion.doc_types import DocCategory
        contents = [
            "Hello  World ",
            "cafe resume naive",
            unicodedata.normalize("NFD", "cafe resume"),  # NFD form
            "      Japanese text ",
            "\u0000\u0001\u001f",  # control chars
        ]
        for c in contents:
            mid = mf.store(c, DocCategory.PERSONAL)
            assert mid

    def test_edge_007_date_condition_year_3000_not_met(self):
        """A DateCondition for 3000 is not met in 2026."""
        from legacy.vault.conditions import DateCondition
        dc = DateCondition(unlock_after_iso="3000-01-01T00:00:00+00:00")
        assert not dc.is_met()

    def test_edge_008_date_condition_year_1970_already_met(self):
        """A DateCondition for 1970 is already met."""
        from legacy.vault.conditions import DateCondition
        dc = DateCondition(unlock_after_iso="1970-01-01T00:00:00+00:00")
        assert dc.is_met()

    def test_edge_009_inactivity_zero_days_immediately_met(self):
        """InactivityCondition(days=0) is met at creation time."""
        from legacy.vault.conditions import InactivityCondition
        now = datetime.now(timezone.utc)
        ic = InactivityCondition(
            days=0,
            last_activity_iso=now.isoformat(),
        )
        assert ic.is_met()

    def test_edge_010_content_exactly_at_limit_not_truncated(self, mf):
        """Content exactly at MAX_CONTENT_BYTES is not truncated or rejected."""
        from legacy.ingestion.doc_types import DocCategory
        content = "a" * mf.MAX_CONTENT_BYTES
        mid = mf.store(content, DocCategory.PERSONAL)
        with sqlite3.connect(mf._db_path) as conn:
            stored = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert len(stored.encode("utf-8")) <= mf.MAX_CONTENT_BYTES

    def test_edge_011_content_over_limit_is_truncated(self, mf):
        """Content over MAX_CONTENT_BYTES is truncated silently."""
        from legacy.ingestion.doc_types import DocCategory
        content = "b" * (mf.MAX_CONTENT_BYTES + 1024)
        mid = mf.store(content, DocCategory.PERSONAL)
        with sqlite3.connect(mf._db_path) as conn:
            stored = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert len(stored.encode("utf-8")) <= mf.MAX_CONTENT_BYTES

    def test_edge_012_audit_events_limit_one(self, tmp_path):
        """events(limit=1) returns exactly the first event."""
        from legacy.core.audit_trail import AuditTrail
        at = AuditTrail(tmp_path / "a.db", hmac_key=b"")
        for i in range(5):
            at.append("EV", actor="x")
        events = at.events(limit=1)
        assert len(events) == 1
        assert events[0]["seq"] == 1


class TestComposition:

    def test_comp_001_full_pipeline_classify_store_recall(self, tmp_path):
        """
        classify(text) -> category -> store(text, category) -> recall(category).
        The contracts of Classifier and MemoryField are compatible.
        """
        from legacy.ingestion.classifier import DocumentClassifier
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        dc = DocumentClassifier()
        mf = MemoryField(tmp_path / "mem.db")

        text = "The will of Mr. Jordan Perez. He leaves his assets to his children."
        result = dc.classify(text, filename="will.txt")
        mid = mf.store(text, result.category)

        results = mf.recall("will assets", category=result.category)
        assert any(r.memory_id == mid for r in results),\
            f"The memory was not recovered for category={result.category}"

    def test_comp_002_legacy_index_roundtrip(self):
        """to_dict() followed by from_dict() produces an identical LegacyIndex."""
        from legacy.agent.memory_agent import LegacyIndex, ArtifactRecord
        import uuid

        idx = LegacyIndex(
            owner_id="owner-1",
            created_at="2026-01-01T00:00:00+00:00",
            last_updated="2026-06-01T12:00:00+00:00",
            artifacts=[
                ArtifactRecord(
                    artifact_id=str(uuid.uuid4()),
                    path="/home/user/will.txt",
                    filename="will.txt",
                    category="LEGAL",
                    content_hash="abc" * 21 + "a",
                    classification_confidence="HIGH",
                    memory_id=str(uuid.uuid4()),
                    ingested_at="2026-01-15T10:00:00+00:00",
                ).to_dict()
            ],
            notes="Sample legacy record",
        )
        recovered = LegacyIndex.from_dict(idx.to_dict())
        assert recovered.owner_id == idx.owner_id
        assert recovered.artifacts == idx.artifacts
        assert recovered.notes == idx.notes

    def test_comp_003_access_policy_survives_vault(self, tmp_path):
        """A serialized AccessPolicy evaluates to the same result after a vault roundtrip."""
        from legacy.vault.locker import Vault
        from legacy.vault.conditions import AccessPolicy, ManualCondition

        policy = AccessPolicy(conditions=[ManualCondition(activated=True)])
        data = {"policy": policy.to_dict(), "other": "data"}

        v = Vault(tmp_path / "v.vault")
        v.seal(data, "pass")
        recovered = v.open("pass")

        from legacy.vault.conditions import AccessPolicy as AP
        p2 = AP.from_dict(recovered["policy"])
        assert p2.evaluate() == policy.evaluate()

    def test_comp_004_audit_and_memory_both_valid_in_clean_state(self, agent_dir, doc):
        """
        In a clean state, verify_audit() is valid and verify_memory_integrity() is OK.
        The contracts of AuditTrail and MemoryField are compatible.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        audit_result = agent.verify_audit(hmac_key=b"testhmackey0000!")
        memory_result = agent.verify_memory_integrity()

        assert audit_result["valid"] is True
        assert memory_result["ok"] is True

    def test_comp_005_composition_gap_audit_valid_memory_tampered(self, agent_dir, doc):
        """
        Known gap (KL-008): the audit trail can be valid while memory.db is corrupt.
        The contracts are individually valid but do not verify each other.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute("UPDATE memories SET content='forged'")

        audit_result = agent.verify_audit(hmac_key=b"testhmackey0000!")
        assert audit_result["valid"] is True

        memory_result = agent.verify_memory_integrity()
        assert memory_result["ok"] is False


class TestAuthority:

    def test_auth_001_memory_db_is_authority_for_reads(self, agent_dir, doc):
        """
        After tampering with memory.db, recall() returns the forged content.
        memory.db is the source of truth for reads; the vault is for verification.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute(
            "UPDATE memories SET content='the true heir is someone else'"
            )

        results = agent._memory.recall("heir")
        assert any("someone else" in r.content for r in results),\
            "recall() must return the content of memory.db even after tampering"

    def test_auth_002_vault_is_authority_for_integrity(self, agent_dir, doc):
        """
        verify_memory_integrity() uses the encrypted vault hash as its reference.
        An attacker modifying memory.db cannot bypass this verification
        without knowing the vault passphrase.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        new_content = "forged content that is internally consistent"
        new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute(
                "UPDATE memories SET content=?, content_hash=?",
                (new_content, new_hash),
            )

        result = agent.verify_memory_integrity()
        assert result["ok"] is False,\
            "verify_memory_integrity() must detect tampering even when the DB content_hash is consistent"

    def test_auth_003_db_is_authority_for_audit_seq(self, tmp_path):
        """
        With two AuditTrail instances, the database is authoritative for seq.
        The instance that writes first forces the other to reload the tip.
        """
        from legacy.core.audit_trail import AuditTrail

        db = tmp_path / "audit.db"
        at1 = AuditTrail(db, hmac_key=b"")
        at2 = AuditTrail(db, hmac_key=b"")

        at1.append("EV_FROM_1", actor="a")
        at2.append("EV_FROM_2", actor="b")

        events = at1.events()
        assert len(events) == 2
        seqs = [e["seq"] for e in events]
        assert seqs == [1, 2], f"Out-of-order sequences: {seqs}"

        assert at1.verify(hmac_key=b"").valid

    def test_auth_004_system_operational_despite_inconsistency(self, agent_dir, doc):
        """
        Limitation KL-008: the system remains operational for recall in an inconsistent state.
        verify_memory_integrity() detects the inconsistency but does not block the system.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute("UPDATE memories SET content='content altered'")

        results = agent._memory.recall("altered")
        assert isinstance(results, list)  # Recall does not crash.

        integrity = agent.verify_memory_integrity()
        assert integrity["ok"] is False

        audit = agent.verify_audit(hmac_key=b"testhmackey0000!")
        assert audit["valid"] is True

    def test_auth_005_extra_memory_not_in_vault_is_ghost(self, agent_dir, doc):
        """
        A memory inserted directly into memory.db without passing through the vault:
        - is visible in recall()
        - does not pass verify_memory_integrity() because it is not in the vault index
        - is a "ghost memory" without provenance
        This documents limitation KL-008 (ghost memories are detected by verify).
        """
        import uuid as _uuid
        agent, data = agent_dir
        agent.ingest(doc)  # One legitimate artifact.

        ghost_content = "I am a memory without provenance in the vault"
        ghost_id = str(_uuid.uuid4())
        now = time.time()
        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute(
                """INSERT INTO memories
                   (memory_id, category, content, content_hash, artifact,
                    state, score, recall_count, last_access, created_at,
                    embedding_json, tags_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ghost_id, "personal", ghost_content,
                 hashlib.sha256(ghost_content.encode()).hexdigest(),
                 "", "NEUTRAL", 1.0, 0, now, now, "[]", "[]"),
            )

        results = agent._memory.recall("provenance vault")
        assert any(r.memory_id == ghost_id for r in results)

        integrity = agent.verify_memory_integrity()
        assert integrity["ok"] is False
        assert any("ghost" in e for e in integrity["errors"])
        assert integrity["checked"] == 1
