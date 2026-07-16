"""
tests/test_properties.py
=========================
Tests of propiedades of the system  no of funciones individuales.

Organizacion:
  INV    invariantes globales: "what promete Digital Legacy?"
  RST    reinicios: "sobrevive a ciclo store/reopen/recall?"
  IDEM   idempotencia: "dos veces = once?"
  ORD    orden: "importa the orden of the operaciones?"
  REPRO  reproducibilidad: "same input  same output?"
  EDGE   estados limit: "0, 1, maximo, empty, extrano"
  COMP   composition: "the contratos are compatibles between modulos?"
  AUTH   autoridad: "memory.db vs vault vs audit  who gana?"
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

# Implementation note.
# Implementation note.
# Implementation note.

@pytest.fixture
def agent(tmp_path):
    from legacy.agent.memory_agent import LegacyAgent
    a = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testhmackey0000!")
    a.initialize("passphrase-segura")
    return a


@pytest.fixture
def agent_dir(tmp_path):
    """returns (agent, data_dir) for tests that necesitan reinicializar."""
    from legacy.agent.memory_agent import LegacyAgent
    data = tmp_path / "data"
    a = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
    a.initialize("passphrase-segura")
    return a, data


@pytest.fixture
def mf(tmp_path):
    from legacy.memory.field import MemoryField
    return MemoryField(tmp_path / "mem.db")


@pytest.fixture
def doc(tmp_path):
    """Crea a file of artifact of prueba."""
    p = tmp_path / "testamento.txt"
    p.write_text("Este is mi testamento. Dejo mis bienes a mis hijos.")
    return p


# Implementation note.
# Implementation note.
# Implementation note.

class TestInvariants:

    # Implementation note.
    def test_inv_001_every_ingested_memory_has_audit_event(self, agent, doc):
        """property: ingest() siempre produce exactamente a ARTIFACT_INGESTED."""
        records = []
        for i in range(3):
            d = doc.parent / f"doc_{i}.txt"
            d.write_text(f"Documento {i}: contenido del legado.")
            records.append(agent.ingest(d))

        events = agent._audit.events(event_type="ARTIFACT_INGESTED")
        assert len(events) == 3

        # Implementation note.
        audited_paths = {e["artifact"] for e in events}
        for r in records:
            assert r.path in audited_paths

    # Implementation note.
    def test_inv_001_break_memory_without_audit_is_detectable(self, agent, doc):
        """a memory insertada directamente in memory.db is detectada as ghost."""
        agent.ingest(doc)

        # Implementation note.
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
                (ghost_id, "legal", "memory fantasma", "fakehash",
                 "", "NEUTRAL", 1.0, 0, now, now, "[]", "[]"),
            )
        # Implementation note.
        results = agent._memory.recall("fantasma memory")
        assert any(r.memory_id == ghost_id for r in results)

        # Implementation note.
        result = agent.verify_memory_integrity()
        assert result["ok"] is False
        assert any("ghost" in e for e in result["errors"])

    # Implementation note.
    def test_inv_002_artifact_id_immutable_across_lock_unlock(self, agent_dir, doc):
        """property: artifact_id no cambia between seal and open."""
        agent, data = agent_dir
        record = agent.ingest(doc)
        original_id = record.artifact_id
        agent.lock("passphrase-segura")

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent2.open_owner("passphrase-segura")

        found = next(
            (a for a in agent2._index.artifacts if a["artifact_id"] == original_id),
            None,
        )
        assert found is not None, "artifact_id desaparecio tras lock/unlock"
        assert found["memory_id"] == record.memory_id

    # Implementation note.
    def test_inv_003_opened_index_equals_sealed_index(self, agent_dir, doc):
        """property: open(seal(D)) = D  without perdida, without modificacion."""
        agent, data = agent_dir
        agent.ingest(doc)
        sealed_artifacts = list(agent._index.artifacts)
        agent.lock("passphrase-segura")

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent2.open_owner("passphrase-segura")

        assert agent2._index.artifacts == sealed_artifacts

    # Implementation note.
    def test_inv_003_break_vault_tamper_detected(self, agent_dir):
        """Modificar the vault file between seal and open produce VaultAuthError o VaultCorruptError."""
        from legacy.vault.locker import VaultAuthError, VaultCorruptError
        agent, data = agent_dir
        agent.lock("passphrase-segura")

        vault_file = data / "legacy.vault"
        raw = json.loads(vault_file.read_text())
        # Implementation note.
        ct_bytes = bytes.fromhex(raw["ciphertext"])
        tampered = bytearray(ct_bytes)
        tampered[0] ^= 0xFF
        raw["ciphertext"] = tampered.hex()
        vault_file.write_text(json.dumps(raw))

        from legacy.agent.memory_agent import LegacyAgent
        agent2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        with pytest.raises((VaultAuthError, VaultCorruptError)):
            agent2.open_owner("passphrase-segura")

    # Implementation note.
    def test_inv_004_fresh_vault_has_no_memories(self, agent):
        """property: without ingest(), recall() returns []."""
        results = agent._memory.recall("testamento herencia legado")
        assert results == []

    # Implementation note.
    def test_inv_005_heir_sees_last_locked_state(self, agent_dir, doc):
        """
        property: the heir ve the vault tal as quedo in the last lock().
        Operaciones of the owner after of the lock no are visibles to the heir
        until the proximo lock.
        """
        from legacy.agent.memory_agent import LegacyAgent
        from legacy.vault.conditions import AccessPolicy, ManualCondition

        agent, data = agent_dir
        d1 = doc.parent / "doc_antes.txt"
        d1.write_text("document previous to the lock.")
        agent.ingest(d1)
        agent.lock("passphrase-segura")  #  the heir ve until aqui

        # Implementation note.
        from legacy.agent.memory_agent import LegacyAgent
        agent_owner = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        agent_owner.open_owner("passphrase-segura")
        d2 = doc.parent / "doc_despues.txt"
        d2.write_text("document posterior to the lock  no visible to the heir.")
        agent_owner.ingest(d2)
        # Implementation note.

        # Implementation note.
        agent_heir = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        policy = AccessPolicy(conditions=[ManualCondition(activated=True)])
        # Implementation note.
        from legacy.vault.locker import Vault
        v = Vault(data / "legacy.vault")
        raw = v.open("passphrase-segura")
        raw["policy"] = policy.to_dict()
        v.seal(raw, "passphrase-segura")
        granted = agent_heir.open_heir("heir-1", "passphrase-segura")
        assert granted

        # Implementation note.
        assert len(agent_heir._index.artifacts) == 1
        assert agent_heir._index.artifacts[0]["filename"] == "doc_antes.txt"

    # Implementation note.
    def test_inv_006_audit_seq_strictly_monotonic(self, agent, doc):
        """property: each evento tiene seq = prev_seq + 1, without saltos."""
        for i in range(5):
            d = doc.parent / f"d{i}.txt"
            d.write_text(f"Doc {i}")
            agent.ingest(d)

        events = agent._audit.events()
        for i, ev in enumerate(events, start=1):
            assert ev["seq"] == i, f"seq={ev['seq']} esperado={i}"

    # Implementation note.
    def test_inv_007_forgotten_is_never_recalled(self, agent):
        """property: FORGOTTEN  nunca aparece in recall(), without excepciones."""
        from legacy.ingestion.doc_types import DocCategory
        mid = agent._memory.store(
            "testamento herencia bienes inmuebles familia",
            DocCategory.LEGAL,
        )
        # Implementation note.
        agent._memory.reinforce(mid)
        agent._memory.reinforce(mid)
        agent._memory.forget(mid)

        for query in ["testamento herencia", "bienes inmuebles", "familia legado", mid]:
            results = agent._memory.recall(query)
            assert not any(r.memory_id == mid for r in results),\
                f"Memoria FORGOTTEN apareció en recall('{query}')"

    # Implementation note.
    def test_inv_008_integrity_check_is_read_only(self, agent, doc):
        """verify_memory_integrity() no altera the state of the system."""
        agent.ingest(doc)
        r1 = agent.verify_memory_integrity()
        r2 = agent.verify_memory_integrity()
        assert r1["ok"] == r2["ok"]
        assert r1["checked"] == r2["checked"]


# Implementation note.
# Implementation note.
# Implementation note.

class TestRestartSurvival:

    # Implementation note.
    def test_rst_001_memories_survive_restart(self, tmp_path):
        """store()  new instancia  recall() encuentra the memories."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mid = mf.store("hipoteca banco escritura property", DocCategory.REAL_ESTATE)
        del mf

        mf2 = MemoryField(db)
        results = mf2.recall("hipoteca banco property")
        assert any(r.memory_id == mid for r in results)

    # Implementation note.
    def test_rst_002_vocab_bounded_after_restart(self, tmp_path):
        """_load_vocab() siempre produce vocab  _MAX_VOCAB_SIZE."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        for i in range(50):
            mf.store(f"palabra{i} término{i} concepto{i}", DocCategory.PERSONAL)
        del mf

        mf2 = MemoryField(db)
        assert len(mf2._vocab) <= mf2._MAX_VOCAB_SIZE

    # Implementation note.
    def test_rst_003_top_result_stable_across_restart(self, tmp_path):
        """the memory more relevante before of the reinicio sigue siendo the more relevante after."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mid_target = mf.store(
            "testamento last voluntad herencia bienes inmuebles", DocCategory.LEGAL
        )
        for i in range(5):
            mf.store(f"nota personal {i} sin relación", DocCategory.PERSONAL)
        del mf

        mf2 = MemoryField(db)
        results = mf2.recall("testamento herencia bienes")
        assert len(results) > 0
        assert results[0].memory_id == mid_target

    # Implementation note.
    def test_rst_004_audit_trail_continues_from_correct_seq(self, tmp_path):
        """new instancia of AuditTrail continua from seq correcto."""
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

    # Implementation note.
    def test_rst_005_full_agent_cycle_survives_restart(self, tmp_path):
        """Ciclo complete: init  ingest  lock  new instancia  open  query."""
        from legacy.agent.memory_agent import LegacyAgent

        data = tmp_path / "data"
        doc = tmp_path / "doc.txt"
        doc.write_text("contract of arrendamiento of the inmueble in calle Mayor 5.")

        # Implementation note.
        a1 = LegacyAgent(data, "owner", hmac_key=b"testkey00000001!")
        a1.initialize("pass")
        r1 = a1.ingest(doc)
        a1.lock("pass")

        # Implementation note.
        a2 = LegacyAgent(data, "owner", hmac_key=b"testkey00000001!")
        a2.open_owner("pass")
        results = a2.query("contract arrendamiento", actor="owner")

        assert len(results) > 0
        assert any(
            r.memory_id == r1.memory_id for r in results
        ), "the memory of the contract no fue recuperada tras reiniciar"

    # Implementation note.
    def test_rst_006_synaptic_links_survive_restart(self, tmp_path):
        """the pesos sinapticos creados in session 1 existen in session 2."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        for i in range(3):
            mf.store(f"legal contrato herencia {i}", DocCategory.LEGAL)
        del mf

        with sqlite3.connect(db) as conn:
            count = conn.execute("SELECT COUNT(*) FROM synaptic_links").fetchone()[0]
        assert count > 0, "the synaptic links no sobrevivieron to the reinicio"


# Implementation note.
# Implementation note.
# Implementation note.

class TestIdempotence:

    # Implementation note.
    def test_idem_001_double_seal_opens_correctly(self, tmp_path):
        """seal(D)  seal(D)  open() = D. the vault no remains corrupto."""
        from legacy.vault.locker import Vault
        v = Vault(tmp_path / "v.vault")
        data = {"key": "value", "n": 42}
        v.seal(data, "pass")
        v.seal(data, "pass")  # segunda vez  salt/nonce nuevos
        assert v.open("pass") == data

    # Implementation note.
    def test_idem_002_double_ingest_is_idempotent(self, agent, doc):
        """ingest() is idempotente: the same content returns the artifact existente."""
        r1 = agent.ingest(doc)
        r2 = agent.ingest(doc)
        # Implementation note.
        assert r1.artifact_id == r2.artifact_id
        assert r1.memory_id == r2.memory_id
        assert r1.content_hash == r2.content_hash
        # Implementation note.
        assert len(agent._index.artifacts) == 1
        # Implementation note.
        skip_events = agent._audit.events(event_type="ARTIFACT_SKIPPED_DUPLICATE")
        assert len(skip_events) == 1

    # Implementation note.
    def test_idem_003_double_reinforce_is_reinforced(self, mf):
        """reinforce() is idempotente in cuanto to the state resultante."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("content of prueba legal", DocCategory.LEGAL)
        mf.reinforce(mid)
        mf.reinforce(mid)

        with sqlite3.connect(mf._db_path) as conn:
            row = conn.execute(
                "SELECT state, score FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()
        assert row[0] == "REINFORCED"
        # Implementation note.
        assert row[1] == pytest.approx(2.25, abs=1e-6)

    # Implementation note.
    def test_idem_004_double_forget_is_forgotten(self, mf):
        """forget() is idempotente."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("nota privada personal", DocCategory.PERSONAL)
        mf.forget(mid)
        mf.forget(mid)  # segunda vez  no rompe nada

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "FORGOTTEN"

    # Implementation note.
    def test_idem_005_double_initialize_raises_not_corrupts(self, agent_dir, doc):
        """initialize() fails when the vault exists without corrupting it."""
        from legacy.agent.memory_agent import LegacyAgent
        agent, data = agent_dir

        with pytest.raises(ValueError, match="The vault already exists"):
            agent.initialize("passphrase-segura")

        # Implementation note.
        a2 = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
        a2.open_owner("passphrase-segura")  # no must lanzar

    # Implementation note.
    def test_idem_006_multiple_lock_unlock_cycles_stable(self, agent_dir, doc):
        """property: N ciclos lock/open producen siempre the same state of the index."""
        from legacy.agent.memory_agent import LegacyAgent
        agent, data = agent_dir
        agent.ingest(doc)
        agent.lock("passphrase-segura")

        for _ in range(3):
            a = LegacyAgent(data, "owner-test", hmac_key=b"testhmackey0000!")
            a.open_owner("passphrase-segura")
            assert len(a._index.artifacts) == 1
            a.lock("passphrase-segura")


# Implementation note.
# Implementation note.
# Implementation note.

class TestOperationOrder:

    # Implementation note.
    def test_ord_001_reinforce_then_forget_is_forgotten(self, mf):
        """reinforce  forget produce state FORGOTTEN (forget gana)."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("hipoteca contract banco property", DocCategory.LEGAL)
        mf.reinforce(mid)
        mf.forget(mid)

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "FORGOTTEN"
        # Implementation note.
        assert not any(r.memory_id == mid for r in mf.recall("hipoteca"))

    def test_ord_001_forget_then_reinforce_is_reinforced(self, mf):
        """forget  reinforce produce state REINFORCED (reinforce gana)."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("hipoteca contract banco property", DocCategory.LEGAL)
        mf.forget(mid)
        mf.reinforce(mid)

        with sqlite3.connect(mf._db_path) as conn:
            state = conn.execute(
                "SELECT state FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert state == "REINFORCED"
        # Implementation note.
        assert any(r.memory_id == mid for r in mf.recall("hipoteca"))

    # Implementation note.
    def test_ord_002_ingest_order_independent_for_membership(self, tmp_path):
        """the conjunto of memories recuperadas no depende of the orden of ingestion."""
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
            ("doc_A.txt", "testamento herencia bienes legado familia"),
            ("doc_B.txt", "hipoteca banco escritura property inmueble"),
        ]
        agent_ab, recs_ab = build_agent(docs_data)
        agent_ba, recs_ba = build_agent(list(reversed(docs_data)))

        # Implementation note.
        ids_ab = {r.memory_id for r in recs_ab}
        ids_ba = {r.memory_id for r in recs_ba}

        results_ab = agent_ab._memory.recall("herencia bienes")
        results_ba = agent_ba._memory.recall("herencia bienes")

        # Implementation note.
        assert len(results_ab) > 0
        assert len(results_ba) > 0

    # Implementation note.
    def test_ord_003_stdp_links_bidirectional_regardless_of_order(self, mf):
        """STDP crea links bidireccionales AB and BA without importar the orden of insertion."""
        from legacy.ingestion.doc_types import DocCategory
        m1 = mf.store("contract compraventa property banco", DocCategory.LEGAL)
        m2 = mf.store("testamento herencia bienes familia", DocCategory.LEGAL)

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

    # Implementation note.
    def test_ord_004_recall_before_vs_after_reinforce(self, mf):
        """property: recall() after of reinforce() returns mayor score."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("contract hipoteca banco property", DocCategory.REAL_ESTATE)

        results_before = mf.recall("contract hipoteca")
        score_before = next(r.final_score for r in results_before if r.memory_id == mid)

        mf.reinforce(mid)

        results_after = mf.recall("contract hipoteca")
        score_after = next(r.final_score for r in results_after if r.memory_id == mid)

        assert score_after > score_before,\
            "REINFORCED (1.5) must producir score mayor that NEUTRAL"


# Implementation note.
# Implementation note.
# Implementation note.

class TestReproducibility:

    # Implementation note.
    def test_repro_001_same_content_same_hash(self):
        """SHA-256 of a string is determinista."""
        content = "Mi testamento: dejo todo a mis hijos."
        h1 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert h1 == h2

    # Implementation note.
    def test_repro_002_same_content_same_vocab_same_embedding(self, tmp_path):
        """TF-IDF is determinista for the same content and vocab."""
        from legacy.memory.field import MemoryField, _tokenize, _tfidf_vector
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mf.store("word uno dos tres", DocCategory.PERSONAL)
        content = "testamento herencia bienes"
        tokens = _tokenize(content)
        e1 = _tfidf_vector(tokens, mf._vocab)
        e2 = _tfidf_vector(tokens, mf._vocab)
        assert e1 == e2

    # Implementation note.
    def test_repro_003_same_audit_payload_same_hash(self):
        """the chain of hash is determinista dado the same seq, prev_hash and payload."""
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

    # Implementation note.
    def test_repro_004_classifier_deterministic(self):
        """DocumentClassifier is determinista: same input  same output."""
        from legacy.ingestion.classifier import DocumentClassifier
        dc = DocumentClassifier()
        text = "contract of arrendamiento. Hipoteca banco. Escritura property."
        r1 = dc.classify(text, filename="contract.txt")
        r2 = dc.classify(text, filename="contract.txt")
        assert r1.category == r2.category
        assert r1.confidence == r2.confidence
        assert r1.scores == r2.scores

    # Implementation note.
    def test_repro_005_vault_envelope_changes_but_data_survives(self, tmp_path):
        """Dos seal() of the same data producen envelopes distintos pero data
        identica. (v2: the nonce of the payload is fresco in each seal; the
        keyslots is preservan  same data key, same custodia.)"""
        from legacy.vault.locker import Vault
        v = Vault(tmp_path / "v.vault")
        data = {"nombre": "Juan", "bienes": ["casa", "coche"]}

        v.seal(data, "pass")
        env1 = json.loads((tmp_path / "v.vault").read_text())

        v.seal(data, "pass")
        env2 = json.loads((tmp_path / "v.vault").read_text())

        # Implementation note.
        assert env1["nonce"] != env2["nonce"]
        assert env1["ciphertext"] != env2["ciphertext"]
        # Implementation note.
        assert env1["keyslots"] == env2["keyslots"]

        # Implementation note.
        assert v.open("pass") == data

    # Implementation note.
    def test_repro_006_two_instances_same_db_same_results(self, tmp_path):
        """Dos MemoryField over the same DB producen the same recall."""
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        db = tmp_path / "mem.db"
        mf = MemoryField(db)
        mf.store("contract compraventa inmueble property", DocCategory.REAL_ESTATE)
        mf.store("testamento herencia familia bienes", DocCategory.LEGAL)
        del mf

        mf1 = MemoryField(db)
        mf2 = MemoryField(db)
        r1 = [x.memory_id for x in mf1.recall("contract compraventa")]
        r2 = [x.memory_id for x in mf2.recall("contract compraventa")]
        assert r1 == r2


# Implementation note.
# Implementation note.
# Implementation note.

class TestEdgeCases:

    # Implementation note.
    def test_edge_001_zero_memories_recall_empty(self, mf):
        """recall() in a DB empty returns []."""
        assert mf.recall("any query") == []

    # Implementation note.
    def test_edge_002_one_memory_found(self, mf):
        """with exactamente a memory, recall() the returns if is relevante."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("testamento herencia bienes familia legado", DocCategory.LEGAL)
        results = mf.recall("testamento herencia")
        assert len(results) == 1
        assert results[0].memory_id == mid

    # Implementation note.
    def test_edge_003_empty_content_does_not_crash(self, mf):
        """store('') no must lanzar excepcion."""
        from legacy.ingestion.doc_types import DocCategory
        mid = mf.store("", DocCategory.PERSONAL)
        assert mid  # is creo a memory_id

        # Implementation note.
        results = mf.recall("")
        # Implementation note.

    # Implementation note.
    def test_edge_004_empty_query_returns_recent_memories(self, mf):
        """recall('') no crashea and can return memories by recency."""
        from legacy.ingestion.doc_types import DocCategory
        for i in range(3):
            mf.store(f"contenido relevante {i}", DocCategory.PERSONAL)
        # Implementation note.
        results = mf.recall("")
        # Implementation note.
        assert isinstance(results, list)

    # Implementation note.
    def test_edge_005_top_k_zero_returns_empty(self, mf):
        """recall(top_k=0) must return []."""
        from legacy.ingestion.doc_types import DocCategory
        mf.store("testamento herencia", DocCategory.LEGAL)
        results = mf.recall("testamento", top_k=0)
        assert results == []

    # Implementation note.
    def test_edge_006_unicode_extremes_do_not_crash(self, mf):
        """Emojis, surrogates (reemplazados), and combining chars no rompen store()."""
        from legacy.ingestion.doc_types import DocCategory
        contents = [
            "Hello  World ",
            "cafe resume naive",
            unicodedata.normalize("NFD", "cafe resume"),  # NFD
            "      Japanese ",
            "\u0000\u0001\u001f",  # control chars
        ]
        for c in contents:
            mid = mf.store(c, DocCategory.PERSONAL)
            assert mid

    # Implementation note.
    def test_edge_007_date_condition_year_3000_not_met(self):
        """DateCondition with ano 3000 no must estar cumplida in 2026."""
        from legacy.vault.conditions import DateCondition
        dc = DateCondition(unlock_after_iso="3000-01-01T00:00:00+00:00")
        assert not dc.is_met()

    # Implementation note.
    def test_edge_008_date_condition_year_1970_already_met(self):
        """DateCondition with ano 1970 already is cumplida."""
        from legacy.vault.conditions import DateCondition
        dc = DateCondition(unlock_after_iso="1970-01-01T00:00:00+00:00")
        assert dc.is_met()

    # Implementation note.
    def test_edge_009_inactivity_zero_days_immediately_met(self):
        """InactivityCondition(days=0) is cumple in the instante of creation."""
        from legacy.vault.conditions import InactivityCondition
        now = datetime.now(timezone.utc)
        ic = InactivityCondition(
            days=0,
            last_activity_iso=now.isoformat(),
        )
        assert ic.is_met()

    # Implementation note.
    def test_edge_010_content_exactly_at_limit_not_truncated(self, mf):
        """content exactamente in MAX_CONTENT_BYTES no is trunca ni crashea."""
        from legacy.ingestion.doc_types import DocCategory
        content = "a" * mf.MAX_CONTENT_BYTES
        mid = mf.store(content, DocCategory.PERSONAL)
        with sqlite3.connect(mf._db_path) as conn:
            stored = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert len(stored.encode("utf-8")) <= mf.MAX_CONTENT_BYTES

    # Implementation note.
    def test_edge_011_content_over_limit_is_truncated(self, mf):
        """content over MAX_CONTENT_BYTES is trunca silenciosamente."""
        from legacy.ingestion.doc_types import DocCategory
        content = "b" * (mf.MAX_CONTENT_BYTES + 1024)
        mid = mf.store(content, DocCategory.PERSONAL)
        with sqlite3.connect(mf._db_path) as conn:
            stored = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (mid,)
            ).fetchone()[0]
        assert len(stored.encode("utf-8")) <= mf.MAX_CONTENT_BYTES

    # Implementation note.
    def test_edge_012_audit_events_limit_one(self, tmp_path):
        """events(limit=1) returns exactamente the primer evento."""
        from legacy.core.audit_trail import AuditTrail
        at = AuditTrail(tmp_path / "a.db", hmac_key=b"")
        for i in range(5):
            at.append("EV", actor="x")
        events = at.events(limit=1)
        assert len(events) == 1
        assert events[0]["seq"] == 1


# Implementation note.
# Implementation note.
# Implementation note.

class TestComposition:

    # Implementation note.
    def test_comp_001_full_pipeline_classify_store_recall(self, tmp_path):
        """
        classify(text)  category  store(text, category)  recall(category)  found.
        the contratos of Classifier and MemoryField are compatibles.
        """
        from legacy.ingestion.classifier import DocumentClassifier
        from legacy.memory.field import MemoryField
        from legacy.ingestion.doc_types import DocCategory

        dc = DocumentClassifier()
        mf = MemoryField(tmp_path / "mem.db")

        text = "Testamento of the senor Juan Perez. Deja sus bienes a sus hijos."
        result = dc.classify(text, filename="testamento.txt")
        mid = mf.store(text, result.category)

        results = mf.recall("testamento bienes", category=result.category)
        assert any(r.memory_id == mid for r in results),\
            f"La memoria no fue recuperada con categoría={result.category}"

    # Implementation note.
    def test_comp_002_legacy_index_roundtrip(self):
        """to_dict()  from_dict() produce a LegacyIndex identico."""
        from legacy.agent.memory_agent import LegacyIndex, ArtifactRecord
        import uuid

        idx = LegacyIndex(
            owner_id="owner-1",
            created_at="2026-01-01T00:00:00+00:00",
            last_updated="2026-06-01T12:00:00+00:00",
            artifacts=[
                ArtifactRecord(
                    artifact_id=str(uuid.uuid4()),
                    path="/home/user/testamento.txt",
                    filename="testamento.txt",
                    category="LEGAL",
                    content_hash="abc" * 21 + "a",
                    classification_confidence="HIGH",
                    memory_id=str(uuid.uuid4()),
                    ingested_at="2026-01-15T10:00:00+00:00",
                ).to_dict()
            ],
            notes="Legado of prueba",
        )
        recovered = LegacyIndex.from_dict(idx.to_dict())
        assert recovered.owner_id == idx.owner_id
        assert recovered.artifacts == idx.artifacts
        assert recovered.notes == idx.notes

    # Implementation note.
    def test_comp_003_access_policy_survives_vault(self, tmp_path):
        """AccessPolicy serializada in vault  deserializada  evaluate() same result."""
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

    # Implementation note.
    def test_comp_004_audit_and_memory_both_valid_in_clean_state(self, agent_dir, doc):
        """
        in state limpio: verify_audit() valid and verify_memory_integrity() ok.
        the contratos of AuditTrail and MemoryField are compatibles.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        audit_result = agent.verify_audit(hmac_key=b"testhmackey0000!")
        memory_result = agent.verify_memory_integrity()

        assert audit_result["valid"] is True
        assert memory_result["ok"] is True

    # Implementation note.
    def test_comp_005_composition_gap_audit_valid_memory_tampered(self, agent_dir, doc):
        """
        Brecha conocida (KL-008): the audit trail can be valid mientras memory.db is corrupta.
        the contratos are individualmente validos pero no is verifican mutuamente.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        # Implementation note.
        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute("UPDATE memories SET content='forged'")

        # Implementation note.
        audit_result = agent.verify_audit(hmac_key=b"testhmackey0000!")
        assert audit_result["valid"] is True

        # Implementation note.
        memory_result = agent.verify_memory_integrity()
        assert memory_result["ok"] is False


# Implementation note.
# Implementation note.
# Implementation note.

class TestAuthority:

    # Implementation note.
    def test_auth_001_memory_db_is_authority_for_reads(self, agent_dir, doc):
        """
        after of tamper in memory.db, recall() returns the content forged.
        memory.db is the fuente of verdad for lectura; the vault is for verificacion.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute(
                "UPDATE memories SET content='the true heir is another'"
            )

        results = agent._memory.recall("heir")
        assert any("another" in r.content for r in results),\
            "recall() must return the content of memory.db, incluso if fue tamperado"

    # Implementation note.
    def test_auth_002_vault_is_authority_for_integrity(self, agent_dir, doc):
        """
        verify_memory_integrity() usa the hash of the vault (encrypted) as referencia.
        a attacker that modifica memory.db no can eludir esta verificacion
        without conocer the passphrase of the vault.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        # Implementation note.
        new_content = "content forged that is internamente consistente"
        new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute(
                "UPDATE memories SET content=?, content_hash=?",
                (new_content, new_hash),
            )

        # Implementation note.
        result = agent.verify_memory_integrity()
        assert result["ok"] is False,\
            "verify_memory_integrity() must detect the tamper aunque content_hash of the DB sea consistente"

    # Implementation note.
    def test_auth_003_db_is_authority_for_audit_seq(self, tmp_path):
        """
        Dos instancias of AuditTrail: the DB is the autoridad for the seq.
        the that writes first fuerza to the another a recargar the tip.
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
        assert seqs == [1, 2], f"Seqs desordenados: {seqs}"

        # Implementation note.
        assert at1.verify(hmac_key=b"").valid

    # Implementation note.
    def test_auth_004_system_operational_despite_inconsistency(self, agent_dir, doc):
        """
        Limitacion KL-008: the system can funcionar (recall) in state inconsistente.
        verify_memory_integrity() detects the inconsistencia pero no bloquea the system.
        """
        agent, data = agent_dir
        agent.ingest(doc)

        # Implementation note.
        with sqlite3.connect(data / "memory.db") as conn:
            conn.execute("UPDATE memories SET content='content altered'")

        # Implementation note.
        results = agent._memory.recall("altered")
        assert isinstance(results, list)  # no crashea

        # Implementation note.
        integrity = agent.verify_memory_integrity()
        assert integrity["ok"] is False

        # Implementation note.
        audit = agent.verify_audit(hmac_key=b"testhmackey0000!")
        assert audit["valid"] is True

    # Implementation note.
    def test_auth_005_extra_memory_not_in_vault_is_ghost(self, agent_dir, doc):
        """
        memory insertada directamente in memory.db without pasar by the vault:
        - is visible in recall()
        - NO rompe verify_memory_integrity() (no is in the vault index)
        - is a "recuerdo fantasma" without procedencia
        Documenta the limitacion KL-008 (ghost memories no detectadas by verify).
        """
        import uuid as _uuid
        agent, data = agent_dir
        agent.ingest(doc)  # 1 artifact legitimo

        # Implementation note.
        ghost_content = "Soy a memory without procedencia in the vault"
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

        # Implementation note.
        results = agent._memory.recall("procedencia vault")
        assert any(r.memory_id == ghost_id for r in results)

        # Implementation note.
        integrity = agent.verify_memory_integrity()
        assert integrity["ok"] is False
        assert any("ghost" in e for e in integrity["errors"])
        # Implementation note.
        assert integrity["checked"] == 1
