"""
tests/test_security_r3.py
==========================
Regresiones for the hallazgos of the audit R3.

Cubre propiedades emergentes: composition, invariantes globales,
recovery, concurrencia, degradacion acumulativa, consistencia criptografica.
"""
import sqlite3
import time
from pathlib import Path

import pytest


# Implementation note.
# Implementation note.
# Implementation note.

def test_r3_001_integrity_passes_on_clean_db(tmp_path):
    """verify_memory_integrity() returns ok=True when memory.db no fue altered."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "testamento.txt"
    doc.write_text("Este is mi testamento.")
    agent.ingest(doc)

    result = agent.verify_memory_integrity()
    assert result["ok"] is True
    assert result["checked"] == 1
    assert result["errors"] == []


def test_r3_001_integrity_detects_content_tamper(tmp_path):
    """
    verify_memory_integrity() detects when the content of memory.db
    fue modificado directamente with a editor SQLite.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "contract.txt"
    doc.write_text("contract of compraventa firmado the 2025-01-01.")
    record = agent.ingest(doc)

    # Implementation note.
    db_path = tmp_path / "data" / "memory.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE memories SET content=? WHERE memory_id=?",
            ("content forged by the attacker", record.memory_id),
        )

    result = agent.verify_memory_integrity()
    assert result["ok"] is False
    assert result["checked"] == 1
    assert any("altered" in e for e in result["errors"])


def test_r3_001_integrity_detects_missing_memory(tmp_path):
    """
    verify_memory_integrity() detects when a row of memory.db fue eliminada.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "poliza.txt"
    doc.write_text("Poliza of seguro of vida numero 12345.")
    record = agent.ingest(doc)

    # Implementation note.
    db_path = tmp_path / "data" / "memory.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM memories WHERE memory_id=?", (record.memory_id,))

    result = agent.verify_memory_integrity()
    assert result["ok"] is False
    assert any("ausente" in e for e in result["errors"])


def test_r3_001_integrity_logs_audit_event(tmp_path):
    """verify_memory_integrity() siempre registra a evento INTEGRITY_CHECK."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")
    agent.verify_memory_integrity()

    events = agent._audit.events(event_type="INTEGRITY_CHECK")
    assert len(events) == 1
    assert "memory_integrity" in events[0]["detail"]


def test_r3_001_integrity_multiple_artifacts(tmp_path):
    """with N artifacts, verify_memory_integrity() verifica all."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    for i in range(5):
        doc = tmp_path / f"doc_{i}.txt"
        doc.write_text(f"Documento número {i} del legado.")
        agent.ingest(doc)

    result = agent.verify_memory_integrity()
    assert result["ok"] is True
    assert result["checked"] == 5


# Implementation note.
# Implementation note.
# Implementation note.

def test_r3_002_vocab_capped_during_session(tmp_path):
    """
    after of ingerir muchos documents with vocabulario diverso,
    _vocab no supera _MAX_VOCAB_SIZE.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Implementation note.
    for i in range(200):
        mf.store(
            f"palabraúnica{i} términoespecífico{i} conceptonovedad{i} definiciónnueva{i}",
            DocCategory.PERSONAL,
        )

    assert len(mf._vocab) <= mf._MAX_VOCAB_SIZE


def test_r3_002_embedding_length_bounded(tmp_path):
    """the embedding almacenado in DB nunca supera _MAX_VOCAB_SIZE floats."""
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory
    import json

    mf = MemoryField(tmp_path / "mem.db")
    for i in range(100):
        mf.store(f"término{i} palabra{i} concepto{i}", DocCategory.PROFESSIONAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        rows = conn.execute("SELECT embedding_json FROM memories").fetchall()

    for row in rows:
        emb = json.loads(row[0] or "[]")
        assert len(emb) <= mf._MAX_VOCAB_SIZE


# Implementation note.
# Implementation note.
# Implementation note.

def test_r3_003_score_does_not_overflow(tmp_path):
    """after of muchos reinforce(), score no llega a float('inf')."""
    import math
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("document important testamento", DocCategory.LEGAL)

    # Implementation note.
    for _ in range(600):
        mf.reinforce(mid)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        score = conn.execute(
            "SELECT score FROM memories WHERE memory_id=?", (mid,)
        ).fetchone()[0]

    assert not math.isinf(score), "score llego a float('inf')"
    assert not math.isnan(score), "score llego a NaN"
    assert score <= mf._MAX_SCORE + 1e-6


def test_r3_003_score_cap_value():
    """_MAX_SCORE is definido and is a float positivo finito."""
    from legacy.memory.field import MemoryField
    import math
    assert hasattr(MemoryField, "_MAX_SCORE")
    assert math.isfinite(MemoryField._MAX_SCORE)
    assert MemoryField._MAX_SCORE > 0


# Implementation note.
# Implementation note.
# Implementation note.

def test_c001_low_confidence_wrong_category_missed_by_filtered_recall(tmp_path):
    """
    a document clasificado with categoria incorrect (LOW confidence) no aparece
    in recall(category=categoria_correcta).
    Esto is comportamiento esperado  documentado as C-001.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Implementation note.
    mid = mf.store("hipoteca escritura property inmueble banco", DocCategory.LEGAL)

    # Implementation note.
    results = mf.recall("hipoteca property", category=DocCategory.REAL_ESTATE)
    assert not any(r.memory_id == mid for r in results),\
        "the document filtrado by categoria incorrect no should aparecer"

    # Implementation note.
    results_all = mf.recall("hipoteca property")
    assert any(r.memory_id == mid for r in results_all)


# Implementation note.
# Implementation note.
# Implementation note.

def test_global_inv_no_double_vault_created(tmp_path):
    """
    initialize() fallara if the vault already exists  imposible tener dos VAULT_CREATED
    for the same vault.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    with pytest.raises(ValueError, match="the vault already exists"):
        agent.initialize("pass")

    events = agent._audit.events(event_type="VAULT_CREATED")
    assert len(events) == 1


def test_global_inv_synaptic_weights_never_exceed_max(tmp_path):
    """STDP_MAX_WEIGHT is the techo estricto of all the pesos sinapticos."""
    from legacy.memory.field import MemoryField, STDP_MAX_WEIGHT
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    for i in range(30):
        mf.store(f"legal contrato herencia {i}", DocCategory.LEGAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        max_w = conn.execute("SELECT MAX(weight) FROM synaptic_links").fetchone()[0]
    if max_w is not None:
        assert max_w <= STDP_MAX_WEIGHT + 1e-9


# Implementation note.
# Implementation note.
# Implementation note.

def test_degradation_recall_stable_after_many_stores(tmp_path):
    """
    recall() sigue devolviendo resultados relevantes after of ingerir
    muchos documents of distintas categorias.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    target_mid = mf.store(
        "testamento last voluntad bienes herencia legado",
        DocCategory.LEGAL,
    )

    # Implementation note.
    for i in range(200):
        cat = [DocCategory.MEDICAL, DocCategory.FINANCIAL, DocCategory.PERSONAL][i % 3]
        mf.store(f"documento {i} contenido genérico sin relación con el testamento", cat)

    results = mf.recall("testamento herencia legado")
    assert any(r.memory_id == target_mid for r in results[:5]),\
        "the memory of the testamento fue desplazada by ruido after of 200 stores"


def test_degradation_forget_then_recall_excludes_forgotten(tmp_path):
    """
    a memory marcada as FORGOTTEN nunca aparece in recall(),
    incluso with alto score historico.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("hipoteca banco escritura property", DocCategory.REAL_ESTATE)
    mf.reinforce(mid)  # elevamos the score
    mf.forget(mid)

    results = mf.recall("hipoteca banco property")
    assert not any(r.memory_id == mid for r in results),\
        "memory FORGOTTEN aparecio in recall()"


# Implementation note.
# Implementation note.
# Implementation note.

def test_recovery_vault_tmp_cleaned_on_success(tmp_path):
    """after of seal() exitoso no remains file .tmp."""
    from legacy.vault.locker import Vault

    v = Vault(tmp_path / "x.vault")
    v.seal({"k": "v"}, "pass")
    assert not (tmp_path / "x.tmp").exists()


def test_recovery_vault_original_survives_if_tmp_fails(tmp_path, monkeypatch):
    """
    if write_text over .tmp falla, the vault original no is corrompe.
    the escritura atomica (tmp  rename) garantiza that the original permanece
    intacto until that the escritura complete is in .tmp.
    """
    from legacy.vault.locker import Vault

    v = Vault(tmp_path / "x.vault")
    v.seal({"original": True}, "pass")

    # Implementation note.
    assert v.open("pass")["original"] is True

    # Implementation note.
    def always_fail(self, data, *args, **kwargs):
        raise OSError("Disco lleno simulado")

    monkeypatch.setattr(Path, "write_text", always_fail)

    with pytest.raises(OSError, match="Disco lleno"):
        v.seal({"tampered": True}, "pass")

    # Implementation note.
    # Implementation note.
    monkeypatch.undo()

    # Implementation note.
    recovered = v.open("pass")
    assert recovered["original"] is True
    assert "tampered" not in recovered


# Implementation note.
# Implementation note.
# Implementation note.

def test_crypto_consistency_vault_hash_chain_still_valid_after_r3_changes(tmp_path):
    """
    after of all the correcciones of R3, verify_audit() sigue devolviendo
    a chain valid.
    """
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner", hmac_key=b"key123456789012!")
    agent.initialize("pass")

    doc = tmp_path / "doc.txt"
    doc.write_text("content of prueba for chain of audit.")
    agent.ingest(doc)

    mid = agent._memory.stats()
    agent.reinforce_memory(
        list(agent._memory.recall("content prueba"))[0].memory_id
    )
    agent.verify_memory_integrity()

    audit_result = agent.verify_audit(hmac_key=b"key123456789012!")
    assert audit_result["valid"] is True
    # Implementation note.
    assert audit_result["broken_links"] == []
    assert audit_result["tampered_content"] == []
    assert audit_result["seq_discontinuities"] == []
    assert audit_result["hmac_failures"] == []
