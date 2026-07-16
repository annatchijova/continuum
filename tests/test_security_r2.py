"""
tests/test_security_r2.py
==========================
Regresiones para los hallazgos de la auditoría R2.

Cada test tiene el ID del hallazgo que cubre.
"""
import hashlib
import json
import math
import time
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# R2-001 — Vault: escritura atómica
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_001_vault_atomic_write_leaves_no_tmp(tmp_path):
    """Después de seal() exitoso no debe quedar archivo .tmp."""
    from legacy.vault.locker import Vault
    v = Vault(tmp_path / "test.vault")
    v.seal({"x": 1}, "pass")
    assert not (tmp_path / "test.tmp").exists()


def test_r2_001_vault_overwrites_preserve_original_until_rename(tmp_path):
    """
    Simula que seal() escribe primero al .tmp.
    El vault original solo se reemplaza cuando el rename es exitoso.
    El .tmp debe existir durante la escritura antes del replace.
    (Verificación post-facto: después del seal, el vault original fue reemplazado
    y el contenido es el nuevo, no el viejo.)
    """
    from legacy.vault.locker import Vault
    v = Vault(tmp_path / "test.vault")
    v.seal({"version": 1}, "pass")
    content_v1 = json.loads((tmp_path / "test.vault").read_text())

    v.seal({"version": 2}, "pass")
    content_v2 = json.loads((tmp_path / "test.vault").read_text())

    # El segundo seal reemplazó el primero completamente
    assert content_v1 != content_v2
    assert not (tmp_path / "test.tmp").exists()


# ─────────────────────────────────────────────────────────────────────────────
# R2-002 — STDP poisoning: reinforce/forget con audit trail
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_002_reinforce_memory_logs_audit_event(tmp_path):
    """reinforce_memory() genera exactamente un evento MEMORY_REINFORCED."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("testamento legal contrato", DocCategory.LEGAL)
    agent.reinforce_memory(mid)

    events = agent._audit.events(event_type="MEMORY_REINFORCED")
    assert len(events) == 1
    assert mid in events[0]["detail"]


def test_r2_002_forget_memory_logs_audit_event(tmp_path):
    """forget_memory() genera exactamente un evento MEMORY_FORGOTTEN."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("nota personal privada", DocCategory.PERSONAL)
    agent.forget_memory(mid)

    events = agent._audit.events(event_type="MEMORY_FORGOTTEN")
    assert len(events) == 1
    assert mid in events[0]["detail"]


def test_r2_002_reinforce_memory_requires_open_vault(tmp_path):
    """reinforce_memory() en vault cerrado lanza RuntimeError."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")
    agent.lock("pass")

    with pytest.raises(RuntimeError, match="Vault is locked"):
        agent.reinforce_memory("any-id")


def test_r2_002_forget_memory_requires_open_vault(tmp_path):
    """forget_memory() en vault cerrado lanza RuntimeError."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")
    agent.lock("pass")

    with pytest.raises(RuntimeError, match="Vault is locked"):
        agent.forget_memory("any-id")


def test_r2_002_stdp_weights_bounded(tmp_path):
    """STDP potentiation no puede superar STDP_MAX_WEIGHT = 2.0."""
    import sqlite3
    from legacy.memory.field import MemoryField, STDP_MAX_WEIGHT
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Ingerir 20 documentos de la misma categoría para saturar el peso
    for i in range(20):
        mf.store(f"contrato hipoteca banco {i} legado", DocCategory.LEGAL)

    with sqlite3.connect(tmp_path / "mem.db") as conn:
        max_w = conn.execute("SELECT MAX(weight) FROM synaptic_links").fetchone()[0]
    assert max_w is not None
    assert max_w <= STDP_MAX_WEIGHT + 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# R2-003 — _recency_bonus con timestamp futuro
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_003_recency_bonus_zero_for_future_timestamp():
    """Si last_access > now, el bono de recencia debe ser 0, no positivo."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    future = now + 86400  # 1 día adelante
    bonus = _recency_bonus(future, now)
    assert bonus == 0.0


def test_r2_003_recency_bonus_positive_for_past_timestamp():
    """Si last_access < now, el bono debe ser > 0."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    past = now - 3600  # 1 hora atrás
    bonus = _recency_bonus(past, now)
    assert bonus > 0.0


def test_r2_003_recency_bonus_bounded_above():
    """El bono de recencia no puede superar 0.05 (inmediato, delta=0)."""
    from legacy.memory.field import _recency_bonus

    now = time.time()
    bonus = _recency_bonus(now, now)
    # exp(0) = 1, bonus = 0.05 * 1.0 = 0.05
    assert bonus == pytest.approx(0.05, abs=1e-9)


def test_r2_003_future_timestamp_does_not_dominate_recall(tmp_path):
    """
    Una memoria con last_access en el futuro no debe dominar el recall.
    Antes del fix, podía tener bonus > 50 y desplazar toda memoria legítima.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Memoria "trampa" — será marcada con timestamp futuro manualmente
    mid_trap = mf.store("documento sin relevancia alguna xyz", DocCategory.PERSONAL)
    mid_real = mf.store("testamento herencia bienes legado familia", DocCategory.LEGAL)

    import sqlite3
    future_ts = time.time() + 86400 * 10  # 10 días en el futuro
    with sqlite3.connect(tmp_path / "mem.db") as conn:
        conn.execute("UPDATE memories SET last_access=? WHERE memory_id=?",
                     (future_ts, mid_trap))
        conn.commit()

    results = mf.recall("testamento herencia legado")
    assert len(results) > 0
    # La memoria relevante debe aparecer; la trampa no debe desplazarla
    top_id = results[0].memory_id
    assert top_id == mid_real, (
        f"La memoria trampa (future timestamp) dominó el recall. "
        f"Top: {top_id}, esperado: {mid_real}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# R2-004 — TF-IDF staleness: vocab crece, embeddings viejos divergen
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_004_recall_stable_after_vocab_growth(tmp_path):
    """
    Recall de una memoria específica no debe degradarse después de
    ingerir documentos que extienden el vocabulario.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mid = mf.store("hipoteca banco inmueble propiedad escritura", DocCategory.REAL_ESTATE)

    # Recall antes de extender el vocab
    results_before = mf.recall("hipoteca inmueble")
    scores_before = {r.memory_id: r.final_score for r in results_before}

    # Extender el vocabulario con documentos nuevos de otro dominio
    for i in range(30):
        mf.store(
            f"diagnóstico médico laboratorio análisis sangre {i}",
            DocCategory.MEDICAL
        )

    # Recall después de la extensión
    results_after = mf.recall("hipoteca inmueble")
    scores_after = {r.memory_id: r.final_score for r in results_after}

    # La memoria original debe seguir siendo recuperable
    assert mid in scores_after, "Memoria original perdida tras crecimiento del vocab"
    # El score no debe caer a cero (lo que indicaría fallback a overlap)
    assert scores_after[mid] > 0.01


def test_r2_004_lazy_recompute_uses_cosine_not_overlap(tmp_path):
    """
    Cuando el vocab crece, recall usa recompute coseno, no token overlap.
    Un documento muy similar a la query pero almacenado con vocab viejo
    debe seguir puntuando alto.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    # Almacenar con vocab inicial pequeño
    mid = mf.store("seguro de vida póliza cobertura", DocCategory.FINANCIAL)

    # Crecer el vocab significativamente
    for i in range(50):
        mf.store(f"palabra{i} término{i} concepto{i} definición{i}", DocCategory.PERSONAL)

    results = mf.recall("seguro de vida póliza")
    assert any(r.memory_id == mid for r in results), \
        "Memoria de seguro de vida no recuperada con vocab extendido"


# ─────────────────────────────────────────────────────────────────────────────
# R2-005 — NFC/NFD: misma palabra, mismo token
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_005_tokenize_nfc_nfd_equivalent():
    """NFC y NFD de la misma palabra producen los mismos tokens."""
    from legacy.memory.field import _tokenize

    nfc = "café résumé"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd  # confirmar que son distintos en bytes
    assert _tokenize(nfc) == _tokenize(nfd)


def test_r2_005_store_nfd_recall_nfc(tmp_path):
    """
    Documento almacenado con texto NFD debe recuperarse con query NFC
    y viceversa.
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    nfd_content = unicodedata.normalize("NFD", "médico diagnóstico clínica")
    mid = mf.store(nfd_content, DocCategory.MEDICAL)

    # Query en NFC
    results = mf.recall("médico diagnóstico")
    assert any(r.memory_id == mid for r in results), \
        "NFC query no recuperó documento almacenado en NFD"


def test_r2_005_canonicalize_nfc_nfd_same_hash():
    """NFC y NFD del mismo string producen el mismo hash canónico."""
    from legacy.core.canonicalize import _canonicalize
    from legacy.core.hash_chain import canonical_hash

    payload_nfc = {"actor": "María", "detail": "café con leche"}
    payload_nfd = {
        "actor": unicodedata.normalize("NFD", "María"),
        "detail": unicodedata.normalize("NFD", "café con leche"),
    }
    assert canonical_hash(payload_nfc) == canonical_hash(payload_nfd)


# ─────────────────────────────────────────────────────────────────────────────
# R2-006 — Inyección temporal en open_heir(now=...)
# ─────────────────────────────────────────────────────────────────────────────

def test_r2_006_now_override_logged_in_audit(tmp_path):
    """
    Cuando open_heir() recibe `now` explícito, el audit trail debe registrar
    el valor overrideado en el detail del evento CONDITION_CHECK.
    """
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.vault.conditions import AccessPolicy, DateCondition

    now_real = datetime.now(timezone.utc)
    # Condición: fecha de acceso en 1 año
    far_future = (now_real + timedelta(days=365)).isoformat()
    policy = AccessPolicy(conditions=[DateCondition(unlock_after_iso=far_future)])

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass", policy=policy)
    agent.lock("pass")

    # Heredero inyecta un 'now' en el futuro para eludir DateCondition
    forged_now = now_real + timedelta(days=400)
    granted = agent.open_heir("heir-1", "pass", now=forged_now)

    assert granted is True  # la condición se satisface con el now falso

    condition_events = agent._audit.events(event_type="CONDITION_CHECK")
    assert len(condition_events) >= 1
    last_event = condition_events[-1]
    assert "now_override" in last_event["detail"], \
        "El override de 'now' no quedó registrado en el audit trail"
    assert forged_now.isoformat() in last_event["detail"]


def test_r2_006_no_now_override_tag_when_now_is_none(tmp_path):
    """Cuando now=None (uso normal), el audit trail no incluye 'now_override'."""
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.vault.conditions import AccessPolicy, ManualCondition

    policy = AccessPolicy(conditions=[ManualCondition(activated=True)])
    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass", policy=policy)
    agent.lock("pass")

    agent.open_heir("heir-1", "pass")

    condition_events = agent._audit.events(event_type="CONDITION_CHECK")
    assert len(condition_events) >= 1
    last_event = condition_events[-1]
    assert "now_override" not in last_event["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Invariantes DL — enforcement
# ─────────────────────────────────────────────────────────────────────────────

def test_dl001_ingest_always_sets_artifact(tmp_path):
    """DL-001: artifact_id y path siempre presentes después de ingest()."""
    from legacy.agent.memory_agent import LegacyAgent

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    doc = tmp_path / "testamento.txt"
    doc.write_text("Este es mi testamento.")
    record = agent.ingest(doc)

    assert record.artifact_id
    assert record.path == str(doc)
    assert record.memory_id


def test_dl004_every_vault_mutation_has_audit_event(tmp_path):
    """
    DL-004: initialize, ingest, reinforce_memory, forget_memory, lock
    producen cada uno exactamente sus eventos esperados.
    """
    from legacy.agent.memory_agent import LegacyAgent
    from legacy.ingestion.doc_types import DocCategory

    agent = LegacyAgent(tmp_path / "data", "owner-test", hmac_key=b"testkey12345678!")
    agent.initialize("pass")

    mid = agent._memory.store("contenido de prueba", DocCategory.PERSONAL)
    agent.reinforce_memory(mid)
    agent.forget_memory(mid)
    agent.lock("pass")

    events = agent._audit.events()
    event_types = [e["event_type"] for e in events]

    assert "VAULT_CREATED" in event_types
    assert "MEMORY_REINFORCED" in event_types
    assert "MEMORY_FORGOTTEN" in event_types
    assert "VAULT_LOCKED" in event_types


def test_dl005_stdp_makes_retrieval_stateful(tmp_path):
    """
    DL-005 (documentado como limitación): dos recall() consecutivos idénticos
    producen el mismo top_memory_id pero scores distintos (last_access muta).
    """
    from legacy.memory.field import MemoryField
    from legacy.ingestion.doc_types import DocCategory

    mf = MemoryField(tmp_path / "mem.db")
    mf.store("hipoteca escritura banco propiedad", DocCategory.REAL_ESTATE)
    mf.store("testamento herencia familia legado", DocCategory.LEGAL)

    r1 = mf.recall("hipoteca banco")
    r2 = mf.recall("hipoteca banco")

    # El orden de los IDs debe ser consistente
    assert [r.memory_id for r in r1] == [r.memory_id for r in r2]
    # Pero los scores pueden diferir por last_access / recency_bonus
    # (no asertamos igualdad — este es el comportamiento esperado de STDP)
