"""
tests/test_query_engine.py
===========================
Tests of the motor of consultas.
"""
from fractions import Fraction

import pytest

from legacy.agent.query_engine import QueryEngine, QueryIntent, _extract_name
from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField, MemoryState


@pytest.fixture
def memory(tmp_path):
    return MemoryField(tmp_path / "mem.db")


@pytest.fixture
def engine(memory):
    return QueryEngine(memory)


@pytest.fixture
def populated_engine(tmp_path):
    mem = MemoryField(tmp_path / "mem2.db")
    mem.store(
        "contract of compraventa of the property ubicada in Av. Libertador 1234. "
        "Precio: USD 150,000. Escritura firmada ante notario.",
        category=DocCategory.LEGAL,
        artifact="/docs/contrato_casa.pdf",
        tags=["casa", "property"],
    )
    mem.store(
        "Suscripcion a Netflix - plan premium. is renueva automatically. "
        "Cargo mensual: $25.99. Proxima factura: 15/08/2026.",
        category=DocCategory.SUBSCRIPTION,
        artifact="/docs/netflix_factura.pdf",
    )
    mem.store(
        "Historial medico - diagnosis hipertension. Medicamento: Enalapril 10mg "
        "each 24 horas. Control mensual in clinica.",
        category=DocCategory.MEDICAL,
        artifact="/docs/historial_clinico.pdf",
    )
    mem.store(
        "Foto of cumpleanos of the abuela Maria, 2019.",
        category=DocCategory.MEDIA,
        artifact="/fotos/cumple_abuela_2019.jpg",
        tags=["abuela", "Maria", "cumpleanos"],
    )
    return QueryEngine(mem)


# Implementation note.
# Implementation note.
# Implementation note.

def test_locate_intent(engine):
    a = engine.analyze("where is the contract of the casa?")
    assert a.intent == QueryIntent.LOCATE


def test_list_intent(engine):
    a = engine.analyze("what suscripciones hay activas?")
    assert a.intent in (QueryIntent.LIST, QueryIntent.STATUS)


def test_status_intent(engine):
    a = engine.analyze("what suscripciones activas tengo?")
    assert a.intent == QueryIntent.STATUS


def test_timeline_intent(engine):
    a = engine.analyze("cuando fue firmado the contract?")
    assert a.intent == QueryIntent.TIMELINE


def test_person_intent(engine):
    a = engine.analyze("fotos with the abuela")
    assert a.intent == QueryIntent.PERSON


def test_general_fallback(engine):
    a = engine.analyze("algo completamente ambiguo")
    assert a.intent == QueryIntent.GENERAL


def test_category_detected_legal(engine):
    a = engine.analyze("where is the testamento?")
    assert a.detected_category == DocCategory.LEGAL


def test_category_detected_financial(engine):
    a = engine.analyze("cuales are mis cuentas bancarias?")
    assert a.detected_category == DocCategory.FINANCIAL


def test_category_detected_subscription(engine):
    a = engine.analyze("what suscripciones of Netflix tengo activas?")
    assert a.detected_category == DocCategory.SUBSCRIPTION


def test_intent_scores_are_fractions(engine):
    a = engine.analyze("where is the banco?")
    for score in a.intent_scores.values():
        assert isinstance(score, Fraction)
    for score in a.category_scores.values():
        assert isinstance(score, Fraction)


# Implementation note.
# Implementation note.
# Implementation note.

def test_extract_name_spanish():
    # Implementation note.
    name = _extract_name("fotos of Maria Garcia")
    assert name is not None
    assert "Maria" in name


def test_extract_name_none_if_no_match():
    name = _extract_name("where is the contract?")
    assert name is None


# Implementation note.
# Implementation note.
# Implementation note.

def test_query_finds_legal_document(populated_engine):
    response = populated_engine.query("where is the contract of the casa?")
    assert response.signals_count > 0
    cats = [r.category for r in response.results]
    assert DocCategory.LEGAL in cats


def test_query_finds_subscription(populated_engine):
    response = populated_engine.query("what suscripciones activas tengo?")
    assert response.signals_count > 0


def test_query_finds_medical(populated_engine):
    response = populated_engine.query("historial medico diagnosis")
    assert response.signals_count > 0
    cats = [r.category for r in response.results]
    assert DocCategory.MEDICAL in cats


def test_query_returns_answer_string(populated_engine):
    response = populated_engine.query("where is the contract?")
    assert isinstance(response.answer, str)
    assert len(response.answer) > 0


def test_query_empty_memory_returns_no_results(engine):
    response = engine.query("where are the documents?")
    assert response.signals_count == 0
    assert "No relevant information found" in response.answer


def test_llm_fn_called_when_provided(tmp_path):
    mem = MemoryField(tmp_path / "mem3.db")
    mem.store("contract of hipoteca banco", category=DocCategory.FINANCIAL)
    called_with = []

    def fake_llm(query, context):
        called_with.append((query, context))
        return "Respuesta of the LLM"

    eng = QueryEngine(mem, llm_fn=fake_llm)
    response = eng.query("cual is mi hipoteca?")
    assert response.llm_narration == "Respuesta of the LLM"
    assert len(called_with) == 1


def test_llm_fn_failure_does_not_crash(tmp_path):
    mem = MemoryField(tmp_path / "mem4.db")
    mem.store("contract", category=DocCategory.LEGAL)

    def failing_llm(q, c):
        raise RuntimeError("LLM no disponible")

    eng = QueryEngine(mem, llm_fn=failing_llm)
    response = eng.query("contract")
    # Implementation note.
    assert response.llm_narration is None
    assert response.signals_count > 0
