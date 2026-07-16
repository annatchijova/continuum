"""
tests/test_query_engine.py
===========================
Tests for the query engine.
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
        "sales contract for the property located at 1234 Libertador Avenue. "
        "Price: USD 150,000. Deed signed before a notary.",
        category=DocCategory.LEGAL,
        artifact="/docs/contrato_casa.pdf",
        tags=["house", "property"],
    )
    mem.store(
        "Netflix subscription - premium plan. It renews automatically. "
        "Monthly charge: $25.99. Next invoice: 2026-08-15.",
        category=DocCategory.SUBSCRIPTION,
        artifact="/docs/netflix_factura.pdf",
    )
    mem.store(
        "Medical history - hypertension diagnosis. Medication: Enalapril 10mg "
        "every 24 hours. Monthly checkup at the clinic.",
        category=DocCategory.MEDICAL,
        artifact="/docs/historial_clinico.pdf",
    )
    mem.store(
        "Photo of grandmother Maria's birthday, 2019.",
        category=DocCategory.MEDIA,
        artifact="/fotos/cumple_abuela_2019.jpg",
        tags=["grandmother", "Maria", "birthday"],
    )
    return QueryEngine(mem)


# Intent detection tests.

def test_locate_intent(engine):
    a = engine.analyze("where is the contract for the house?")
    assert a.intent == QueryIntent.LOCATE


def test_list_intent(engine):
    a = engine.analyze("what subscriptions are active?")
    assert a.intent in (QueryIntent.LIST, QueryIntent.STATUS)


def test_status_intent(engine):
    a = engine.analyze("what active subscriptions do I have?")
    assert a.intent == QueryIntent.STATUS


def test_timeline_intent(engine):
    a = engine.analyze("when was the contract signed?")
    assert a.intent == QueryIntent.TIMELINE


def test_person_intent(engine):
    a = engine.analyze("photos with the grandmother")
    assert a.intent == QueryIntent.PERSON


def test_general_fallback(engine):
    a = engine.analyze("something completely ambiguous")
    assert a.intent == QueryIntent.GENERAL


def test_category_detected_legal(engine):
    a = engine.analyze("where is the will?")
    assert a.detected_category == DocCategory.LEGAL


def test_category_detected_financial(engine):
    a = engine.analyze("which bank accounts are mine?")
    assert a.detected_category == DocCategory.FINANCIAL


def test_category_detected_subscription(engine):
    a = engine.analyze("what active Netflix subscriptions do I have?")
    assert a.detected_category == DocCategory.SUBSCRIPTION


def test_intent_scores_are_fractions(engine):
    a = engine.analyze("where is the bank?")
    for score in a.intent_scores.values():
        assert isinstance(score, Fraction)
    for score in a.category_scores.values():
        assert isinstance(score, Fraction)


# Name extraction tests.

def test_extract_name_spanish():
    # English names are extracted from English queries.
    name = _extract_name("photos of Maria Garcia")
    assert name is not None
    assert "Maria" in name


def test_extract_name_none_if_no_match():
    name = _extract_name("where is the contract?")
    assert name is None


# Query execution tests.

def test_query_finds_legal_document(populated_engine):
    response = populated_engine.query("where is the contract for the house?")
    assert response.signals_count > 0
    cats = [r.category for r in response.results]
    assert DocCategory.LEGAL in cats


def test_query_finds_subscription(populated_engine):
    response = populated_engine.query("what active subscriptions do I have?")
    assert response.signals_count > 0


def test_query_finds_medical(populated_engine):
    response = populated_engine.query("medical history diagnosis")
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
    mem.store("mortgage bank contract", category=DocCategory.FINANCIAL)
    called_with = []

    def fake_llm(query, context):
        called_with.append((query, context))
        return "LLM answer"

    eng = QueryEngine(mem, llm_fn=fake_llm)
    response = eng.query("what is my mortgage?")
    assert response.llm_narration == "LLM answer"
    assert len(called_with) == 1


def test_llm_fn_failure_does_not_crash(tmp_path):
    mem = MemoryField(tmp_path / "mem4.db")
    mem.store("contract", category=DocCategory.LEGAL)

    def failing_llm(q, c):
        raise RuntimeError("LLM unavailable")

    eng = QueryEngine(mem, llm_fn=failing_llm)
    response = eng.query("contract")
    # LLM failures must not break deterministic answers.
    assert response.llm_narration is None
    assert response.signals_count > 0
