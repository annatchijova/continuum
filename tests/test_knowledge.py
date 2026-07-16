"""
tests/test_knowledge.py
========================
Tests for the professional knowledge database.
"""
import pytest
from legacy.knowledge.extractor import (
    KnowledgeBase,
    KnowledgeDomain,
    _detect_domain,
    _extract_keywords,
    _infer_title,
    _summarize,
)


@pytest.fixture
def kb(tmp_path):
    return KnowledgeBase(tmp_path / "kb.db")


# Text helper tests.

def test_infer_title_basic():
    title = _infer_title("protocol of treatment for arterial hypertension")
    assert len(title) > 0
    assert title[0].isupper()


def test_infer_title_skips_stopwords():
    title = _infer_title("the treatment of hypertension according to the protocol")
    assert title.lower().split()[0] not in {"the", "of"}


def test_extract_keywords_returns_list():
    kws = _extract_keywords("patient diagnosis treatment protocol clinical history")
    assert isinstance(kws, list)
    assert len(kws) > 0


def test_extract_keywords_no_stopwords():
    kws = _extract_keywords("the patient of the clinic")
    for kw in kws:
        assert len(kw) >= 4


def test_summarize_short_text():
    s = _summarize("short text.")
    assert isinstance(s, str)


def test_summarize_long_text():
    text = (
        "The clinical protocol establishes the following procedure. "
        "First, the patient's history is taken. "
        "Next, a complete physical examination is performed. "
        "Finally, the necessary complementary studies are requested. "
        "The results are analyzed together with the medical team."
    )
    summary = _summarize(text, max_sentences=2)
    assert len(summary) < len(text)


def test_detect_domain_medicine():
    domain, conf = _detect_domain(
        "diagnosis of arterial hypertension in a patient with symptoms "
        "of excessive dosage. Recommended clinical treatment."
    )
    assert domain == KnowledgeDomain.MEDICINE


def test_detect_domain_engineering():
    domain, conf = _detect_domain(
        "The system architecture uses microservices. "
        "The load-balancing algorithm implements the defined protocol "
        "in the requirements specification for the central module."
    )
    assert domain == KnowledgeDomain.ENGINEERING


def test_detect_domain_law():
    domain, conf = _detect_domain(
        "The regulations establish that the contract must include all clauses "
        "defined in the current regulation. Case law indicates that "
        "the judgment in the ruling is appealable under the code."
    )
    assert domain == KnowledgeDomain.LAW


def test_detect_domain_general_fallback():
    domain, conf = _detect_domain("this is text without clear signals")
    assert domain == KnowledgeDomain.GENERAL
    assert conf == "LOW"


# Storage tests.

def test_extract_and_store_basic(kb):
    text = (
        "Protocol of treatment for patients with a diagnosis of "
        "arterial hypertension. The indicated medication is Enalapril "
        "10mg every 24 hours. Mandatory monthly clinical checkup."
    )
    entry = kb.extract_and_store(text, source_path="/notas/hta.txt")
    assert entry is not None
    assert entry.domain == KnowledgeDomain.MEDICINE
    assert entry.content_hash is not None
    assert entry.source_path == "/notas/hta.txt"


def test_extract_short_text_returns_none(kb):
    entry = kb.extract_and_store("very short text")
    assert entry is None


def test_deduplication(kb):
    text = (
        "Protocol of treatment for patients with severe arterial hypertension. "
        "The clinical diagnosis requires complete laboratory analysis "
        "and monthly follow-up with the treating physician."
    )
    e1 = kb.extract_and_store(text)
    e2 = kb.extract_and_store(text)  # duplicate text
    assert e1 is not None
    assert e2 is None   # deduplicated by hash


def test_extract_chunks(kb):
    long_text = (
        "The electrical power distribution system requires a "
        "specific preventive-maintenance protocol. The transformers "
        "must be inspected every six months under current regulations. "
        "The fault-detection algorithm implements heuristic methods based "
        "on the architecture of the electrical system. The technical specification "
        "defines the minimum requirements for each system module. "
    ) * 5  # long text
    entries = kb.extract_chunks(long_text, source_path="/doc.txt", chunk_size=400)
    assert len(entries) >= 1


# Search tests.

def test_search_finds_entry(kb):
    kb.extract_and_store(
        "The machine-learning algorithm uses neural networks "
        "to classify signals in a distributed architecture. "
        "The implementation requires specialized processing modules.",
        source_path="/papers/ml.txt",
    )
    results = kb.search("algorithm architecture system")
    assert len(results) >= 1


def test_search_empty_returns_empty(kb):
    results = kb.search("term that does not exist in no document")
    assert isinstance(results, list)


def test_search_by_domain(kb):
    kb.extract_and_store(
        "The patient has a type 2 diabetes diagnosis. "
        "The clinical treatment includes oral medication and a controlled diet. "
        "Biweekly medical checkup at the specialized clinic.",
    )
    kb.extract_and_store(
        "The cloud infrastructure system uses a microservices architecture. "
        "The load-balancing algorithm implementation complies with the technical "
        "specification for the main module of the distributed system.",
    )
    results = kb.search("patient treatment", domain=KnowledgeDomain.MEDICINE)
    for r in results:
        assert r.domain == KnowledgeDomain.MEDICINE


# Statistics tests.

def test_stats_empty(kb):
    stats = kb.stats()
    assert stats["total"] == 0


def test_stats_after_insert(kb):
    kb.extract_and_store(
        "Clinical diagnosis of a patient with symptoms of arterial hypertension. "
        "Medical treatment includes oral medication and monthly monitoring.",
    )
    stats = kb.stats()
    assert stats["total"] == 1
    assert KnowledgeDomain.MEDICINE.value in stats["by_domain"]
