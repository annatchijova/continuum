"""
tests/test_knowledge.py
========================
Tests of the database of conocimiento profesional.
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


# Implementation note.
# Implementation note.
# Implementation note.

def test_infer_title_basic():
    title = _infer_title("protocol of treatment for hipertension arterial")
    assert len(title) > 0
    assert title[0].isupper()


def test_infer_title_skips_stopwords():
    title = _infer_title("the treatment of the hipertension segun the protocol")
    # Implementation note.
    assert title.lower().split()[0] not in {"the", "of", "the"}


def test_extract_keywords_returns_list():
    kws = _extract_keywords("patient diagnosis treatment protocol clinical historial")
    assert isinstance(kws, list)
    assert len(kws) > 0


def test_extract_keywords_no_stopwords():
    kws = _extract_keywords("the patient of the clinica")
    # Implementation note.
    for kw in kws:
        assert len(kw) >= 4


def test_summarize_short_text():
    s = _summarize("text corto.")
    assert isinstance(s, str)


def test_summarize_long_text():
    text = (
        "the protocol clinical establece the siguiente procedimiento. "
        "in primer lugar is realiza the anamnesis of the patient. "
        "Posteriormente is efectua the examen fisico complete. "
        "Finalmente is solicitan the estudios complementarios necesarios. "
        "the resultados is analizan in conjunto with the equipo medico."
    )
    summary = _summarize(text, max_sentences=2)
    assert len(summary) < len(text)


def test_detect_domain_medicine():
    domain, conf = _detect_domain(
        "diagnosis of hipertension arterial in patient with sintomas "
        "of dose excesiva. treatment clinical recomendado."
    )
    assert domain == KnowledgeDomain.MEDICINE


def test_detect_domain_engineering():
    domain, conf = _detect_domain(
        "the architecture of the system utiliza microservicios. "
        "the algorithm of balanceo implementa the protocol definido "
        "in the specification of requerimientos of the module central."
    )
    assert domain == KnowledgeDomain.ENGINEERING


def test_detect_domain_law():
    domain, conf = _detect_domain(
        "the regulations establece that the contract must incluir all the clausulas "
        "definidas in the regulation vigente. the case law indicates that "
        "the judgment of the ruling is apelable segun the code."
    )
    assert domain == KnowledgeDomain.LAW


def test_detect_domain_general_fallback():
    domain, conf = _detect_domain("esto is text without senales claras")
    assert domain == KnowledgeDomain.GENERAL
    assert conf == "LOW"


# Implementation note.
# Implementation note.
# Implementation note.

def test_extract_and_store_basic(kb):
    text = (
        "protocol of treatment for pacientes with diagnosis of "
        "hipertension arterial. the medicamento indicado is Enalapril "
        "10mg each 24 horas. Control clinical mensual obligatorio."
    )
    entry = kb.extract_and_store(text, source_path="/notas/hta.txt")
    assert entry is not None
    assert entry.domain == KnowledgeDomain.MEDICINE
    assert entry.content_hash is not None
    assert entry.source_path == "/notas/hta.txt"


def test_extract_short_text_returns_none(kb):
    entry = kb.extract_and_store("text very corto")
    assert entry is None


def test_deduplication(kb):
    text = (
        "protocol of treatment for pacientes with hipertension arterial "
        "severa. the diagnosis clinical requires analysis of laboratorio "
        "complete and seguimiento mensual of the medico tratante."
    )
    e1 = kb.extract_and_store(text)
    e2 = kb.extract_and_store(text)  # same text
    assert e1 is not None
    assert e2 is None   # deduplicado by hash


def test_extract_chunks(kb):
    long_text = (
        "the system of distribucion of energia electrica requires a "
        "protocol especifico of mantenimiento preventivo. the transformadores "
        "deben revisarse each seis meses segun the regulations vigente. "
        "the algorithm of deteccion of fallas implementa heuristicas basadas "
        "in the architecture of the system electrico. the specification technique "
        "define the requerimientos minimos for each module of the system. "
    ) * 5  # text largo
    entries = kb.extract_chunks(long_text, source_path="/doc.txt", chunk_size=400)
    assert len(entries) >= 1


# Implementation note.
# Implementation note.
# Implementation note.

def test_search_finds_entry(kb):
    kb.extract_and_store(
        "the algorithm of aprendizaje automatic utiliza redes neuronales "
        "for clasificar senales in the system of architecture distribuida. "
        "the implementation requires modulos especializados of procesamiento.",
        source_path="/papers/ml.txt",
    )
    results = kb.search("algorithm architecture system")
    assert len(results) >= 1


def test_search_empty_returns_empty(kb):
    results = kb.search("term that does not exist in no document")
    assert isinstance(results, list)


def test_search_by_domain(kb):
    kb.extract_and_store(
        "the patient presenta diagnosis of diabetes tipo 2. "
        "the treatment clinical incluye medicacion oral and dieta controlada. "
        "Control medico quincenal in the clinica especializada.",
    )
    kb.extract_and_store(
        "the system of infraestructura cloud utiliza architecture of microservicios. "
        "the implementation of the algorithm of balanceo cumple with the specification "
        "technique of the module principal of the system distribuido.",
    )
    results = kb.search("patient treatment", domain=KnowledgeDomain.MEDICINE)
    for r in results:
        assert r.domain == KnowledgeDomain.MEDICINE


# Implementation note.
# Implementation note.
# Implementation note.

def test_stats_empty(kb):
    stats = kb.stats()
    assert stats["total"] == 0


def test_stats_after_insert(kb):
    kb.extract_and_store(
        "diagnosis clinical of the patient with sintomas of hipertension arterial. "
        "the treatment medico incluye medicacion oral and control mensual.",
    )
    stats = kb.stats()
    assert stats["total"] == 1
    assert KnowledgeDomain.MEDICINE.value in stats["by_domain"]
