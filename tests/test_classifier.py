"""
tests/test_classifier.py
=========================
Tests of the clasificador determinista of documents.
"""
from fractions import Fraction

import pytest

from legacy.ingestion.classifier import DocumentClassifier
from legacy.ingestion.doc_types import DocCategory


@pytest.fixture
def clf():
    return DocumentClassifier()


# Implementation note.
# Implementation note.
# Implementation note.

def test_deterministic(clf):
    text = "Este is a contract of hipoteca by the inmueble ubicado in Av. Siempre Viva."
    r1 = clf.classify(text)
    r2 = clf.classify(text)
    assert r1.category == r2.category
    assert r1.scores == r2.scores
    assert r1.content_hash == r2.content_hash


def test_scores_are_fractions(clf):
    text = "testamento poder notarial escritura contract"
    result = clf.classify(text)
    for score in result.scores.values():
        assert isinstance(score, Fraction)


# Implementation note.
# Implementation note.
# Implementation note.

def test_legal_document(clf):
    text = (
        "by medio of the presente instrumento publico, ante mi the notario, "
        "is otorga poder notarial to the senor Juan Perez for representar "
        "a the sociedad in all the actos judiciales and extrajudiciales. "
        "Este testamento is of last voluntad."
    )
    result = clf.classify(text, filename="poder_notarial.pdf")
    assert result.category == DocCategory.LEGAL
    assert result.confidence in ("HIGH", "MEDIUM")


def test_financial_document(clf):
    text = (
        "Extracto bancario - Cuenta: ES21 1234 5678 9101 1121 3141 "
        "Saldo disponible: 12,450.00 "
        "Su inversion in fondos of jubilacion ha generado dividendos. "
        "Proxima facturacion of the seguro of vida: 15/08/2026."
    )
    result = clf.classify(text, filename="extracto.pdf")
    assert result.category == DocCategory.FINANCIAL


def test_medical_document(clf):
    text = (
        "diagnosis: Hipertension arterial. "
        "Medicamento: Enalapril 10mg each 24 horas. "
        "Proximo control in hospital in 30 dias. "
        "analysis of laboratorio pendiente."
    )
    result = clf.classify(text)
    assert result.category == DocCategory.MEDICAL


def test_subscription_document(clf):
    text = (
        "Tu suscripcion a Netflix is renovara automatically. "
        "Cargo mensual: $15.99. Proxima factura: 01/08/2026. "
        "for cancelar before of the renovacion, ingresa a tu cuenta."
    )
    result = clf.classify(text)
    assert result.category == DocCategory.SUBSCRIPTION


def test_unknown_short_text(clf):
    result = clf.classify("hola mundo")
    # Implementation note.
    assert result.confidence == "LOW" or result.category == DocCategory.UNKNOWN


def test_empty_text(clf):
    result = clf.classify("")
    assert result.category == DocCategory.UNKNOWN


# Implementation note.
# Implementation note.
# Implementation note.

def test_image_classified_as_media(clf):
    result = clf.classify("", filename="foto_vacaciones.jpg")
    assert result.category == DocCategory.MEDIA


def test_excel_gets_financial_hint(clf):
    # Implementation note.
    result = clf.classify("", filename="presupuesto.xlsx")
    assert result.category == DocCategory.FINANCIAL


# Implementation note.
# Implementation note.
# Implementation note.

def test_signals_are_recorded(clf):
    text = "testamento escritura contract poder notarial"
    result = clf.classify(text)
    assert len(result.signals) > 0
    legal_signals = [s for s in result.signals if s.category == DocCategory.LEGAL]
    assert len(legal_signals) > 0


def test_content_hash_is_sha256(clf):
    import hashlib
    text = "content of prueba"
    result = clf.classify(text)
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert result.content_hash == expected


# Implementation note.
# Implementation note.
# Implementation note.

def test_no_float_in_scores(clf):
    """the path of decision no must contener floats."""
    text = "Este contract of hipoteca cubre the inmueble with folio real 12345."
    result = clf.classify(text)
    for score in result.scores.values():
        assert not isinstance(score, float), f"Float encontrado: {score!r}"
        assert isinstance(score, Fraction)
