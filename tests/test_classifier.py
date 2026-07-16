"""
tests/test_classifier.py
=========================
Tests for the deterministic document classifier.
"""
from fractions import Fraction

import pytest

from legacy.ingestion.classifier import DocumentClassifier
from legacy.ingestion.doc_types import DocCategory


@pytest.fixture
def clf():
    return DocumentClassifier()


# Determinism and score types.

def test_deterministic(clf):
    text = "This is a mortgage contract for the property located at Evergreen Avenue."
    r1 = clf.classify(text)
    r2 = clf.classify(text)
    assert r1.category == r2.category
    assert r1.scores == r2.scores
    assert r1.content_hash == r2.content_hash


def test_scores_are_fractions(clf):
    text = "will power of attorney notarial deed contract"
    result = clf.classify(text)
    for score in result.scores.values():
        assert isinstance(score, Fraction)


# Category classification.

def test_legal_document(clf):
    text = (
        "By means of this public instrument, before me the notary, "
        "power of attorney is granted to Mr. Juan Perez to represent "
        "the company in all judicial and extrajudicial acts. "
        "This will expresses the last wishes."
    )
    result = clf.classify(text, filename="power_of_attorney.pdf")
    assert result.category == DocCategory.LEGAL
    assert result.confidence in ("HIGH", "MEDIUM")


def test_financial_document(clf):
    text = (
        "Bank statement - Account: ES21 1234 5678 9101 1121 3141 "
        "Available balance: 12,450.00 "
        "The investment in retirement funds generated dividends. "
        "Next billing date for life insurance: 08/15/2026."
    )
    result = clf.classify(text, filename="extracto.pdf")
    assert result.category == DocCategory.FINANCIAL


def test_medical_document(clf):
    text = (
        "Diagnosis: Arterial hypertension. "
        "Medication: Enalapril 10mg every 24 hours. "
        "Next hospital checkup in 30 days. "
        "Pending laboratory analysis."
    )
    result = clf.classify(text)
    assert result.category == DocCategory.MEDICAL


def test_subscription_document(clf):
    text = (
        "Your Netflix subscription will renew automatically. "
        "Monthly charge: $15.99. Next bill: 08/01/2026. "
        "To cancel before renewal, log in to your account."
    )
    result = clf.classify(text)
    assert result.category == DocCategory.SUBSCRIPTION


def test_unknown_short_text(clf):
    result = clf.classify("hello world")
    # An uninformative document should remain low-confidence.
    assert result.confidence == "LOW" or result.category == DocCategory.UNKNOWN


def test_empty_text(clf):
    result = clf.classify("")
    assert result.category == DocCategory.UNKNOWN


# Empty and extension-based classification.

def test_image_classified_as_media(clf):
    result = clf.classify("", filename="vacation_photo.jpg")
    assert result.category == DocCategory.MEDIA


def test_excel_gets_financial_hint(clf):
    # Spreadsheet files provide a financial extension hint.
    result = clf.classify("", filename="budget.xlsx")
    assert result.category == DocCategory.FINANCIAL


# Signal and hash behavior.

def test_signals_are_recorded(clf):
    text = "will deed contract power of attorney notarial"
    result = clf.classify(text)
    assert len(result.signals) > 0
    legal_signals = [s for s in result.signals if s.category == DocCategory.LEGAL]
    assert len(legal_signals) > 0


def test_content_hash_is_sha256(clf):
    import hashlib
    text = "sample content"
    result = clf.classify(text)
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert result.content_hash == expected


# Score precision.

def test_no_float_in_scores(clf):
    """The decision path must not contain floats."""
    text = "This mortgage contract covers the property with real folio 12345."
    result = clf.classify(text)
    for score in result.scores.values():
        assert not isinstance(score, float), f"Float found: {score!r}"
        assert isinstance(score, Fraction)
