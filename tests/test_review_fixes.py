"""
tests/test_review_fixes.py
==========================
Regression tests for code-review findings (2026-07-07).

Cubre cuatro correcciones:
  RV-001  pyproject.toml build-backend is valid.
  RV-002  verify_legacy.py (standalone) y legacy/core/canonicalize.py
          produces the SAME canonical hash (NFC parity).
  RV-003  heartbeat() persists the activity refresh without explicit lock().
  RV-004  keyword matching does not trigger false positives inside words.

Accented fixtures use unicodedata.normalize("NFD", ...) at runtime so they are
deterministically NFD regardless of how the editor stored literals.
"""
from __future__ import annotations

import sys
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import verify_legacy as VL
from legacy.core.canonicalize import _canonicalize as lib_canonicalize
from legacy.core.audit_trail import AuditTrail
from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.conditions import AccessPolicy, InactivityCondition
from legacy.ingestion.classifier import DocumentClassifier
from legacy.ingestion.doc_types import DocCategory


def _nfd(text: str) -> str:
    return unicodedata.normalize("NFD", text)


# ─────────────────────────────────────────────────────────────────────────────
# RV-001 — valid build-backend
# ─────────────────────────────────────────────────────────────────────────────

def test_pyproject_build_backend_is_valid():
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'build-backend = "setuptools.build_meta"' in text
    # The old value pointed to a nonexistent module.
    assert "setuptools.backends" not in text


# ─────────────────────────────────────────────────────────────────────────────
# RV-002 — canonical parity between library and standalone verifier
# ─────────────────────────────────────────────────────────────────────────────

def test_canonicalize_nfc_parity_unit():
    nfd = _nfd("café résumé")
    assert nfd != unicodedata.normalize("NFC", nfd)
    # ambas implementaciones deben normalizar a NFC igual
    assert VL._canonicalize(nfd) == lib_canonicalize(nfd)
    assert VL._canonicalize(nfd) == unicodedata.normalize("NFC", nfd)


def test_verify_legacy_accepts_valid_nfd_chain(tmp_path):
    """A legitimate chain containing an NFD filename (for example, a macOS
    filename) must not be reported as tampered by the standalone verifier."""
    nfd_artifact = _nfd("café_contrato.pdf")
    assert nfd_artifact != unicodedata.normalize("NFC", nfd_artifact)

    at = AuditTrail(db_path=tmp_path / "audit.db", hmac_key=b"")
    at.append("ARTIFACT_INGESTED", actor="owner", artifact=nfd_artifact, detail="x")
    at.append("QUERY", actor="owner", detail="segunda")

    # The library considers it valid.
    assert at.verify(hmac_key=b"").valid is True

    # The standalone verifier MUST agree (the fix previously reported tampering).
    events = VL._load_events(tmp_path / "audit.db")
    result = VL.verify(events, hmac_key=None)
    assert result.valid is True, [(e.seq, e.kind) for e in result.errors]


# ─────────────────────────────────────────────────────────────────────────────
# RV-003 — heartbeat persists without lock()
# ─────────────────────────────────────────────────────────────────────────────

def test_heartbeat_persists_activity_without_explicit_lock(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    pol = AccessPolicy([InactivityCondition(days=30, last_activity_iso=old)])
    a = LegacyAgent(tmp_path, "owner")
    a.initialize("pw", policy=pol)
    a.lock("pw")

    a.heartbeat("pw")   # no subsequent lock()

    # A new instance reads from disk.
    b = LegacyAgent(tmp_path, "owner")
    b.open_owner("pw")
    la = b._index.policy["conditions"][0]["last_activity_iso"]
    assert la != old, "heartbeat refresh was not persisted"


# ─────────────────────────────────────────────────────────────────────────────
# RV-004 — no false positives inside words
# ─────────────────────────────────────────────────────────────────────────────

def test_keyword_not_matched_midword():
    clf = DocumentClassifier()
    r = clf.classify("This document discusses language syntax.")
    # 'tax' is a substring of 'syntax' but must NOT count as FINANCIAL.
    assert r.scores[DocCategory.FINANCIAL] == 0
    assert r.category == DocCategory.UNKNOWN


def test_keyword_still_matches_plural_prefix():
    clf = DocumentClassifier()
    # The singular keyword must still match its plural prefix.
    r = clf.classify(
        "Several active subscriptions renew automatically each month "
        "across different streaming platforms."
    )
    assert r.scores[DocCategory.SUBSCRIPTION] > 0
