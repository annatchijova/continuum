"""
tests/test_review_fixes.py
==========================
Regresión para los hallazgos del code review (2026-07-07).

Cubre cuatro correcciones:
  RV-001  build-backend de pyproject.toml es válido.
  RV-002  verify_legacy.py (standalone) y legacy/core/canonicalize.py
          producen el MISMO hash canónico (paridad NFC).
  RV-003  heartbeat() persiste el refresco de actividad sin lock() explícito.
  RV-004  el matching de keywords no dispara falsos positivos a mitad de palabra.

Los fixtures acentuados se construyen con unicodedata.normalize("NFD", ...) en
runtime para que sean NFD de forma determinista, independiente de cómo el editor
haya guardado los literales.
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
# RV-001 — build-backend válido
# ─────────────────────────────────────────────────────────────────────────────

def test_pyproject_build_backend_is_valid():
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'build-backend = "setuptools.build_meta"' in text
    # el valor viejo apuntaba a un módulo inexistente
    assert "setuptools.backends" not in text


# ─────────────────────────────────────────────────────────────────────────────
# RV-002 — paridad canónica librería vs verificador standalone
# ─────────────────────────────────────────────────────────────────────────────

def test_canonicalize_nfc_parity_unit():
    nfd = _nfd("café résumé")
    assert nfd != unicodedata.normalize("NFC", nfd)
    # ambas implementaciones deben normalizar a NFC igual
    assert VL._canonicalize(nfd) == lib_canonicalize(nfd)
    assert VL._canonicalize(nfd) == unicodedata.normalize("NFC", nfd)


def test_verify_legacy_accepts_valid_nfd_chain(tmp_path):
    """Una cadena legítima con una cadena NFD (p. ej. nombre de archivo de
    macOS) no debe ser reportada como manipulada por el verificador standalone."""
    nfd_artifact = _nfd("café_contrato.pdf")
    assert nfd_artifact != unicodedata.normalize("NFC", nfd_artifact)

    at = AuditTrail(db_path=tmp_path / "audit.db", hmac_key=b"")
    at.append("ARTIFACT_INGESTED", actor="owner", artifact=nfd_artifact, detail="x")
    at.append("QUERY", actor="owner", detail="segunda")

    # la librería la considera válida
    assert at.verify(hmac_key=b"").valid is True

    # el standalone DEBE coincidir (antes del fix daba tampered_content)
    events = VL._load_events(tmp_path / "audit.db")
    result = VL.verify(events, hmac_key=None)
    assert result.valid is True, [(e.seq, e.kind) for e in result.errors]


# ─────────────────────────────────────────────────────────────────────────────
# RV-003 — heartbeat persiste sin lock()
# ─────────────────────────────────────────────────────────────────────────────

def test_heartbeat_persists_activity_without_explicit_lock(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    pol = AccessPolicy([InactivityCondition(days=30, last_activity_iso=old)])
    a = LegacyAgent(tmp_path, "owner")
    a.initialize("pw", policy=pol)
    a.lock("pw")

    a.heartbeat("pw")   # sin lock() posterior

    # instancia nueva → lee del disco
    b = LegacyAgent(tmp_path, "owner")
    b.open_owner("pw")
    la = b._index.policy["conditions"][0]["last_activity_iso"]
    assert la != old, "el refresco de heartbeat no se persistió"


# ─────────────────────────────────────────────────────────────────────────────
# RV-004 — sin falsos positivos de keyword a mitad de palabra
# ─────────────────────────────────────────────────────────────────────────────

def test_keyword_not_matched_midword():
    clf = DocumentClassifier()
    r = clf.classify("Este documento trata sobre la sintaxis del lenguaje.")
    # 'tax' es substring de 'sintaxis' pero NO debe contar como FINANCIAL
    assert r.scores[DocCategory.FINANCIAL] == 0
    assert r.category == DocCategory.UNKNOWN


def test_keyword_still_matches_plural_prefix():
    clf = DocumentClassifier()
    # 'suscripción' debe seguir matcheando 'suscripciones' (sufijo permitido)
    r = clf.classify(
        "Tenés varias suscripciones activas con renovación automática mensual "
        "en distintas plataformas de streaming."
    )
    assert r.scores[DocCategory.SUBSCRIPTION] > 0
