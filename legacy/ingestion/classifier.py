"""
legacy/ingestion/classifier.py
================================
Clasificador determinista of documents of the legado digital.

Usa aritmetica of Fraction  without float in the path of decision.
the LLM can enriquecer the result post-classification, pero nunca
modifica the categoria asignada by este module.

result:
  ClassificationResult with:
    - category     : DocCategory ganadora
    - scores       : Fraction by categoria (reproducibles)
    - signals      : lista of senales detectadas
    - confidence   : HIGH / MEDIUM / LOW (basada in margen between 1 and 2)
    - content_hash : SHA-256 of the text analizado (trazabilidad)

the clasificador is puro: dado the same text siempre produce
the same result, without state interno ni calls externas.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from legacy.ingestion.doc_types import (
    CATEGORY_PROFILES,
    EXTENSION_HINTS,
    CategoryProfile,
    DocCategory,
)

# Implementation note.
_KW_PATTERN_CACHE: Dict[str, re.Pattern] = {}


def _keyword_present(kw: str, text_lower: str) -> bool:
    """True if `kw` aparece in `text_lower` in a limit of word initial.

    replaces the `kw in text` crudo, that producia falsos positivos a mitad of
    word ("tax" in "sinTAXis"  FINANCIAL). the limit `\\b` only va to the inicio,
    of modo that is conservan the sufijos ("cuenta" sigue matcheando "cuentas",
    "suscripcion" matchea "suscripciones") pero no the coincidencias internas.
    """
    kw = kw.lower()
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


# Implementation note.
# Implementation note.
# Implementation note.

@dataclass
class ClassificationSignal:
    category: DocCategory
    kind: str           # "keyword" | "pattern" | "extension_hint"
    matched: str        # it that disparo the senal
    weight: Fraction


@dataclass
class ClassificationResult:
    category: DocCategory
    scores: Dict[DocCategory, Fraction]
    signals: List[ClassificationSignal]
    confidence: str                     # "HIGH" | "MEDIUM" | "LOW"
    content_hash: str
    filename: Optional[str] = None

    def top_signals(self, n: int = 5) -> List[ClassificationSignal]:
        return sorted(self.signals, key=lambda s: s.weight, reverse=True)[:n]


# Implementation note.
# Implementation note.
# Implementation note.

class DocumentClassifier:
    """
    Clasificador determinista.

    Uso:
        clf = DocumentClassifier()
        result = clf.classify(text, filename="contract.pdf")
    """

    def __init__(self) -> None:
        self._profiles = CATEGORY_PROFILES
        # Implementation note.
        self._compiled: Dict[DocCategory, List[re.Pattern]] = {
            cat: prof.compiled_patterns()
            for cat, prof in self._profiles.items()
        }

    def classify(
        self,
        text: str,
        filename: Optional[str] = None,
    ) -> ClassificationResult:
        """
        classifies the text in a categoria.
        text     : content extraido (UTF-8, already decodificado).
        filename : only for hint of extension and trazabilidad.
        """
        content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        text_lower = text.lower()

        scores: Dict[DocCategory, Fraction] = {cat: Fraction(0) for cat in DocCategory}
        signals: List[ClassificationSignal] = []

        # Implementation note.
        if filename:
            ext = Path(filename).suffix.lower()
            hint_cat = EXTENSION_HINTS.get(ext)
            if hint_cat and hint_cat != DocCategory.UNKNOWN:
                w = Fraction(1, 2)
                scores[hint_cat] += w
                signals.append(ClassificationSignal(
                    category=hint_cat,
                    kind="extension_hint",
                    matched=ext,
                    weight=w,
                ))

        # Implementation note.
        for cat, prof in self._profiles.items():
            for kw in prof.keywords:
                if _keyword_present(kw, text_lower):
                    w = prof.weight
                    scores[cat] += w
                    signals.append(ClassificationSignal(
                        category=cat,
                        kind="keyword",
                        matched=kw,
                        weight=w,
                    ))

        # Implementation note.
        for cat, compiled in self._compiled.items():
            prof = self._profiles[cat]
            for pattern in compiled:
                m = pattern.search(text)
                if m:
                    w = prof.weight * Fraction(3, 2)   # patterns valen 1.5 keywords
                    scores[cat] += w
                    signals.append(ClassificationSignal(
                        category=cat,
                        kind="pattern",
                        matched=m.group(0)[:80],
                        weight=w,
                    ))

        # Implementation note.
        filtered = {c: s for c, s in scores.items() if c != DocCategory.UNKNOWN}
        ranked = sorted(filtered.items(), key=lambda kv: kv[1], reverse=True)

        if not ranked or ranked[0][1] == Fraction(0):
            winner = DocCategory.UNKNOWN
            confidence = "LOW"
        else:
            winner = ranked[0][0]
            first_score = ranked[0][1]
            second_score = ranked[1][1] if len(ranked) > 1 else Fraction(0)
            margin = first_score - second_score

            if first_score >= Fraction(6) and margin >= Fraction(3):
                confidence = "HIGH"
            elif first_score >= Fraction(2) and margin >= Fraction(1):
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

        return ClassificationResult(
            category=winner,
            scores=scores,
            signals=signals,
            confidence=confidence,
            content_hash=content_hash,
            filename=filename,
        )

    def classify_file(self, path: Path, max_bytes: int = 65_536) -> ClassificationResult:
        """
        classifies a file leyendo until max_bytes of su content.
        for binarios (imagenes, video) delega only to the extension hint.
        """
        filename = path.name
        ext = path.suffix.lower()
        binary_exts = {".jpg", ".jpeg", ".png", ".heic", ".gif",
                       ".mp4", ".mov", ".avi", ".mp3", ".flac", ".pdf"}

        if ext in binary_exts - {".pdf"}:
            return self.classify("", filename=filename)

        try:
            raw = path.read_bytes()[:max_bytes]
            # Implementation note.
            if b"\x00" in raw[:512]:
                return self.classify("", filename=filename)
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            text = ""

        return self.classify(text, filename=filename)
