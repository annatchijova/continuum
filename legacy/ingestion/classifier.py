"""
legacy/ingestion/classifier.py
================================
Deterministic classifier for digital-legacy documents.

Uses Fraction arithmetic with no floats in the decision path.
An LLM may enrich the result after classification, but never modifies
the category assigned by this module.

Result:
  ClassificationResult with:
    - category     : winning DocCategory
    - scores       : Fraction per category (reproducible)
    - signals      : detected signals
    - confidence   : HIGH / MEDIUM / LOW (based on the margin between first and second)
    - content_hash : SHA-256 of the analyzed text (traceability)

The classifier is pure: given the same text it always produces the same
result, with no internal state or external calls.
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
    """Return True if `kw` appears at an initial word boundary in `text_lower`.

    This replaces the raw `kw in text`, which produced false positives inside
    words ("tax" in "sinTAXis" → FINANCIAL). The `\\b` boundary is used only
    at the start, preserving suffix matches ("account" matches "accounts")
    while rejecting internal matches.
    """
    kw = kw.lower()
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


# Classification data structures.

@dataclass
class ClassificationSignal:
    category: DocCategory
    kind: str           # "keyword" | "pattern" | "extension_hint"
    matched: str        # text that triggered the signal
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


# Classifier implementation.

class DocumentClassifier:
    """
    Deterministic classifier.

    Uso:
        clf = DocumentClassifier()
        result = clf.classify(text, filename="contract.pdf")
    """

    def __init__(self) -> None:
        self._profiles = CATEGORY_PROFILES
        # Compile patterns once per classifier instance.
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
        Classify text into a category.
        text     : extracted content (UTF-8, already decoded).
        filename : used only for an extension hint and traceability.
        """
        content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        text_lower = text.lower()

        scores: Dict[DocCategory, Fraction] = {cat: Fraction(0) for cat in DocCategory}
        signals: List[ClassificationSignal] = []

        # Extension hints provide a weak signal.
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

        # Keyword signals.
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

        # Structural-pattern signals.
        for cat, compiled in self._compiled.items():
            prof = self._profiles[cat]
            for pattern in compiled:
                m = pattern.search(text)
                if m:
                    w = prof.weight * Fraction(3, 2)   # patterns are worth 1.5 keywords
                    scores[cat] += w
                    signals.append(ClassificationSignal(
                        category=cat,
                        kind="pattern",
                        matched=m.group(0)[:80],
                        weight=w,
                    ))

        # Rank non-UNKNOWN categories.
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
        Classify a file by reading up to max_bytes of its content.
        For binary formats (images, video), use only the extension hint.
        """
        filename = path.name
        ext = path.suffix.lower()
        binary_exts = {".jpg", ".jpeg", ".png", ".heic", ".gif",
                       ".mp4", ".mov", ".avi", ".mp3", ".flac", ".pdf"}

        if ext in binary_exts - {".pdf"}:
            return self.classify("", filename=filename)

        try:
            raw = path.read_bytes()[:max_bytes]
            # Detect binary content using null bytes in the first 512 bytes.
            if b"\x00" in raw[:512]:
                return self.classify("", filename=filename)
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            text = ""

        return self.classify(text, filename=filename)
