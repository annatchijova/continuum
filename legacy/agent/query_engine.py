"""
legacy/agent/query_engine.py
=============================
Query engine for the digital legacy.

Transforms natural-language questions into structured searches over the
memory field.

Phases:
  1. Intent analysis extracts the category and question type deterministically
     (without an LLM).
  2. Memory search recalls matching entries with filters.
  3. Answer construction formats the results.
  4. Optional LLM enrichment generates a narrative answer when a backend is
     available. The LLM narrates; it does not decide.

Detected question types:
  LOCATE     "where is X?" / "find X"
  LIST       "what X exists?" / "show all X"
  TIMELINE   "when...?" / "chronology"
  STATUS     "what active accounts...?"
  PERSON     "photos/files with/of [name]"
  KNOWLEDGE  "what did I know about X?" (professional knowledge database)
  GENERAL    fallback
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField, RecallResult


# Cache compiled keyword patterns.
_KW_PATTERN_CACHE: Dict[str, re.Pattern] = {}


def _keyword_present(kw: str, text_lower: str) -> bool:
    """Return true if `kw` appears at the beginning of a word in `text_lower`.

    This avoids false positives inside words ("with" inside "contracts" would
    trigger PERSON; "id" inside "rapid" would trigger IDENTITY), while keeping
    suffix matches ("subscription" still matches "subscriptions").
    """
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


# Query intent definitions.

class QueryIntent(str, Enum):
    LOCATE    = "locate"
    LIST      = "list"
    TIMELINE  = "timeline"
    STATUS    = "status"
    PERSON    = "person"
    KNOWLEDGE = "knowledge"
    GENERAL   = "general"


# Intent signal definitions.
_INTENT_SIGNALS: List[Tuple[QueryIntent, List[str], Fraction]] = [
    (QueryIntent.LOCATE,
     ["where", "search", "path", "find", "location"],
     Fraction(2)),
    (QueryIntent.LIST,
     ["what", "which", "list", "show", "all"],
     Fraction(2)),
    (QueryIntent.TIMELINE,
     ["when", "date", "history", "timeline", "chronology"],
     Fraction(2)),
    (QueryIntent.STATUS,
     ["active", "subscription", "subscriptions", "billing", "payment"],
     Fraction(3)),
    (QueryIntent.PERSON,
     ["photo", "photos", "image", "images", "person", "with"],
     Fraction(2)),
    (QueryIntent.KNOWLEDGE,
     ["know", "knew", "knowledge", "experience", "expertise", "career"],
     Fraction(2)),
]

# Document-category signals.
_CATEGORY_SIGNALS: List[Tuple[DocCategory, List[str], Fraction]] = [
    (DocCategory.LEGAL,
     ["contract", "legal", "notarial", "lawsuit", "claim", "will", "deed"],
     Fraction(2)),
    (DocCategory.FINANCIAL,
     ["bank", "account", "money", "investment", "insurance", "credit",
      "mortgage", "loan"],
     Fraction(2)),
    (DocCategory.MEDICAL,
     ["health", "doctor", "hospital", "prescription", "diagnosis", "medical"],
     Fraction(2)),
    (DocCategory.REAL_ESTATE,
     ["house", "apartment", "property", "real", "estate", "land"],
     Fraction(2)),
    (DocCategory.SUBSCRIPTION,
     ["netflix", "spotify", "subscription", "subscriptions", "plan",
      "membership", "renewal"],
     Fraction(3)),
    (DocCategory.IDENTITY,
     ["id", "passport", "identity", "document"],
     Fraction(2)),
    (DocCategory.MEDIA,
     ["photo", "photos", "image", "images", "video", "videos"],
     Fraction(2)),
    (DocCategory.PROFESSIONAL,
     ["work", "job", "title", "diploma", "company", "client", "project", "career"],
     Fraction(2)),
]


# Query analysis and response models.

@dataclass
class QueryAnalysis:
    intent: QueryIntent
    detected_category: Optional[DocCategory]
    intent_scores: Dict[QueryIntent, Fraction]
    category_scores: Dict[DocCategory, Fraction]
    extracted_name: Optional[str]   # for PERSON queries


@dataclass
class QueryResponse:
    query: str
    intent: QueryIntent
    category_filter: Optional[DocCategory]
    results: List[RecallResult]
    answer: str                     # deterministic generated text
    llm_narration: Optional[str]    # optional LLM enrichment
    signals_count: int


# Name extraction patterns.

_NAME_PATTERNS = [
    re.compile(r"(?:with|of|photos?\s+of|images?\s+of|where\s+is)\s+([A-ZAEIOUN][a-zaeioun]+(?: [A-ZAEIOUN][a-zaeioun]+)*)", re.UNICODE),
    re.compile(r"(?:with|of|photos?\s+of|pictures?\s+of)\s+([A-ZAEIOUN][a-zaeioun]+(?: [A-ZAEIOUN][a-zaeioun]+)*)", re.UNICODE | re.IGNORECASE),
]

def _extract_name(query: str) -> Optional[str]:
    for pat in _NAME_PATTERNS:
        m = pat.search(query)
        if m:
            return m.group(1).strip()
    return None


# Query engine.

class QueryEngine:
    """
    Query engine over the memory field.

    memory : initialized MemoryField.
    llm_fn : callable(query, context)  str | None.
             if None, use deterministic answers only.
    """

    def __init__(
        self,
        memory: MemoryField,
        llm_fn=None,
    ) -> None:
        self._memory = memory
        self._llm_fn = llm_fn

    # Analyze intent and category signals.

    def analyze(self, query: str) -> QueryAnalysis:
        q_lower = query.lower()
        tokens = set(re.findall(r"[a-zaeiounua-z0-9]+", q_lower))

        intent_scores: Dict[QueryIntent, Fraction] = {i: Fraction(0) for i in QueryIntent}
        for intent, keywords, weight in _INTENT_SIGNALS:
            for kw in keywords:
                if _keyword_present(kw, q_lower):
                    intent_scores[intent] += weight

        category_scores: Dict[DocCategory, Fraction] = {c: Fraction(0) for c in DocCategory}
        for cat, keywords, weight in _CATEGORY_SIGNALS:
            for kw in keywords:
                if _keyword_present(kw, q_lower):
                    category_scores[cat] += weight

        # Select the highest-scoring intent.
        best_intent = max(intent_scores.items(), key=lambda kv: kv[1])
        intent = best_intent[0] if best_intent[1] > Fraction(0) else QueryIntent.GENERAL

        # Select the highest-scoring category.
        best_cat = max(category_scores.items(), key=lambda kv: kv[1])
        detected_cat = best_cat[0] if best_cat[1] >= Fraction(1) else None

        return QueryAnalysis(
            intent=intent,
            detected_category=detected_cat,
            intent_scores=intent_scores,
            category_scores=category_scores,
            extracted_name=_extract_name(query) if intent == QueryIntent.PERSON else None,
        )

    # Search and construct the response.

    def query(self, question: str, top_k: int = 8) -> QueryResponse:
        analysis = self.analyze(question)

        # Include the extracted name to improve recall.
        search_query = question
        if analysis.extracted_name:
            search_query = f"{question} {analysis.extracted_name}"

        results = self._memory.recall(
            search_query,
            category=analysis.detected_category,
            top_k=top_k,
        )

        answer = self._build_answer(question, analysis, results)
        llm_narration: Optional[str] = None

        if self._llm_fn and results:
            context = self._format_context_for_llm(results)
            try:
                llm_narration = self._llm_fn(question, context)
            except Exception:
                pass  # Deterministic output remains valid if the LLM fails.

        return QueryResponse(
            query=question,
            intent=analysis.intent,
            category_filter=analysis.detected_category,
            results=results,
            answer=answer,
            llm_narration=llm_narration,
            signals_count=len(results),
        )

    # Deterministic answer formatting.

    def _build_answer(
        self,
        question: str,
        analysis: QueryAnalysis,
        results: List[RecallResult],
    ) -> str:
        if not results:
            cat_hint = (
                f" in the '{analysis.detected_category.value}' category"
                if analysis.detected_category else ""
            )
            return f"No relevant information found{cat_hint} for: \"{question}\""

        lines: List[str] = []

        if analysis.intent == QueryIntent.LOCATE:
            lines.append(f"Found {len(results)} relevant item(s):\n")
            for r in results:
                if r.artifact:
                    lines.append(f"  • [{r.category.value}] {r.artifact}")
                else:
                    lines.append(f"  • [{r.category.value}] {r.content[:120]}…")

        elif analysis.intent == QueryIntent.LIST:
            cat = analysis.detected_category
            label = cat.value if cat else "documents"
            lines.append(f"Found {len(results)} {label}:\n")
            for i, r in enumerate(results, 1):
                snippet = r.content[:100].replace("\n", " ")
                lines.append(f"  {i}. {r.artifact or snippet}")

        elif analysis.intent == QueryIntent.STATUS:
            lines.append(f"Active items found ({len(results)}):\n")
            for r in results:
                snippet = r.content[:150].replace("\n", " ")
                lines.append(f"  • {snippet}")

        elif analysis.intent == QueryIntent.PERSON:
            name = analysis.extracted_name or "the indicated person"
            lines.append(f"Files related to {name} ({len(results)}):\n")
            for r in results:
                lines.append(
                    f"  • [{r.category.value}] {r.artifact or r.content[:80]}"
                )

        elif analysis.intent == QueryIntent.KNOWLEDGE:
            lines.append(f"Knowledge base — {len(results)} entr(y/ies):\n")
            for r in results:
                lines.append(f"  • {r.content[:200].replace(chr(10), ' ')}")

        else:
            lines.append(f"Results for \"{question}\" ({len(results)}):\n")
            for r in results:
                snippet = r.content[:120].replace("\n", " ")
                lines.append(f"  • [{r.category.value}] {snippet}")

        if analysis.detected_category:
            lines.append(f"\nDetected category: {analysis.detected_category.value}")

        return "\n".join(lines)

    def _format_context_for_llm(self, results: List[RecallResult]) -> str:
        parts = []
        for r in results:
            parts.append(
                f"[{r.category.value}] "
                f"{'artifact: ' + r.artifact if r.artifact else ''}\n"
                f"{r.content[:300]}"
            )
        return "\n---\n".join(parts[:5])
