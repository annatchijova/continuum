"""
legacy/agent/query_engine.py
=============================
Motor of consultas over the legado digital.

Transforma questions in lenguaje natural in busquedas estructuradas
over the field of memory.

Fases:
  1. analysis of intencion  extracts categoria and tipo of question
     of forma determinista (without LLM).
  2. search in memory  recall with filtros.
  3. Construccion of respuesta  formatea the resultados.
  4. Enriquecimiento LLM (opcional)  if hay backend disponible,
     generates a respuesta narrative. the LLM narra, no decide.

Tipos of question detectados:
  LOCATE     "where is X?"  / "encontra X"
  LIST       "what X hay?"    / "mostra all the X"
  TIMELINE   "cuando...?"    / "cronologia"
  STATUS     "what cuentas activas...?"
  PERSON     "fotos/files with/of [nombre]"
  KNOWLEDGE  "what sabia over X?" (database of conocimiento profesional)
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


# Implementation note.
_KW_PATTERN_CACHE: Dict[str, re.Pattern] = {}


def _keyword_present(kw: str, text_lower: str) -> bool:
    """True if `kw` aparece in a limit of word initial of `text_lower`.

    Evita falsos positivos a mitad of word ("with" dentro of "contratos"
    disparaba the intencion PERSON; "id" dentro of "rapidez" disparaba IDENTITY),
    conservando the sufijos ("suscripcion" sigue matcheando "suscripciones").
    """
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


# Implementation note.
# Implementation note.
# Implementation note.

class QueryIntent(str, Enum):
    LOCATE    = "locate"
    LIST      = "list"
    TIMELINE  = "timeline"
    STATUS    = "status"
    PERSON    = "person"
    KNOWLEDGE = "knowledge"
    GENERAL   = "general"


# Implementation note.
_INTENT_SIGNALS: List[Tuple[QueryIntent, List[str], Fraction]] = [
    (QueryIntent.LOCATE,
     ["where", "where", "ubicar", "encontrar", "search", "path",
      "where", "find", "location", "ruta"],
     Fraction(2)),
    (QueryIntent.LIST,
     ["what", "cuales", "lista", "mostrar", "all", "all",
      "what", "which", "list", "show", "all"],
     Fraction(2)),
    (QueryIntent.TIMELINE,
     ["cuando", "when", "fecha", "cronologia", "timeline",
      "historia", "historial", "when", "date", "history", "chronology"],
     Fraction(2)),
    (QueryIntent.STATUS,
     ["activo", "activa", "activas", "activos", "vigente", "vigentes",
      "suscripcion", "suscripciones", "pago", "pagos", "cobro",
      "active", "subscription", "billing", "payment"],
     Fraction(3)),
    (QueryIntent.PERSON,
     ["foto", "fotos", "imagen", "imagenes", "person", "with",
      "photo", "photo", "image", "person", "with"],
     Fraction(2)),
    (QueryIntent.KNOWLEDGE,
     ["sabia", "sabe", "conocia", "conoce", "experiencia", "expertise",
      "trabajo", "profesion", "carrera", "know", "experience", "career"],
     Fraction(2)),
]

# Implementation note.
_CATEGORY_SIGNALS: List[Tuple[DocCategory, List[str], Fraction]] = [
    (DocCategory.LEGAL,
     ["contract", "testamento", "escritura", "poder", "legal", "notarial",
      "juicio", "demanda", "contract", "will", "deed"],
     Fraction(2)),
    (DocCategory.FINANCIAL,
     ["banco", "cuenta", "dinero", "inversion", "seguro", "credito",
      "hipoteca", "bank", "account", "money", "insurance", "loan"],
     Fraction(2)),
    (DocCategory.MEDICAL,
     ["medico", "medica", "salud", "hospital", "receta", "diagnosis",
      "health", "doctor", "prescription", "medical"],
     Fraction(2)),
    (DocCategory.REAL_ESTATE,
     ["casa", "departamento", "property", "inmueble", "terreno",
      "house", "apartment", "property", "land"],
     Fraction(2)),
    (DocCategory.SUBSCRIPTION,
     ["netflix", "spotify", "suscripcion", "suscripciones", "plan",
      "membresia", "subscription", "membership", "renewal"],
     Fraction(3)),
    (DocCategory.IDENTITY,
     ["dni", "pasaporte", "identidad", "cedula", "document",
      "passport", "id", "identity"],
     Fraction(2)),
    (DocCategory.MEDIA,
     ["foto", "fotos", "imagen", "imagenes", "video", "videos",
      "photo", "photos", "image", "video"],
     Fraction(2)),
    (DocCategory.PROFESSIONAL,
     ["trabajo", "laboral", "title", "diploma", "empresa", "cliente",
      "proyecto", "work", "job", "degree", "company", "project"],
     Fraction(2)),
]


# Implementation note.
# Implementation note.
# Implementation note.

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
    answer: str                     # text generado determinista
    llm_narration: Optional[str]    # enriquecimiento LLM (if disponible)
    signals_count: int


# Implementation note.
# Implementation note.
# Implementation note.

_NAME_PATTERNS = [
    re.compile(r"(?:with|of|fotos?\s+of|imagenes?\s+of|where\s+is)\s+([A-ZAEIOUN][a-zaeioun]+(?: [A-ZAEIOUN][a-zaeioun]+)*)", re.UNICODE),
    re.compile(r"(?:with|of|photos?\s+of|pictures?\s+of)\s+([A-ZAEIOUN][a-zaeioun]+(?: [A-ZAEIOUN][a-zaeioun]+)*)", re.UNICODE | re.IGNORECASE),
]

def _extract_name(query: str) -> Optional[str]:
    for pat in _NAME_PATTERNS:
        m = pat.search(query)
        if m:
            return m.group(1).strip()
    return None


# Implementation note.
# Implementation note.
# Implementation note.

class QueryEngine:
    """
    Motor of consultas over the field of memory.

    memory : MemoryField already inicializado.
    llm_fn : callable(query, context)  str | None.
             if is None, only respuesta determinista.
    """

    def __init__(
        self,
        memory: MemoryField,
        llm_fn=None,
    ) -> None:
        self._memory = memory
        self._llm_fn = llm_fn

    # Implementation note.
    # Implementation note.
    # Implementation note.

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

        # Implementation note.
        best_intent = max(intent_scores.items(), key=lambda kv: kv[1])
        intent = best_intent[0] if best_intent[1] > Fraction(0) else QueryIntent.GENERAL

        # Implementation note.
        best_cat = max(category_scores.items(), key=lambda kv: kv[1])
        detected_cat = best_cat[0] if best_cat[1] >= Fraction(1) else None

        return QueryAnalysis(
            intent=intent,
            detected_category=detected_cat,
            intent_scores=intent_scores,
            category_scores=category_scores,
            extracted_name=_extract_name(query) if intent == QueryIntent.PERSON else None,
        )

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def query(self, question: str, top_k: int = 8) -> QueryResponse:
        analysis = self.analyze(question)

        # Implementation note.
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
                pass  # LLM falla  respuesta determinista sigue siendo valid

        return QueryResponse(
            query=question,
            intent=analysis.intent,
            category_filter=analysis.detected_category,
            results=results,
            answer=answer,
            llm_narration=llm_narration,
            signals_count=len(results),
        )

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _build_answer(
        self,
        question: str,
        analysis: QueryAnalysis,
        results: List[RecallResult],
    ) -> str:
        if not results:
            cat_hint = (
                f" en la categoría '{analysis.detected_category.value}'"
                if analysis.detected_category else ""
            )
            return f"No relevant information found{cat_hint} for: \"{question}\""

        lines: List[str] = []

        if analysis.intent == QueryIntent.LOCATE:
            lines.append(f"Encontré {len(results)} item(s) relevante(s):\n")
            for r in results:
                if r.artifact:
                    lines.append(f"  • [{r.category.value}] {r.artifact}")
                else:
                    lines.append(f"  • [{r.category.value}] {r.content[:120]}…")

        elif analysis.intent == QueryIntent.LIST:
            cat = analysis.detected_category
            label = cat.value if cat else "documents"
            lines.append(f"{len(results)} {label} encontrado(s):\n")
            for i, r in enumerate(results, 1):
                snippet = r.content[:100].replace("\n", " ")
                lines.append(f"  {i}. {r.artifact or snippet}")

        elif analysis.intent == QueryIntent.STATUS:
            lines.append(f"Items activos / vigentes encontrados ({len(results)}):\n")
            for r in results:
                snippet = r.content[:150].replace("\n", " ")
                lines.append(f"  • {snippet}")

        elif analysis.intent == QueryIntent.PERSON:
            name = analysis.extracted_name or "the person indicada"
            lines.append(f"Archivos relacionados con {name} ({len(results)}):\n")
            for r in results:
                lines.append(
                    f"  • [{r.category.value}] {r.artifact or r.content[:80]}"
                )

        elif analysis.intent == QueryIntent.KNOWLEDGE:
            lines.append(f"Base de conocimiento — {len(results)} entrada(s):\n")
            for r in results:
                lines.append(f"  • {r.content[:200].replace(chr(10), ' ')}")

        else:
            lines.append(f"Resultados para \"{question}\" ({len(results)}):\n")
            for r in results:
                snippet = r.content[:120].replace("\n", " ")
                lines.append(f"  • [{r.category.value}] {snippet}")

        if analysis.detected_category:
            lines.append(f"\nCategoría detectada: {analysis.detected_category.value}")

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
