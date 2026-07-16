"""
legacy/knowledge/extractor.py
==============================
Extractor of conocimiento profesional.

Convierte documents, notas and escritos of a person in a database
of conocimiento consultable: no only files inertes, sino entradas
estructuradas with tema, contexto and content.

Casos of uso:
  - 20 years of notas medical  database consultable by especialidad
  - Proyectos of ingenieria  decisiones and razonamiento preservado
  - Clases and materiales docentes  conocimiento pedagogico

Estructura of a entry of conocimiento:
  KnowledgeEntry:
    entry_id    : UUID
    title       : title inferido (first N words significativas)
    domain      : area subject (MEDICINE / ENGINEERING / LAW / EDUCATION /
                  FINANCE / GENERAL)
    content     : text complete
    summary     : summary of 1-3 sentences (determinista, without LLM)
    keywords    : terms key extraidos
    source_path : artifact origen
    confidence  : HIGH / MEDIUM / LOW (over the extraction)
    created_at  : ISO 8601

the extractor is puro: same input  same output.
No llama LLMs  the summary is generates with heuristica determinista.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from legacy.core.dbcrypto import (
    FieldCipher,
    FieldCryptoError,
    escape_plaintext,
    is_encrypted,
    unescape_plaintext,
)


# Implementation note.
# Implementation note.
# Implementation note.

class KnowledgeDomain(str, Enum):
    MEDICINE    = "medicine"
    ENGINEERING = "engineering"
    LAW         = "law"
    EDUCATION   = "education"
    FINANCE     = "finance"
    ARTS        = "arts"
    SCIENCE     = "science"
    GENERAL     = "general"


_DOMAIN_SIGNALS: List[tuple[KnowledgeDomain, List[str], Fraction]] = [
    (KnowledgeDomain.MEDICINE,
     ["patient", "diagnosis", "treatment", "clinical", "surgical",
      "pathology", "symptom", "dose", "patient", "diagnosis", "clinical",
      "treatment", "symptom", "therapy", "protocol"],
     Fraction(2)),
    (KnowledgeDomain.ENGINEERING,
     ["system", "architecture", "design", "implementation", "algorithm",
      "protocol", "specification", "requirement", "module",
      "system", "architecture", "design", "algorithm", "specification",
      "requirement", "module", "deployment", "infrastructure"],
     Fraction(2)),
    (KnowledgeDomain.LAW,
     ["case law", "regulations", "regulation", "contract", "clause",
      "judgment", "ruling", "law", "code", "statute", "regulation",
      "contract", "clause", "judgment", "legal", "compliance"],
     Fraction(2)),
    (KnowledgeDomain.EDUCATION,
     ["class", "lesson", "student", "student", "curriculum", "evaluation",
      "pedagog", "aprendizaje", "class", "lesson", "student", "curriculum",
      "assessment", "learning", "teaching", "syllabus"],
     Fraction(2)),
    (KnowledgeDomain.FINANCE,
     ["balance", "flujo of caja", "capital", "rendimiento", "cartera",
      "riesgo", "volatilidad", "cashflow", "portfolio", "yield",
      "risk", "return", "valuation", "equity", "dividend"],
     Fraction(2)),
    (KnowledgeDomain.ARTS,
     ["composition", "narrative", "style", "technique", "work", "creation",
      "composition", "narrative", "style", "technique", "artwork"],
     Fraction(2)),
    (KnowledgeDomain.SCIENCE,
     ["hypothesis", "experiment", "methodology", "result", "data",
      "analysis", "sample", "hypothesis", "experiment", "methodology",
      "result", "data", "analysis", "sample", "variable"],
     Fraction(2)),
]


# Implementation note.
# Implementation note.
# Implementation note.

@dataclass
class KnowledgeEntry:
    entry_id: str
    title: str
    domain: KnowledgeDomain
    content: str
    summary: str
    keywords: List[str]
    source_path: Optional[str]
    confidence: str
    created_at: str
    content_hash: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["domain"] = self.domain.value
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "KnowledgeEntry":
        d = dict(d)
        d["domain"] = KnowledgeDomain(d["domain"])
        return KnowledgeEntry(**d)


# Implementation note.
# Implementation note.
# Implementation note.

_STOP_WORDS = frozenset({
    "of", "the", "the", "the", "the", "a", "a", "and", "o", "in", "with",
    "by", "for", "that", "of the", "to the", "is", "is", "su", "sus", "a",
    "the", "of", "and", "to", "in", "is", "it", "for", "on", "at",
})

_SENTENCE_END = re.compile(r"[.!?]\s+")


def _infer_title(text: str, max_words: int = 8) -> str:
    """first N words significativas of the text as title."""
    first_line = text.strip().split("\n")[0]
    words = re.findall(r"[A-ZAEIOUNa-zaeiounua-z0-9]+", first_line)
    significant = [w for w in words if w.lower() not in _STOP_WORDS][:max_words]
    return " ".join(significant).capitalize() or "entry without title"


def _extract_keywords(text: str, top_n: int = 15) -> List[str]:
    """extracts keywords by frecuencia, excluyendo stopwords."""
    from collections import Counter
    tokens = re.findall(r"[a-zaeiounua-z]{4,}", text.lower())
    filtered = [t for t in tokens if t not in _STOP_WORDS]
    counter = Counter(filtered)
    return [w for w, _ in counter.most_common(top_n)]


def _summarize(text: str, max_sentences: int = 3) -> str:
    """
    summary heuristico: first N sentences with longitud minima.
    without LLM  determinista.
    """
    sentences = _SENTENCE_END.split(text.strip())
    meaningful = [s.strip() for s in sentences if len(s.strip()) > 30]
    selected = meaningful[:max_sentences]
    return " ".join(selected)[:500] or text[:200]


_KW_PATTERN_CACHE: Dict[str, re.Pattern] = {}


def _keyword_present(kw: str, text_lower: str) -> bool:
    """True if `kw` aparece in a limit of word initial of `text_lower`.

    Evita falsos positivos a mitad of word (p. ej. "data" dentro of another
    word) conservando the sufijos by prefijo.
    """
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


def _detect_domain(text: str) -> tuple[KnowledgeDomain, str]:
    """returns (domain, confidence)."""
    text_lower = text.lower()
    scores: Dict[KnowledgeDomain, Fraction] = {d: Fraction(0) for d in KnowledgeDomain}
    for domain, keywords, weight in _DOMAIN_SIGNALS:
        for kw in keywords:
            if _keyword_present(kw, text_lower):
                scores[domain] += weight

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best_score = ranked[0][1]
    second_score = ranked[1][1] if len(ranked) > 1 else Fraction(0)

    if best_score == Fraction(0):
        return KnowledgeDomain.GENERAL, "LOW"
    margin = best_score - second_score
    if best_score >= Fraction(6) and margin >= Fraction(3):
        return ranked[0][0], "HIGH"
    if best_score >= Fraction(2):
        return ranked[0][0], "MEDIUM"
    return ranked[0][0], "LOW"


# Implementation note.
# Implementation note.
# Implementation note.

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    entry_id     TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    domain       TEXT NOT NULL,
    content      TEXT NOT NULL,
    summary      TEXT NOT NULL,
    keywords_json TEXT NOT NULL,
    source_path  TEXT,
    confidence   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    content_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kn_domain ON knowledge(domain);
"""
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.
# Implementation note.


class KnowledgeBase:
    """
    database of conocimiento profesional persistida in SQLite.

    db_path : ruta to the file SQLite.
    db_key  : 32 bytes  encrypts at rest the fields sensibles (KL-001b).
              None  database in plaintext (compatibilidad).

    with db_key, the search is a scan in memory (decrypts and puntua); without
    the key the database is opaca and search() returns empty.
    """

    # Implementation note.
    # Implementation note.
    # Implementation note.
    _ENCRYPTED_COLUMNS = ("title", "content", "summary", "keywords_json", "source_path")

    def __init__(self, db_path: Path, db_key: Optional[bytes] = None) -> None:
        self._db_path = db_path
        self._cipher: Optional[FieldCipher] = FieldCipher(db_key) if db_key else None
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def set_db_key(self, db_key: Optional[bytes]) -> None:
        """Inyecta (o quita) the key of encrypted tras open the vault."""
        self._cipher = FieldCipher(db_key) if db_key else None

    # Implementation note.

    @staticmethod
    def _aad(entry_id: str, column: str) -> str:
        return f"{entry_id}:{column}"

    def _enc(self, entry_id: str, column: str, value: str) -> str:
        if self._cipher:
            return self._cipher.encrypt_field(value, self._aad(entry_id, column))
        return escape_plaintext(value)

    def _dec(self, entry_id: str, column: str, value):
        """Forma almacenada  valor logico; None if unreadable in esta session."""
        if value is None:
            return None
        if is_encrypted(value):
            if not self._cipher:
                return None
            try:
                return self._cipher.decrypt_field(value, self._aad(entry_id, column))
            except FieldCryptoError:
                return None
        return unescape_plaintext(value)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def extract_and_store(
        self,
        text: str,
        source_path: Optional[str] = None,
        *,
        min_length: int = 100,
    ) -> Optional[KnowledgeEntry]:
        """
        extracts conocimiento of a text and it almacena.
        returns None if the text is demasiado corto o trivial.
        """
        text = text.strip()
        if len(text) < min_length:
            return None

        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # Implementation note.
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT entry_id FROM knowledge WHERE content_hash=?",
                (content_hash,),
            ).fetchone()
        if existing:
            return None

        domain, confidence = _detect_domain(text)
        title = _infer_title(text)
        summary = _summarize(text)
        keywords = _extract_keywords(text)

        entry = KnowledgeEntry(
            entry_id=str(uuid.uuid4()),
            title=title,
            domain=domain,
            content=text,
            summary=summary,
            keywords=keywords,
            source_path=source_path,
            confidence=confidence,
            created_at=datetime.now(timezone.utc).isoformat(),
            content_hash=content_hash,
        )

        eid = entry.entry_id
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO knowledge
                   (entry_id, title, domain, content, summary, keywords_json,
                    source_path, confidence, created_at, content_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid,
                    self._enc(eid, "title", entry.title),
                    entry.domain.value,
                    self._enc(eid, "content", entry.content),
                    self._enc(eid, "summary", entry.summary),
                    self._enc(eid, "keywords_json", json.dumps(entry.keywords)),
                    self._enc(eid, "source_path", entry.source_path or ""),
                    entry.confidence, entry.created_at, entry.content_hash,
                ),
            )

        return entry

    def extract_chunks(
        self,
        text: str,
        source_path: Optional[str] = None,
        chunk_size: int = 1000,
        overlap: int = 100,
    ) -> List[KnowledgeEntry]:
        """
        Divide text largo in chunks with overlap and extracts each uno.
        Util for documents extensos.
        """
        entries: List[KnowledgeEntry] = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]
            # Implementation note.
            if end < len(text):
                last_period = chunk.rfind(".")
                if last_period > chunk_size // 2:
                    chunk = chunk[: last_period + 1]
                    end = start + last_period + 1
            entry = self.extract_and_store(chunk, source_path=source_path)
            if entry:
                entries.append(entry)
            # Implementation note.
            # Implementation note.
            # Implementation note.
            start = max(end - overlap, start + 1)
        return entries

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def search(
        self,
        query: str,
        *,
        domain: Optional[KnowledgeDomain] = None,
        top_k: int = 10,
    ) -> List[KnowledgeEntry]:
        """
        search by scan in memory (KL-001b): decrypts each row and puntua
        by solape of terms over title + content + keywords. the filtro
        by domain is aplica in SQL (domain remains in plaintext). the rows that no
        descifran in esta session (without a key) no participan  search empty.
        """
        terms = [t for t in query.lower().split() if t][:8]
        with self._connect() as conn:
            if domain:
                rows = conn.execute(
                    "SELECT * FROM knowledge WHERE domain=?", (domain.value,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM knowledge").fetchall()

        scored: List[tuple] = []
        for r in rows:
            entry = self._row_to_entry(r)
            if entry is None:
                continue                    # encrypted without a key in esta session
            if not terms:
                scored.append((0, entry))
                continue
            haystack = (
                entry.title + " " + entry.content + " " + " ".join(entry.keywords)
            ).lower()
            score = sum(1 for t in terms if t in haystack)
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: (x[0], x[1].created_at), reverse=True)
        return [e for _, e in scored[:top_k]]

    def by_domain(self, domain: KnowledgeDomain) -> List[KnowledgeEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM knowledge WHERE domain=? ORDER BY created_at DESC",
                (domain.value,),
            ).fetchall()
        return [e for e in (self._row_to_entry(r) for r in rows) if e is not None]

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0]
            by_domain = {
                r["domain"]: r["cnt"]
                for r in conn.execute(
                    "SELECT domain, COUNT(*) as cnt FROM knowledge GROUP BY domain"
                ).fetchall()
            }
        return {"total": total, "by_domain": by_domain}

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def migrate_encryption(self) -> Dict[str, int]:
        """
        encrypts at rest the rows still in plaintext. requires db_key. Re-ejecutable
        (skips the already encrypted) and does VACUUM + checkpoint for clean the
        plaintext residual of the file. same patron that MemoryField.
        """
        if self._cipher is None:
            raise RuntimeError("migrate_encryption requires db_key (set_db_key).")
        migrated = 0
        skipped = 0
        fts_dropped = False
        with self._connect() as conn:
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            has_fts = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='knowledge_fts'"
            ).fetchone()
            if has_fts:
                conn.execute("DROP TABLE IF EXISTS knowledge_fts")
                fts_dropped = True

            rows = conn.execute(
                "SELECT entry_id, title, content, summary, keywords_json, "
                "source_path FROM knowledge"
            ).fetchall()
            for r in rows:
                eid = r["entry_id"]
                if all(is_encrypted(r[c]) for c in self._ENCRYPTED_COLUMNS):
                    skipped += 1
                    continue

                def _reenc(col: str) -> str:
                    stored = r[col] if r[col] is not None else ""
                    if is_encrypted(stored):
                        return stored
                    return self._enc(eid, col, unescape_plaintext(stored))

                conn.execute(
                    "UPDATE knowledge SET title=?, content=?, summary=?, "
                    "keywords_json=?, source_path=? WHERE entry_id=?",
                    (_reenc("title"), _reenc("content"), _reenc("summary"),
                     _reenc("keywords_json"), _reenc("source_path"), eid),
                )
                migrated += 1

        # Implementation note.
        # Implementation note.
        # Implementation note.
        if migrated or fts_dropped:
            scrub = sqlite3.connect(self._db_path, timeout=30)
            try:
                scrub.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                scrub.isolation_level = None
                scrub.execute("VACUUM")
            finally:
                scrub.close()
        return {"migrated": migrated, "skipped": skipped}

    def encryption_status(self) -> Dict[str, int]:
        """Cuenta rows encrypted vs in plaintext (by the column content)."""
        with self._connect() as conn:
            rows = conn.execute("SELECT content FROM knowledge").fetchall()
        enc = sum(1 for r in rows if is_encrypted(r["content"]))
        return {"total": len(rows), "encrypted": enc, "plaintext": len(rows) - enc}

    # Implementation note.

    def _row_to_entry(self, row: sqlite3.Row) -> Optional[KnowledgeEntry]:
        """row  entry descifrada. None if some field encrypted is unreadable
        in esta session (missing the key o dato tampered)."""
        eid = row["entry_id"]
        title = self._dec(eid, "title", row["title"])
        content = self._dec(eid, "content", row["content"])
        if title is None or content is None:
            return None
        keywords_json = self._dec(eid, "keywords_json", row["keywords_json"]) or "[]"
        source_path = self._dec(eid, "source_path", row["source_path"]) or ""
        return KnowledgeEntry(
            entry_id=eid,
            title=title,
            domain=KnowledgeDomain(row["domain"]),
            content=content,
            summary=self._dec(eid, "summary", row["summary"]) or "",
            keywords=json.loads(keywords_json),
            source_path=source_path or None,
            confidence=row["confidence"],
            created_at=row["created_at"],
            content_hash=row["content_hash"],
        )
