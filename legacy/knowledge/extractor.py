"""
legacy/knowledge/extractor.py
==============================
Professional knowledge extractor.

Converts documents, notes, and writings into a searchable knowledge database:
not just inert files, but structured entries with topic, context, and content.

Use cases:
  - 20 years of medical notes: searchable by specialty
  - Engineering projects: preserved decisions and reasoning
  - Classes and teaching materials: pedagogical knowledge

Knowledge-entry structure:
  KnowledgeEntry:
    entry_id    : UUID
    title       : inferred title (first N significant words)
    domain      : subject area (MEDICINE / ENGINEERING / LAW / EDUCATION /
                  FINANCE / GENERAL)
    content     : text complete
    summary     : 1–3 sentence summary (deterministic, without an LLM)
    keywords    : extracted key terms
    source_path : source artifact
    confidence  : HIGH / MEDIUM / LOW (for the extraction)
    created_at  : ISO 8601

The extractor is pure: the same input produces the same output.
It does not call LLMs; the summary uses deterministic heuristics.
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


# Knowledge domains and detection signals.

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
      ["class", "lesson", "student", "curriculum", "evaluation", "pedagog",
      "assessment", "learning", "teaching", "syllabus"],
     Fraction(2)),
    (KnowledgeDomain.FINANCE,
     ["balance", "cash flow", "capital", "performance", "portfolio",
      "risk", "volatility", "cashflow", "yield",
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


# Knowledge entry model.

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


# Text extraction helpers.

_STOP_WORDS = frozenset({
    "of", "the", "a", "and", "in", "with", "by", "for", "that", "of the",
    "to the", "is", "it", "on", "at",
    "the", "of", "and", "to", "in", "is", "it", "for", "on", "at",
})

_SENTENCE_END = re.compile(r"[.!?]\s+")


def _infer_title(text: str, max_words: int = 8) -> str:
    """Return the first N significant words of the text as a title."""
    first_line = text.strip().split("\n")[0]
    words = re.findall(r"[A-ZAEIOUNa-zaeiounua-z0-9]+", first_line)
    significant = [w for w in words if w.lower() not in _STOP_WORDS][:max_words]
    return " ".join(significant).capitalize() or "entry without title"


def _extract_keywords(text: str, top_n: int = 15) -> List[str]:
    """Extract keywords by frequency, excluding stop words."""
    from collections import Counter
    tokens = re.findall(r"[a-zaeiounua-z]{4,}", text.lower())
    filtered = [t for t in tokens if t not in _STOP_WORDS]
    counter = Counter(filtered)
    return [w for w, _ in counter.most_common(top_n)]


def _summarize(text: str, max_sentences: int = 3) -> str:
    """
    Deterministic heuristic summary: first N sentences above the minimum length.
    No LLM is used.
    """
    sentences = _SENTENCE_END.split(text.strip())
    meaningful = [s.strip() for s in sentences if len(s.strip()) > 30]
    selected = meaningful[:max_sentences]
    return " ".join(selected)[:500] or text[:200]


_KW_PATTERN_CACHE: Dict[str, re.Pattern] = {}


def _keyword_present(kw: str, text_lower: str) -> bool:
    """Return true if `kw` appears at the beginning of a word in `text_lower`.

    Avoid false positives inside another word while preserving prefix matches.
    """
    pat = _KW_PATTERN_CACHE.get(kw)
    if pat is None:
        pat = re.compile(r"\b" + re.escape(kw))
        _KW_PATTERN_CACHE[kw] = pat
    return pat.search(text_lower) is not None


def _detect_domain(text: str) -> tuple[KnowledgeDomain, str]:
    """Return (domain, confidence)."""
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


# SQLite schema.

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
# Persistent knowledge base.


class KnowledgeBase:
    """
    Persistent professional knowledge database backed by SQLite.

    db_path : path to the SQLite file.
    db_key  : 32-byte key for encrypting sensitive fields at rest (KL-001b).
              None means plaintext database (compatibility mode).

    With db_key, search scans decrypted rows in memory; without the key the
    database is opaque and search() returns no results.
    """

    # Fields encrypted at rest when a database key is configured.
    _ENCRYPTED_COLUMNS = ("title", "content", "summary", "keywords_json", "source_path")

    def __init__(self, db_path: Path, db_key: Optional[bytes] = None) -> None:
        self._db_path = db_path
        self._cipher: Optional[FieldCipher] = FieldCipher(db_key) if db_key else None
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def set_db_key(self, db_key: Optional[bytes]) -> None:
        """Set or remove the encryption key after opening the vault."""
        self._cipher = FieldCipher(db_key) if db_key else None

    # Associated data binds each encrypted value to its entry and column.

    @staticmethod
    def _aad(entry_id: str, column: str) -> str:
        return f"{entry_id}:{column}"

    def _enc(self, entry_id: str, column: str, value: str) -> str:
        if self._cipher:
            return self._cipher.encrypt_field(value, self._aad(entry_id, column))
        return escape_plaintext(value)

    def _dec(self, entry_id: str, column: str, value):
        """Convert a stored value to its logical value; None if unreadable."""
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

    # Extraction and persistence.

    def extract_and_store(
        self,
        text: str,
        source_path: Optional[str] = None,
        *,
        min_length: int = 100,
    ) -> Optional[KnowledgeEntry]:
        """
        Extract and store knowledge from text.
        Return None when the text is too short or trivial.
        """
        text = text.strip()
        if len(text) < min_length:
            return None

        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # Avoid storing duplicate content.
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
        Divide long text into overlapping chunks and extract each one.
        Useful for large documents.
        """
        entries: List[KnowledgeEntry] = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]
            # Prefer ending chunks at sentence boundaries.
            if end < len(text):
                last_period = chunk.rfind(".")
                if last_period > chunk_size // 2:
                    chunk = chunk[: last_period + 1]
                    end = start + last_period + 1
            entry = self.extract_and_store(chunk, source_path=source_path)
            if entry:
                entries.append(entry)
            # Advance with the requested overlap while guaranteeing progress.
            start = max(end - overlap, start + 1)
        return entries

    # Search and metadata.

    def search(
        self,
        query: str,
        *,
        domain: Optional[KnowledgeDomain] = None,
        top_k: int = 10,
    ) -> List[KnowledgeEntry]:
        """
        Search by scanning decrypted rows in memory (KL-001b), scoring term
        overlap across title, content, and keywords. Domain filtering is done
        in SQL because domain remains plaintext. Rows that cannot be decrypted
        in this session do not participate; without a key, search is empty.
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
                continue                    # encrypted without a key in this session
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

    # Encryption migration.

    def migrate_encryption(self) -> Dict[str, int]:
        """
        Encrypt rows still in plaintext at rest. Requires db_key. Safe to rerun:
        already encrypted rows are skipped. Runs VACUUM and checkpoint to clean
        plaintext remnants from the file, matching MemoryField behavior.
        """
        if self._cipher is None:
            raise RuntimeError("migrate_encryption requires db_key (set_db_key).")
        migrated = 0
        skipped = 0
        fts_dropped = False
        with self._connect() as conn:
            # Drop the legacy plaintext FTS index before scrubbing the database.
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

        # Scrub WAL and database pages after migration.
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
        """Count encrypted and plaintext rows using the content column."""
        with self._connect() as conn:
            rows = conn.execute("SELECT content FROM knowledge").fetchall()
        enc = sum(1 for r in rows if is_encrypted(r["content"]))
        return {"total": len(rows), "encrypted": enc, "plaintext": len(rows) - enc}

    # Row decoding.

    def _row_to_entry(self, row: sqlite3.Row) -> Optional[KnowledgeEntry]:
        """Decode a row into an entry, or None if encrypted data is unreadable
        in this session because the key is missing or data was tampered with."""
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
