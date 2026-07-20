"""
legacy/memory/field.py
=======================
Adaptive memory field for a digital legacy.

Adapted from raven-memory v1.1 (Anna Tchijova).
Key changes from the original:
  - numpy/scipy are optional dependencies (graceful degradation).
  - Embeddings: deterministic TF-IDF cosine fallback.
  - Three-state model preserved: REINFORCED / NEUTRAL / FORGOTTEN.
  - Simplified STDP: direct co-activation without KDTree BFS.
  - Each memory carries its category (DocCategory) and artifact path.
  - Audit hash chain over every insertion and query.

SQLite WAL persistence. Lazy index reconstruction.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import unicodedata
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from legacy.core.dbcrypto import (
    FieldCipher,
    FieldCryptoError,
    escape_plaintext,
    is_encrypted,
    unescape_plaintext,
)
from legacy.ingestion.doc_types import DocCategory

# Optional scientific-computing acceleration.
try:
    import numpy as np
    from scipy.spatial import KDTree
    _SCIPY = True
except ImportError:
    _SCIPY = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    memory_id   TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    content     TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    artifact    TEXT,
    state       TEXT NOT NULL DEFAULT 'NEUTRAL',
    score       REAL NOT NULL DEFAULT 1.0,
    recall_count INTEGER NOT NULL DEFAULT 0,
    last_access  REAL NOT NULL,
    created_at   REAL NOT NULL,
    embedding_json TEXT,
    tags_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_mem_category ON memories(category);
CREATE INDEX IF NOT EXISTS idx_mem_state    ON memories(state);

CREATE TABLE IF NOT EXISTS synaptic_links (
    src_id      TEXT NOT NULL,
    dst_id      TEXT NOT NULL,
    weight      REAL NOT NULL DEFAULT 1.0,
    link_type   TEXT NOT NULL DEFAULT 'NEUTRAL',
    PRIMARY KEY (src_id, dst_id),
    FOREIGN KEY (src_id) REFERENCES memories(memory_id),
    FOREIGN KEY (dst_id) REFERENCES memories(memory_id)
);
"""

RECENCY_HALFLIFE = 86_400.0     # 24 hours in seconds
STDP_POTENTIATION = 0.10
STDP_DEPRESSION   = 0.02
STDP_PRUNE_EPS    = 1e-9
STDP_MAX_WEIGHT   = 2.0
STDP_MIN_WEIGHT   = 0.0

# Common question words may influence TF-IDF, but cannot establish that a
# document is evidence for a factual question.
_QUERY_STOPWORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "before", "by", "can",
        "could", "do", "does", "for", "from", "had", "has", "have", "how",
        "i", "in", "is", "it", "me", "my", "of", "on", "or", "please",
        "should", "show", "tell", "that", "the", "this", "to", "was", "we",
        "what", "when", "where", "which", "who", "why", "with", "would", "you",
        "your", "about", "all", "any", "find", "get", "give", "need",
        "de", "del", "el", "en", "es", "la", "las", "lo", "los", "mi", "mis",
        "para", "por", "que", "quiero", "su", "sus", "un", "una", "y", "yo",
    }
)


class MemoryState(str, Enum):
    REINFORCED = "REINFORCED"
    NEUTRAL    = "NEUTRAL"
    FORGOTTEN  = "FORGOTTEN"

    @property
    def multiplier(self) -> float:
        return {"REINFORCED": 1.5, "NEUTRAL": 1.0, "FORGOTTEN": 0.0}[self.value]


class LinkType(str, Enum):
    RESONANT   = "RESONANT"
    NEUTRAL    = "NEUTRAL"
    INHIBITORY = "INHIBITORY"


@dataclass
class MemoryEntry:
    memory_id: str
    category: DocCategory
    content: str
    content_hash: str
    artifact: Optional[str]
    state: MemoryState
    score: float
    recall_count: int
    last_access: float
    created_at: float
    embedding: Optional[List[float]]
    tags: List[str]


@dataclass
class RecallResult:
    memory_id: str
    category: DocCategory
    content: str
    artifact: Optional[str]
    final_score: float
    state: MemoryState
    tags: List[str]


# Tokenization and vector helpers.

def _tokenize(text: str) -> List[str]:
    # NFC normalization makes canonically equivalent text share tokens.
    # Restrict tokens to letters and digits.
    text = unicodedata.normalize("NFC", text)
    return re.findall(r"[a-zaeiounua-z0-9]+", text.lower())


def _has_evidence_overlap(query_terms: set[str], memory_tokens: set[str]) -> bool:
    """Match a content term, allowing the ordinary English plural suffix."""
    for term in query_terms:
        if term in memory_tokens:
            return True
        if len(term) > 3 and term.endswith("s") and term[:-1] in memory_tokens:
            return True
        if any(
            len(token) > 3 and token.endswith("s") and token[:-1] == term
            for token in memory_tokens
        ):
            return True
    return False


def _idf_weights(vocab: List[str], doc_freq: Counter, doc_count: int) -> Dict[str, float]:
    """
    Smoothed inverse document frequency: log((N+1)/(df+1)) + 1.
    Always positive, so a term present in every document still contributes
    (weight 1.0) instead of collapsing to zero.
    """
    n = max(doc_count, 1)
    return {t: math.log((n + 1) / (doc_freq.get(t, 0) + 1)) + 1.0 for t in vocab}


def _tfidf_vector(
    tokens: List[str], vocab: List[str], idf: Optional[Dict[str, float]] = None
) -> List[float]:
    count = Counter(tokens)
    total = max(len(tokens), 1)
    if idf:
        vec = [(count.get(w, 0) / total) * idf.get(w, 1.0) for w in vocab]
    else:
        # FIX: this branch is plain term frequency, not TF-IDF — kept only for
        # callers that have no corpus-wide document-frequency stats yet.
        vec = [count.get(w, 0) / total for w in vocab]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    return max(0.0, min(1.0, dot))


def _recency_bonus(last_access: float, now: float) -> float:
    delta = now - last_access
    # Return no bonus for future timestamps.
    if delta < 0:
        return 0.0
    return 0.05 * math.exp(-math.log(2) * delta / RECENCY_HALFLIFE)


# Memory field implementation.

class MemoryField:
    """
    Memory field for the legacy.
    db_path : SQLite path where memories are persisted.
    """

    # Columns encrypted when a database key is configured.
    _ENCRYPTED_COLUMNS = ("content", "embedding_json", "tags_json")

    def __init__(self, db_path: Path, db_key: Optional[bytes] = None) -> None:
        self._db_path = db_path
        self._cipher: Optional[FieldCipher] = FieldCipher(db_key) if db_key else None
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        # Reconstruct the vocabulary lazily from readable content.
        self._vocab: List[str]
        self._doc_freq: Counter
        self._doc_count: int
        self._vocab, self._doc_freq, self._doc_count = self._load_vocab()
        self._idf: Dict[str, float] = _idf_weights(
            self._vocab, self._doc_freq, self._doc_count
        )

    def set_db_key(self, db_key: Optional[bytes]) -> None:
        """
        Inject or remove the encryption key after opening the vault and
        rebuild the vocabulary from currently readable content.
        MemoryField is constructed in the agent's __init__ before the vault is
        opened; the key becomes available afterward.
        """
        self._cipher = FieldCipher(db_key) if db_key else None
        self._vocab, self._doc_freq, self._doc_count = self._load_vocab()
        self._idf = _idf_weights(self._vocab, self._doc_freq, self._doc_count)

    # Bind encrypted values to their memory row and column.

    @staticmethod
    def _aad(memory_id: str, column: str) -> str:
        return f"{memory_id}:{column}"

    def _enc(self, memory_id: str, column: str, value: str) -> str:
        """
        Return the stored form of a logical plaintext value. With a cipher,
        return ciphertext; without one, escape plaintext so it can never
        collide with the ciphertext prefix (FIX R5-001).
        """
        if self._cipher:
            return self._cipher.encrypt_field(value, self._aad(memory_id, column))
        return escape_plaintext(value)

    def _dec(self, memory_id: str, column: str, value):
        """
        Convert the stored form into the logical plaintext value.
        Return None when the value is unreadable in this session (encrypted
        without a key, or incorrect key/AAD). Read paths (recall, vocabulary,
        consolidator) treat None as a row that does not participate instead of
        propagating the error. Tamper detection belongs to
        verify_memory_integrity, not recall.

        Three storage forms are possible:
          - ciphertext (gcmf1:...) requires a cipher; None if unavailable or invalid
          - escaped plaintext (gcmf0:...) unescaped and readable without a key
          - verbatim plaintext (pre-0.5.0 databases)
        """
        if value is None:
            return None
        if is_encrypted(value):
            if not self._cipher:
                return None       # Encrypted without a key: opaque in this session.
            try:
                return self._cipher.decrypt_field(value, self._aad(memory_id, column))
            except FieldCryptoError:
                return None
        return unescape_plaintext(value)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Vocabulary management.

    def _load_vocab(self) -> Tuple[List[str], Counter, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT memory_id, content FROM memories").fetchall()
        all_tokens: Counter = Counter()
        doc_freq: Counter = Counter()
        doc_count = 0
        for r in rows:
            content = self._dec(r["memory_id"], "content", r["content"])
            if content is None:
                continue        # Encrypted row without a key in this session.
            tokens = _tokenize(content)
            all_tokens.update(tokens)
            doc_freq.update(set(tokens))
            doc_count += 1
        # FIX: when the vocabulary must be trimmed to the cap, keep the
        # terms with the *lowest* document frequency first, not the ones
        # with the highest raw term frequency. A word that occurs once
        # across the whole corpus (a name, a codeword, an identifier) is
        # exactly what makes one memory findable among many, but
        # `most_common` was discarding it in favor of common words that
        # appear in almost every document and carry the least discriminative
        # signal — the opposite of what a search index needs.
        ranked = sorted(all_tokens, key=lambda t: (doc_freq[t], t))
        vocab = sorted(ranked[:512])
        return vocab, doc_freq, doc_count

    def _embed(self, text: str) -> List[float]:
        if not self._vocab:
            return []
        tokens = _tokenize(text)
        return _tfidf_vector(tokens, self._vocab, self._idf)

    def _rebuild_vocab(self) -> None:
        self._vocab, self._doc_freq, self._doc_count = self._load_vocab()
        self._idf = _idf_weights(self._vocab, self._doc_freq, self._doc_count)

    # Storage.

    MAX_CONTENT_BYTES: int = 256 * 1024   # 256 KB content limit.

    # Bound vocabulary growth during a session.
    _MAX_VOCAB_SIZE: int = 512

    def store(
        self,
        content: str,
        category: DocCategory,
        *,
        artifact: Optional[str] = None,
        tags: Optional[List[str]] = None,
        state: MemoryState = MemoryState.NEUTRAL,
    ) -> str:
        """Store a memory and return its memory_id.

        FIX F-006: truncate content to MAX_CONTENT_BYTES when it exceeds the limit.
        """
        # Enforce the maximum UTF-8 byte size.
        encoded = content.encode("utf-8")
        if len(encoded) > self.MAX_CONTENT_BYTES:
            content = encoded[: self.MAX_CONTENT_BYTES].decode("utf-8", errors="replace")

        mid = str(uuid.uuid4())
        now = time.time()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Update corpus-wide document-frequency stats first, then rank the
        # merged vocabulary the same way _load_vocab does (rarest terms
        # first) before applying the size cap — keeps a codeword or name
        # seen only in this document from being displaced by common words.
        content_tokens = set(_tokenize(content))
        self._doc_count += 1
        self._doc_freq.update(content_tokens)
        merged_terms = set(self._vocab) | content_tokens
        ranked = sorted(merged_terms, key=lambda t: (self._doc_freq[t], t))
        self._vocab = sorted(ranked[: self._MAX_VOCAB_SIZE])
        self._idf = _idf_weights(self._vocab, self._doc_freq, self._doc_count)
        embedding = self._embed(content)

        # Persist the memory and its encrypted fields.
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO memories
                   (memory_id, category, content, content_hash, artifact,
                    state, score, recall_count, last_access, created_at,
                    embedding_json, tags_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    mid, category.value,
                    self._enc(mid, "content", content), content_hash,
                    artifact or "", state.value, 1.0, 0, now, now,
                    self._enc(mid, "embedding_json", json.dumps(embedding)),
                    self._enc(mid, "tags_json", json.dumps(tags or [])),
                ),
            )
            # Create bidirectional STDP links with related memories.
            self._stdp_on_store(conn, mid, content, category)

        return mid

    def _stdp_on_store(
        self,
        conn: sqlite3.Connection,
        new_id: str,
        content: str,
        category: DocCategory,
    ) -> None:
        """Co-activation: strengthen links with memories in the same category."""
        peers = conn.execute(
            "SELECT memory_id FROM memories WHERE category=? AND memory_id!=? "
            "AND state != 'FORGOTTEN' LIMIT 10",
            (category.value, new_id),
        ).fetchall()
        for row in peers:
            pid = row["memory_id"]
            existing = conn.execute(
                "SELECT weight FROM synaptic_links WHERE src_id=? AND dst_id=?",
                (pid, new_id),
            ).fetchone()
            if existing:
                new_w = min(existing["weight"] + STDP_POTENTIATION, STDP_MAX_WEIGHT)
            else:
                new_w = 1.0 + STDP_POTENTIATION
            conn.execute(
                """INSERT INTO synaptic_links (src_id, dst_id, weight, link_type)
                   VALUES (?,?,?,?)
                   ON CONFLICT(src_id, dst_id) DO UPDATE SET weight=excluded.weight""",
                (pid, new_id, new_w, LinkType.RESONANT.value),
            )
            conn.execute(
                """INSERT INTO synaptic_links (src_id, dst_id, weight, link_type)
                   VALUES (?,?,?,?)
                   ON CONFLICT(src_id, dst_id) DO UPDATE SET weight=excluded.weight""",
                (new_id, pid, new_w, LinkType.RESONANT.value),
            )

    # Recall and state updates.

    def recall(
        self,
        query: str,
        *,
        category: Optional[DocCategory] = None,
        top_k: int = 10,
        min_score: float = 0.01,
    ) -> List[RecallResult]:
        """
        Retrieve memories relevant to the query.
        Scoring: cosine * state_multiplier + recency_bonus.
        """
        now = time.time()
        q_tokens = _tokenize(query)
        # FIX: a contraction or possessive ("what's", "Dr. Lee's") tokenizes
        # into a real word plus an orphan one-character fragment ("s"). That
        # fragment is not a stopword, so it was surviving as "evidence" and
        # matching almost any document containing an apostrophe — exactly
        # the kind of accidental overlap this filter exists to reject.
        evidence_terms = {
            t for t in q_tokens if t not in _QUERY_STOPWORDS and len(t) > 1
        }
        q_vec = _tfidf_vector(q_tokens, self._vocab, self._idf) if self._vocab else []

        with self._connect() as conn:
            if category:
                rows = conn.execute(
                    "SELECT * FROM memories WHERE category=? AND state!='FORGOTTEN'",
                    (category.value,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM memories WHERE state!='FORGOTTEN'",
                ).fetchall()

        results: List[Tuple[float, MemoryEntry]] = []
        for r in rows:
            mid = r["memory_id"]
            content = self._dec(mid, "content", r["content"])
            if content is None:
                continue        # Encrypted row without a key in this session.
            emb = json.loads(self._dec(mid, "embedding_json", r["embedding_json"]) or "[]")
            if q_vec:
                # FIX: always recompute against the current vocabulary/IDF
                # instead of trusting the stored embedding_json. IDF depends
                # on document-frequency counts for the whole corpus, which
                # keep changing as memories are added even when the
                # vocabulary's *length* stops changing (it is capped at
                # _MAX_VOCAB_SIZE) — a same-length stored vector can still
                # have been built against stale document frequencies and
                # silently under- or over-score. Content is already
                # decrypted above, so recomputing here is cheap.
                fresh_emb = _tfidf_vector(_tokenize(content), self._vocab, self._idf)
                cos = _cosine(q_vec, fresh_emb)
            elif q_tokens:
                # Score lexical token overlap when no query vector exists.
                mem_tokens = set(_tokenize(content))
                overlap = len(set(q_tokens) & mem_tokens)
                cos = overlap / (len(q_tokens) + 1)
            else:
                cos = 0.0

            # A capped vocabulary can omit a rare query term, so establish
            # evidence with direct overlap as well as TF-IDF. Recency only
            # orders relevant results; it cannot manufacture evidence from a
            # shared question word such as "is" or "my".
            if q_tokens and not evidence_terms:
                continue
            if evidence_terms and not _has_evidence_overlap(
                evidence_terms, set(_tokenize(content))
            ):
                continue

            state = MemoryState(r["state"])
            final = cos * state.multiplier + _recency_bonus(r["last_access"], now)

            if final >= min_score:
                entry = MemoryEntry(
                    memory_id=mid,
                    category=DocCategory(r["category"]),
                    content=content,
                    content_hash=r["content_hash"],
                    artifact=r["artifact"] or None,
                    state=state,
                    score=r["score"],
                    recall_count=r["recall_count"],
                    last_access=r["last_access"],
                    created_at=r["created_at"],
                    embedding=emb,
                    tags=json.loads(self._dec(mid, "tags_json", r["tags_json"]) or "[]"),
                )
                results.append((final, entry))

        results.sort(key=lambda x: x[0], reverse=True)
        top = results[:top_k]

        # Update access state and apply synaptic depression.
        activated = {e.memory_id for _, e in top}
        with self._connect() as conn:
            for _, entry in top:
                conn.execute(
                    "UPDATE memories SET recall_count=recall_count+1, last_access=? "
                    "WHERE memory_id=?",
                    (now, entry.memory_id),
                )
            # Depress links from memories that were not activated.
            if activated:
                placeholders = ",".join("?" * len(activated))
                conn.execute(
                    f"UPDATE synaptic_links SET weight=MAX(?,weight-?) "
                    f"WHERE src_id NOT IN ({placeholders}) AND weight>?",
                    (STDP_MIN_WEIGHT, STDP_DEPRESSION, *activated, STDP_PRUNE_EPS),
                )
            else:
                conn.execute(
                    "UPDATE synaptic_links SET weight=MAX(?,weight-?) WHERE weight>?",
                    (STDP_MIN_WEIGHT, STDP_DEPRESSION, STDP_PRUNE_EPS),
                )

        return [
            RecallResult(
                memory_id=entry.memory_id,
                category=entry.category,
                content=entry.content,
                artifact=entry.artifact,
                final_score=score,
                state=entry.state,
                tags=entry.tags,
            )
            for score, entry in top
        ]

    # Explicit state transitions.

    # Keep the score bounded to prevent overflow.
    _MAX_SCORE: float = 1e9

    def reinforce(self, memory_id: str) -> None:
        """Promote a memory to REINFORCED.

        FIX R3-003: cap the score at _MAX_SCORE to prevent overflow to infinity
        after hundreds of consecutive calls.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE memories SET state=?, score=MIN(score*1.5, ?) WHERE memory_id=?",
                (MemoryState.REINFORCED.value, self._MAX_SCORE, memory_id),
            )

    def forget(self, memory_id: str) -> None:
        """Mark a memory FORGOTTEN (state change, never deletion)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE memories SET state=? WHERE memory_id=?",
                (MemoryState.FORGOTTEN.value, memory_id),
            )

    # Encryption migration and status.

    def migrate_encryption(self) -> Dict[str, int]:
        """
        Encrypt rows that are still plaintext at rest. Requires db_key
        (set_db_key first). Repeatable: already encrypted rows are skipped
        (encrypt_field is idempotent for tokens).

        Atomic per row; an interrupted run leaves a mixed plaintext/ciphertext
        database that remains readable, and rerunning completes the migration.
        """
        if self._cipher is None:
            raise RuntimeError("migrate_encryption requires db_key (set_db_key).")
        migrated = 0
        skipped = 0
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT memory_id, content, embedding_json, tags_json FROM memories"
            ).fetchall()
            for r in rows:
                mid = r["memory_id"]
                if all(is_encrypted(r[c]) for c in self._ENCRYPTED_COLUMNS):
                    skipped += 1
                    continue
                # Re-encrypt only fields that are still stored as plaintext.
                def _reenc(col: str) -> str:
                    stored = r[col] if r[col] is not None else "[]"
                    if is_encrypted(stored):
                        return stored
                    return self._enc(mid, col, unescape_plaintext(stored))

                conn.execute(
                    "UPDATE memories SET content=?, embedding_json=?, tags_json=? "
                    "WHERE memory_id=?",
                    (_reenc("content"), _reenc("embedding_json"),
                     _reenc("tags_json"), mid),
                )
                migrated += 1

        if migrated:
            # Scrub plaintext left in free pages and the WAL.
            scrub = sqlite3.connect(self._db_path, timeout=30)
            try:
                scrub.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                scrub.isolation_level = None      # VACUUM cannot run in a transaction.
                scrub.execute("VACUUM")
            finally:
                scrub.close()
        return {"migrated": migrated, "skipped": skipped}

    def encryption_status(self) -> Dict[str, int]:
        """Count encrypted and plaintext rows using the content column."""
        with self._connect() as conn:
            rows = conn.execute("SELECT content FROM memories").fetchall()
        enc = sum(1 for r in rows if is_encrypted(r["content"]))
        return {"total": len(rows), "encrypted": enc, "plaintext": len(rows) - enc}

    def get_content(self, memory_id: str) -> Optional[str]:
        """Return decrypted memory content for agent cross-checks."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (memory_id,)
            ).fetchone()
        if row is None:
            return None
        return self._dec(memory_id, "content", row["content"])

    # Aggregate statistics.

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            by_state = {
                r["state"]: r["cnt"]
                for r in conn.execute(
                    "SELECT state, COUNT(*) as cnt FROM memories GROUP BY state"
                ).fetchall()
            }
            by_cat = {
                r["category"]: r["cnt"]
                for r in conn.execute(
                    "SELECT category, COUNT(*) as cnt FROM memories GROUP BY category"
                ).fetchall()
            }
        return {
            "total": total,
            "by_state": by_state,
            "by_category": by_cat,
            "vocab_size": len(self._vocab),
        }
