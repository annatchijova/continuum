"""
legacy/memory/field.py
=======================
field of memory adaptativo for the legado digital.

Adaptado of raven-memory v1.1 (Anna Tchijova).
Cambios key respecto to the original:
  - without numpy/scipy as requisito duro (degradacion graceful).
  - Embeddings: TF-IDF coseno as fallback determinista.
  - state ternario preservado: REINFORCED / NEUTRAL / FORGOTTEN.
  - STDP simplificado: co-activacion directa without KDTree BFS.
  - each memory lleva su categoria (DocCategory) and artifact path.
  - Hash chain of audit over each insertion and query.

SQLite WAL for persistencia. Reconstruccion lazy of the index.
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

# Implementation note.
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

RECENCY_HALFLIFE = 86_400.0     # 24h in segundos
STDP_POTENTIATION = 0.10
STDP_DEPRESSION   = 0.02
STDP_PRUNE_EPS    = 1e-9
STDP_MAX_WEIGHT   = 2.0
STDP_MIN_WEIGHT   = 0.0


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


# Implementation note.
# Implementation note.
# Implementation note.

def _tokenize(text: str) -> List[str]:
    # Implementation note.
    # Implementation note.
    text = unicodedata.normalize("NFC", text)
    return re.findall(r"[a-zaeiounua-z0-9]+", text.lower())


def _tfidf_vector(tokens: List[str], vocab: List[str]) -> List[float]:
    count = Counter(tokens)
    total = max(len(tokens), 1)
    vec = [count.get(w, 0) / total for w in vocab]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    return max(0.0, min(1.0, dot))


def _recency_bonus(last_access: float, now: float) -> float:
    delta = now - last_access
    # Implementation note.
    # Implementation note.
    # Implementation note.
    if delta < 0:
        return 0.0
    return 0.05 * math.exp(-math.log(2) * delta / RECENCY_HALFLIFE)


# Implementation note.
# Implementation note.
# Implementation note.

class MemoryField:
    """
    field of memory of the legado.
    db_path : SQLite where is persisten the memories.
    """

    # Implementation note.
    # Implementation note.
    # Implementation note.
    _ENCRYPTED_COLUMNS = ("content", "embedding_json", "tags_json")

    def __init__(self, db_path: Path, db_key: Optional[bytes] = None) -> None:
        self._db_path = db_path
        self._cipher: Optional[FieldCipher] = FieldCipher(db_key) if db_key else None
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        # Implementation note.
        self._vocab: List[str] = self._load_vocab()

    def set_db_key(self, db_key: Optional[bytes]) -> None:
        """
        Inyecta (o quita) the key of encrypted tras open the vault and
        reconstruye the vocabulario with the content already descifrable.
        the MemoryField is construye in the __init__ of the agente, before of
        open the vault; the key llega after.
        """
        self._cipher = FieldCipher(db_key) if db_key else None
        self._vocab = self._load_vocab()

    # Implementation note.

    @staticmethod
    def _aad(memory_id: str, column: str) -> str:
        return f"{memory_id}:{column}"

    def _enc(self, memory_id: str, column: str, value: str) -> str:
        """
        Forma of storage of a valor logico in plaintext. with cipher 
        ciphertext. without cipher  plaintext escapado (nunca colisiona with the
        prefijo of ciphertext; FIX R5-001).
        """
        if self._cipher:
            return self._cipher.encrypt_field(value, self._aad(memory_id, column))
        return escape_plaintext(value)

    def _dec(self, memory_id: str, column: str, value):
        """
        Convierte the forma of storage in the valor logico in plaintext.
        returns None if the valor no is legible in esta session (encrypted without
        key, o key/AAD incorrectos). the caminos of lectura (recall,
        vocab, consolidator) tratan None as "row that no participa" in
        lugar of propagar the error  the deteccion of manipulacion is tarea
        of verify_memory_integrity, no of the recall.

        Tres formas of storage posibles:
          - ciphertext (gcmf1:...)   requires cipher; None if missing o falla
          - plaintext escapado (gcmf0:...)  is desescapa, legible without a key
          - plaintext verbatim     tal cual (bases pre-0.5.0)
        """
        if value is None:
            return None
        if is_encrypted(value):
            if not self._cipher:
                return None       # encrypted without a key: opaco in esta session
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

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _load_vocab(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT memory_id, content FROM memories").fetchall()
        all_tokens: Counter = Counter()
        for r in rows:
            content = self._dec(r["memory_id"], "content", r["content"])
            if content is None:
                continue        # row encrypted without a key in esta session
            all_tokens.update(_tokenize(content))
        # Implementation note.
        return sorted(t for t, _ in all_tokens.most_common(512))

    def _embed(self, text: str) -> List[float]:
        if not self._vocab:
            return []
        tokens = _tokenize(text)
        return _tfidf_vector(tokens, self._vocab)

    def _rebuild_vocab(self) -> None:
        self._vocab = self._load_vocab()

    # Implementation note.
    # Implementation note.
    # Implementation note.

    # Implementation note.
    MAX_CONTENT_BYTES: int = 256 * 1024   # 256 KB

    # Implementation note.
    # Implementation note.
    # Implementation note.
    # Implementation note.
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
        """Almacena a memory. returns the memory_id.

        FIX F-006: content truncado a MAX_CONTENT_BYTES if excede the limit.
        """
        # Implementation note.
        encoded = content.encode("utf-8")
        if len(encoded) > self.MAX_CONTENT_BYTES:
            content = encoded[: self.MAX_CONTENT_BYTES].decode("utf-8", errors="replace")

        mid = str(uuid.uuid4())
        now = time.time()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Implementation note.
        self._vocab = list(set(self._vocab) | set(_tokenize(content)))
        self._vocab.sort()
        # Implementation note.
        # Implementation note.
        # Implementation note.
        if len(self._vocab) > self._MAX_VOCAB_SIZE:
            self._vocab = self._vocab[: self._MAX_VOCAB_SIZE]
        embedding = self._embed(content)

        # Implementation note.
        # Implementation note.
        # Implementation note.
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
            # Implementation note.
            self._stdp_on_store(conn, mid, content, category)

        return mid

    def _stdp_on_store(
        self,
        conn: sqlite3.Connection,
        new_id: str,
        content: str,
        category: DocCategory,
    ) -> None:
        """Co-activacion: fortalecer enlaces with memories of same categoria."""
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

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def recall(
        self,
        query: str,
        *,
        category: Optional[DocCategory] = None,
        top_k: int = 10,
        min_score: float = 0.01,
    ) -> List[RecallResult]:
        """
        Recupera memories relevantes a the query.
        Scoring: coseno  state_multiplier + recency_bonus.
        """
        now = time.time()
        q_tokens = _tokenize(query)
        q_vec = _tfidf_vector(q_tokens, self._vocab) if self._vocab else []

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
                continue        # row encrypted without a key in esta session
            emb = json.loads(self._dec(mid, "embedding_json", r["embedding_json"]) or "[]")
            if q_vec and emb and len(q_vec) == len(emb):
                cos = _cosine(q_vec, emb)
            elif q_vec:
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                fresh_emb = _tfidf_vector(_tokenize(content), self._vocab)
                cos = _cosine(q_vec, fresh_emb)
            elif q_tokens:
                # Implementation note.
                mem_tokens = set(_tokenize(content))
                overlap = len(set(q_tokens) & mem_tokens)
                cos = overlap / (len(q_tokens) + 1)
            else:
                cos = 0.0

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

        # Implementation note.
        activated = {e.memory_id for _, e in top}
        with self._connect() as conn:
            for _, entry in top:
                conn.execute(
                    "UPDATE memories SET recall_count=recall_count+1, last_access=? "
                    "WHERE memory_id=?",
                    (now, entry.memory_id),
                )
            # Implementation note.
            # Implementation note.
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

    # Implementation note.
    # Implementation note.
    # Implementation note.

    # Implementation note.
    # Implementation note.
    # Implementation note.
    _MAX_SCORE: float = 1e9

    def reinforce(self, memory_id: str) -> None:
        """Eleva the state of a memory a REINFORCED.

        FIX R3-003: score acotado in _MAX_SCORE for prevenir overflow a inf
        tras cientos of calls consecutivas.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE memories SET state=?, score=MIN(score*1.5, ?) WHERE memory_id=?",
                (MemoryState.REINFORCED.value, self._MAX_SCORE, memory_id),
            )

    def forget(self, memory_id: str) -> None:
        """Marca as FORGOTTEN (nunca borra  state, no eliminacion)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE memories SET state=? WHERE memory_id=?",
                (MemoryState.FORGOTTEN.value, memory_id),
            )

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def migrate_encryption(self) -> Dict[str, int]:
        """
        encrypts at rest the rows that still are in plaintext. requires db_key
        (set_db_key previo). Re-ejecutable: the rows already encrypted is are skipped
        (encrypt_field is idempotente over tokens).

        Atomico by row; a corrida interrumpida deja a database mixta
        plaintext/ciphertext perfectamente legible, and re-correr the complete.
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
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
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
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            # Implementation note.
            scrub = sqlite3.connect(self._db_path, timeout=30)
            try:
                scrub.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                scrub.isolation_level = None      # VACUUM no admite transaccion
                scrub.execute("VACUUM")
            finally:
                scrub.close()
        return {"migrated": migrated, "skipped": skipped}

    def encryption_status(self) -> Dict[str, int]:
        """Cuenta rows encrypted vs in plaintext (by the column content)."""
        with self._connect() as conn:
            rows = conn.execute("SELECT content FROM memories").fetchall()
        enc = sum(1 for r in rows if is_encrypted(r["content"]))
        return {"total": len(rows), "encrypted": enc, "plaintext": len(rows) - enc}

    def get_content(self, memory_id: str) -> Optional[str]:
        """content decrypted of a memory (for cross-checks of the agente)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content FROM memories WHERE memory_id=?", (memory_id,)
            ).fetchone()
        if row is None:
            return None
        return self._dec(memory_id, "content", row["content"])

    # Implementation note.
    # Implementation note.
    # Implementation note.

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
