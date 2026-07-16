"""
legacy/memory/consolidator.py
==============================
Consolidacion nocturna of the field of memory.

Inspirado in raven-memory sleep_consolidator.py.

what does:
  1. Identifica memories duplicadas by similitud of content
     (Jaccard over tokens, without embeddings).
  2. Fusiona duplicados: the REINFORCED gana; if hay empate, the more
     reciente gana. the content more largo is preserves.
  3. Pruna sinapsis muertas (weight  0).
  4. updates scores by recency decay.
  5. Promueve a REINFORCED memories with high recall_count.
  6. Degrada a FORGOTTEN memories without acceso in >threshold dias.

the consolidador no borra nada  FORGOTTEN is a state, no a
eliminacion. the audit trail preserves toda the historia.

Uso:
    from legacy.memory.consolidator import Consolidator
    c = Consolidator(memory_field)
    report = c.run()
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from legacy.memory.field import MemoryField, MemoryState, STDP_PRUNE_EPS


@dataclass
class ConsolidationReport:
    started_at: str
    finished_at: str
    duplicates_merged: int
    synapses_pruned: int
    promoted_to_reinforced: int
    degraded_to_forgotten: int
    scores_updated: int
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duplicates_merged": self.duplicates_merged,
            "synapses_pruned": self.synapses_pruned,
            "promoted_to_reinforced": self.promoted_to_reinforced,
            "degraded_to_forgotten": self.degraded_to_forgotten,
            "scores_updated": self.scores_updated,
            "errors": self.errors,
        }


def _tokenize(text: str) -> Set[str]:
    return set(re.findall(r"[a-zaeiounua-z0-9]{3,}", text.lower()))


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


class Consolidator:
    """
    Consolidador of memory  opera over the SQLite of the MemoryField.

    similarity_threshold : Jaccard minimo for considerar duplicado (0.85).
    reinforce_threshold  : recall_count minimo for promover a REINFORCED.
    forget_after_days    : dias without acceso for degradar a FORGOTTEN.
    score_decay          : factor multiplicativo of decay diario.
    """

    def __init__(
        self,
        memory: MemoryField,
        *,
        similarity_threshold: float = 0.85,
        reinforce_threshold: int = 5,
        forget_after_days: float = 90.0,
        score_decay: float = 0.98,
    ) -> None:
        self._memory = memory
        self._db_path = memory._db_path
        self._sim_threshold = similarity_threshold
        self._reinforce_threshold = reinforce_threshold
        self._forget_after_seconds = forget_after_days * 86_400
        self._score_decay = score_decay

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def run(self) -> ConsolidationReport:
        started = datetime.now(timezone.utc).isoformat()
        report = ConsolidationReport(
            started_at=started,
            finished_at="",
            duplicates_merged=0,
            synapses_pruned=0,
            promoted_to_reinforced=0,
            degraded_to_forgotten=0,
            scores_updated=0,
        )
        try:
            report.duplicates_merged = self._merge_duplicates()
            report.synapses_pruned   = self._prune_synapses()
            report.promoted_to_reinforced = self._promote_frequent()
            report.degraded_to_forgotten  = self._degrade_stale()
            report.scores_updated = self._apply_score_decay()
        except Exception as exc:
            report.errors.append(str(exc))
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _merge_duplicates(self) -> int:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT memory_id, content, state, recall_count, last_access "
                "FROM memories WHERE state != 'FORGOTTEN' ORDER BY created_at ASC"
            ).fetchall()
        finally:
            conn.close()

        merged = 0
        seen: List[Tuple[str, Set[str], str]] = []  # (memory_id, tokens, state)

        for row in rows:
            mid = row["memory_id"]
            # Implementation note.
            # Implementation note.
            # Implementation note.
            content = self._memory._dec(mid, "content", row["content"])
            if content is None:
                continue
            tokens = _tokenize(content)
            state = row["state"]

            # Implementation note.
            best_sim = 0.0
            best_idx = -1
            for i, (_, seen_tokens, _) in enumerate(seen):
                sim = _jaccard(tokens, seen_tokens)
                if sim > best_sim:
                    best_sim = sim
                    best_idx = i

            if best_sim >= self._sim_threshold and best_idx >= 0:
                # Implementation note.
                orig_id, orig_tokens, orig_state = seen[best_idx]
                winner_id, loser_id = self._resolve_winner(
                    conn_fn=self._connect,
                    a_id=orig_id,
                    b_id=mid,
                )
                self._merge_pair(winner_id, loser_id)
                merged += 1
                # Implementation note.
                seen[best_idx] = (winner_id, orig_tokens | tokens, orig_state)
            else:
                seen.append((mid, tokens, state))

        return merged

    def _resolve_winner(self, conn_fn, a_id: str, b_id: str) -> Tuple[str, str]:
        """the REINFORCED gana. if empate, the more reciente."""
        conn = conn_fn()
        try:
            a = conn.execute(
                "SELECT state, last_access, recall_count FROM memories WHERE memory_id=?",
                (a_id,)
            ).fetchone()
            b = conn.execute(
                "SELECT state, last_access, recall_count FROM memories WHERE memory_id=?",
                (b_id,)
            ).fetchone()
        finally:
            conn.close()

        if not a or not b:
            return a_id, b_id

        if a["state"] == MemoryState.REINFORCED.value:
            return a_id, b_id
        if b["state"] == MemoryState.REINFORCED.value:
            return b_id, a_id
        # Implementation note.
        if a["last_access"] >= b["last_access"]:
            return a_id, b_id
        return b_id, a_id

    def _merge_pair(self, winner_id: str, loser_id: str) -> None:
        """Marca the perdedor as FORGOTTEN and transfiere sus synapses."""
        conn = self._connect()
        try:
            # Implementation note.
            conn.execute(
                """INSERT OR IGNORE INTO synaptic_links (src_id, dst_id, weight, link_type)
                   SELECT ?, dst_id, weight, link_type
                   FROM synaptic_links WHERE src_id=? AND dst_id != ?""",
                (winner_id, loser_id, winner_id),
            )
            conn.execute(
                """INSERT OR IGNORE INTO synaptic_links (src_id, dst_id, weight, link_type)
                   SELECT src_id, ?, weight, link_type
                   FROM synaptic_links WHERE dst_id=? AND src_id != ?""",
                (winner_id, loser_id, winner_id),
            )
            # Implementation note.
            conn.execute("DELETE FROM synaptic_links WHERE src_id=? OR dst_id=?",
                         (loser_id, loser_id))
            # Implementation note.
            conn.execute(
                "UPDATE memories SET state=? WHERE memory_id=?",
                (MemoryState.FORGOTTEN.value, loser_id),
            )
            conn.commit()
        finally:
            conn.close()

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _prune_synapses(self) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM synaptic_links WHERE weight <= ?",
                (STDP_PRUNE_EPS,)
            )
            pruned = cursor.rowcount
            conn.commit()
        finally:
            conn.close()
        return pruned

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _promote_frequent(self) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                """UPDATE memories SET state=?
                   WHERE recall_count >= ? AND state=?""",
                (
                    MemoryState.REINFORCED.value,
                    self._reinforce_threshold,
                    MemoryState.NEUTRAL.value,
                ),
            )
            promoted = cursor.rowcount
            conn.commit()
        finally:
            conn.close()
        return promoted

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _degrade_stale(self) -> int:
        cutoff = time.time() - self._forget_after_seconds
        conn = self._connect()
        try:
            cursor = conn.execute(
                """UPDATE memories SET state=?
                   WHERE last_access < ? AND state=?""",
                (
                    MemoryState.FORGOTTEN.value,
                    cutoff,
                    MemoryState.NEUTRAL.value,
                ),
            )
            degraded = cursor.rowcount
            conn.commit()
        finally:
            conn.close()
        return degraded

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _apply_score_decay(self) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE memories SET score=score*? WHERE state != ?",
                (self._score_decay, MemoryState.FORGOTTEN.value),
            )
            updated = cursor.rowcount
            conn.commit()
        finally:
            conn.close()
        return updated
