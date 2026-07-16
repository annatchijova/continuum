"""
legacy/memory/consolidator.py
==============================
Nightly consolidation of the memory field.

Inspired by raven-memory sleep_consolidator.py.

What it does:
  1. Identifies duplicate memories by content similarity (Jaccard over tokens,
     without embeddings).
  2. Merges duplicates: REINFORCED wins; on a tie, the more recent wins. The
     longer content is preserved.
  3. Prunes dead synapses (weight <= 0).
  4. Updates scores through recency decay.
  5. Promotes memories with high recall_count to REINFORCED.
  6. Degrades memories without access for more than the threshold to FORGOTTEN.

The consolidator never deletes anything: FORGOTTEN is a state, not deletion.
The audit trail preserves the complete history.

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
    # memory_ids this run marked FORGOTTEN (merge losers + inactivity
    # degradations). The agent records these in the audit trail so
    # verify_memory_integrity can distinguish a legitimate suppression from
    # an attack (FIX R7-002).
    forgotten_ids: List[str] = field(default_factory=list)

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
            "forgotten_ids": self.forgotten_ids,
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
    Memory consolidator operating on the MemoryField SQLite database.

    similarity_threshold : minimum Jaccard similarity for duplicates (0.85).
    reinforce_threshold  : minimum recall_count for REINFORCED promotion.
    forget_after_days    : days without access before FORGOTTEN degradation.
    score_decay          : daily multiplicative decay factor.
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
            merged, merge_forgotten = self._merge_duplicates()
            report.duplicates_merged = merged
            report.synapses_pruned   = self._prune_synapses()
            report.promoted_to_reinforced = self._promote_frequent()
            degraded, stale_forgotten = self._degrade_stale()
            report.degraded_to_forgotten = degraded
            report.scores_updated = self._apply_score_decay()
            report.forgotten_ids = merge_forgotten + stale_forgotten
        except Exception as exc:
            report.errors.append(str(exc))
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    # Duplicate merging.

    def _merge_duplicates(self) -> Tuple[int, List[str]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT memory_id, content, state, recall_count, last_access "
                "FROM memories WHERE state != 'FORGOTTEN' ORDER BY created_at ASC"
            ).fetchall()
        finally:
            conn.close()

        merged = 0
        forgotten: List[str] = []
        seen: List[Tuple[str, Set[str], str]] = []  # (memory_id, tokens, state)

        for row in rows:
            mid = row["memory_id"]
            # Decrypt through MemoryField so encrypted rows remain protected.
            content = self._memory._dec(mid, "content", row["content"])
            if content is None:
                continue
            tokens = _tokenize(content)
            state = row["state"]

            # Find the closest previously seen memory.
            best_sim = 0.0
            best_idx = -1
            for i, (_, seen_tokens, _) in enumerate(seen):
                sim = _jaccard(tokens, seen_tokens)
                if sim > best_sim:
                    best_sim = sim
                    best_idx = i

            if best_sim >= self._sim_threshold and best_idx >= 0:
                # Merge into the winner and retain the combined token set.
                orig_id, orig_tokens, orig_state = seen[best_idx]
                winner_id, loser_id = self._resolve_winner(
                    conn_fn=self._connect,
                    a_id=orig_id,
                    b_id=mid,
                )
                self._merge_pair(winner_id, loser_id)
                merged += 1
                forgotten.append(loser_id)
                # Keep the combined token set for later comparisons.
                seen[best_idx] = (winner_id, orig_tokens | tokens, orig_state)
            else:
                seen.append((mid, tokens, state))

        return merged, forgotten

    def _resolve_winner(self, conn_fn, a_id: str, b_id: str) -> Tuple[str, str]:
        """REINFORCED wins; on a tie, choose the more recent memory."""
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
        # Tie-break by last access time.
        if a["last_access"] >= b["last_access"]:
            return a_id, b_id
        return b_id, a_id

    def _merge_pair(self, winner_id: str, loser_id: str) -> None:
        """Mark the loser FORGOTTEN and transfer its synapses."""
        conn = self._connect()
        try:
            # Transfer outgoing and incoming links to the winner.
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
            # Remove all links belonging to the loser.
            conn.execute("DELETE FROM synaptic_links WHERE src_id=? OR dst_id=?",
                         (loser_id, loser_id))
            # Preserve the loser as history, but exclude it from retrieval.
            conn.execute(
                "UPDATE memories SET state=? WHERE memory_id=?",
                (MemoryState.FORGOTTEN.value, loser_id),
            )
            conn.commit()
        finally:
            conn.close()

    # Synapse pruning.

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

    # Promotion by recall frequency.

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

    # Degradation by inactivity.

    def _degrade_stale(self) -> Tuple[int, List[str]]:
        cutoff = time.time() - self._forget_after_seconds
        conn = self._connect()
        try:
            # SELECT before the UPDATE to capture WHICH memories are being
            # degraded (legitimate audit attribution; FIX R7-002). Same
            # transaction/connection.
            stale = [
                r["memory_id"] for r in conn.execute(
                    "SELECT memory_id FROM memories WHERE last_access < ? AND state=?",
                    (cutoff, MemoryState.NEUTRAL.value),
                ).fetchall()
            ]
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
        return degraded, stale

    # Score decay.

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
