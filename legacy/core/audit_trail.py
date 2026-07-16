"""
legacy/core/audit_trail.py
===========================
Audit trail append-only with hash chain tamper-evident.

each evento of acceso to the legado remains sellado in SQLite WAL.
the hash chain cubre the payload complete  no field is editable
without break the chain.

Semantica:
  - a AuditTrail by vault.
  - append() is atomico: falla o writes the link complete.
  - verify() acumula all the errores, no only the first.
  - the chain is verificable by heirs with the key HMAC o
    of forma independiente without ella (only SHA-256).

Eventos registrados:
  VAULT_CREATED    primer sellado of the vault
  VAULT_UNLOCKED   condition of acceso satisfecha
  VAULT_LOCKED     re-sellado
  ARTIFACT_READ    heir leyo a artifact
  QUERY            query to the agente
  CONDITION_CHECK  evaluation of condition of acceso
  HEIR_ADDED       new heir recorded
  HEIR_REVOKED     heir revocado
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Sequence

from legacy.core.hash_chain import (
    CHAIN_SCHEMA_VERSION,
    GENESIS_HASH,
    ChainLink,
    ChainVerification,
    build_link,
    resolve_hmac_key,
    verify_chain,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    seq         INTEGER PRIMARY KEY,
    event_id    TEXT NOT NULL UNIQUE,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    artifact    TEXT,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    entry_hmac  TEXT,
    chain_ver   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
"""

_STRUCTURAL_FIELDS = frozenset({
    "seq", "prev_hash", "entry_hash", "entry_hmac", "chain_ver",
})


class AuditTrail:
    """
    Audit trail append-only with hash chain v2.

    db_path : ruta to the SQLite (is crea if does not exist).
    hmac_key: bytes of key; None  resuelve of the entorno; b""  hash-only.
    """

    def __init__(
        self,
        db_path: Path,
        hmac_key: Optional[bytes] = None,
    ) -> None:
        self._db_path = db_path
        self._hmac_key: Optional[bytes]
        if hmac_key is None:
            self._hmac_key = resolve_hmac_key()
        elif hmac_key == b"":
            self._hmac_key = None
        else:
            self._hmac_key = hmac_key

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            # Implementation note.
            conn.executescript(_SCHEMA)
        self._seq, self._prev_hash = self._load_tip()

    # Implementation note.
    # Implementation note.
    # Implementation note.

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.isolation_level = None   # autocommit  the transacciones are explicitas
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def _load_tip(self) -> tuple[int, str]:
        """Carga seq and entry_hash of the last link for continuar the chain."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT seq, entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        if row:
            return row[0], row[1]
        return 0, GENESIS_HASH

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def append(
        self,
        event_type: str,
        actor: str,
        *,
        artifact: Optional[str] = None,
        detail: Optional[str] = None,
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        adds a evento sellado a the chain.
        Atomico: o writes the link complete o lanza excepcion.

        FIX F-003 (race condition): the tip (seq + prev_hash) is recarga
        from the DB dentro of the transaccion with EXCLUSIVE lock.
        Multiples instancias over the same file are seguras.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        eid = event_id or str(uuid.uuid4())

        with self._connect() as conn:
            # Implementation note.
            conn.execute("BEGIN EXCLUSIVE")
            tip_row = conn.execute(
                "SELECT seq, entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if tip_row:
                current_seq, current_prev = tip_row[0], tip_row[1]
            else:
                current_seq, current_prev = 0, GENESIS_HASH

            next_seq = current_seq + 1

            payload = {
                "event_id": eid,
                "timestamp": ts,
                "event_type": event_type,
                "actor": actor,
                "artifact": artifact or "",
                "detail": detail or "",
            }

            link = build_link(next_seq, current_prev, payload, self._hmac_key)

            row = {
                "seq": link.seq,
                "event_id": eid,
                "timestamp": ts,
                "event_type": event_type,
                "actor": actor,
                "artifact": artifact or "",
                "detail": detail or "",
                "prev_hash": link.prev_hash,
                "entry_hash": link.entry_hash,
                "entry_hmac": link.entry_hmac or "",
                "chain_ver": CHAIN_SCHEMA_VERSION,
            }

            conn.execute(
                """INSERT INTO audit_events
                   (seq, event_id, timestamp, event_type, actor, artifact,
                    detail, prev_hash, entry_hash, entry_hmac, chain_ver)
                   VALUES (:seq, :event_id, :timestamp, :event_type, :actor,
                           :artifact, :detail, :prev_hash, :entry_hash,
                           :entry_hmac, :chain_ver)""",
                row,
            )
            conn.execute("COMMIT")

        # Implementation note.
        self._seq = next_seq
        self._prev_hash = link.entry_hash
        return row

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def events(
        self,
        *,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """returns eventos filtrados, ordenados by seq ascendente.

        FIX F-005: limit must be int positivo. float("inf") u otros tipos
        invalidos lanzan ValueError instead of OverflowError no manejado.
        """
        if limit is not None:
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise ValueError(f"limit debe ser int positivo, recibido: {limit!r}")
            if limit <= 0:
                raise ValueError(f"limit debe ser > 0, recibido: {limit}")

        query = "SELECT * FROM audit_events WHERE 1=1"
        params: list = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if actor:
            query += " AND actor = ?"
            params.append(actor)
        query += " ORDER BY seq ASC"
        if limit is not None:
            query += f" LIMIT {limit}"

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def verify(self, *, hmac_key: Optional[bytes] = None) -> ChainVerification:
        """
        Verifica the integridad complete of the chain.
        hmac_key=None  usa the key of the entorno (if exists).
        hmac_key=b""   verificacion hash-only, without HMAC.
        """
        key = hmac_key if hmac_key is not None else self._hmac_key
        if isinstance(key, bytes) and len(key) == 0:
            key = None

        rows = self.events()
        links = [
            ChainLink(
                seq=r["seq"],
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
                payload={k: v for k, v in r.items() if k not in _STRUCTURAL_FIELDS},
                entry_hmac=r.get("entry_hmac") or None,
            )
            for r in rows
        ]
        return verify_chain(links, first_seq=1, hmac_key=key)

    @property
    def tip_hash(self) -> str:
        """entry_hash of the last link  for checkpoints externos."""
        return self._prev_hash

    @property
    def length(self) -> int:
        return self._seq
