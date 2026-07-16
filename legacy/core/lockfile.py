"""
legacy/core/lockfile.py
========================
Single-instance lock per data_dir — mitigates KL-007.

KL-007: two LegacyAgent instances using the same vault can silently lose data
(the second seal() overwrites the first). This module provides a cooperative
lock file so entry points (CLI, daemons) can guarantee mutual exclusion
without depending on fcntl, which is unavailable on Windows.

Mechanism:
  - Atomic acquisition via os.open(O_CREAT | O_EXCL): the filesystem guarantees
    that only one process creates the file.
  - The lock file contains JSON {pid, hostname, acquired_at} for diagnostics.
  - Stale-lock detection: if the holder PID no longer exists on this host,
    the lock is considered orphaned (a crash without release) and reclaimed.
    Liveness is conclusive only on the same hostname; a lock from another host
    is assumed alive and is not reclaimed.

Uso:
    from legacy.core.lockfile import AgentLock, LockHeldError

    with AgentLock(data_dir):
        ...operar over the vault...

The lock is COOPERATIVE: it protects callers that agree to use it. Code that
opens the vault without acquiring this lock is not stopped, just like any
other advisory flock or lock file.
"""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

LOCK_FILENAME = "agent.lock"


class LockHeldError(RuntimeError):
    """The lock is held by another live process."""

    def __init__(self, holder: Dict[str, Any], lock_path: Path) -> None:
        self.holder = holder
        self.lock_path = lock_path
        super().__init__(
            f"data_dir is already in use by pid={holder.get('pid')} "
            f"host={holder.get('hostname')} since {holder.get('acquired_at')} "
            f"(lock: {lock_path}). If that process died without releasing it, "
            f"remove the lock manually."
        )


def _pid_alive(pid: int) -> bool:
    """Return True if a process with that PID exists on this host."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Lack of permission means the process exists but cannot be inspected.
        return True
    except OSError:
        # Treat other OS errors conservatively as a live process.
        # This prevents accidentally stealing an active lock.
        return True


class AgentLock:
    """
    Cooperative single-instance lock for a data_dir.

    data_dir : agent data directory (created if it does not exist).
    """

    def __init__(self, data_dir: Path) -> None:
        self._lock_path = Path(data_dir) / LOCK_FILENAME
        self._acquired = False

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    # Acquisition and release.

    def acquire(self) -> "AgentLock":
        """
        Acquire the lock. If a stale lock exists (its holder died on this
        host), reclaim it once. Raise LockHeldError if the holder is alive.
        """
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):          # intento normal + intento tras robo
            try:
                fd = os.open(
                    self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                )
            except FileExistsError:
                holder = self._read_holder()
                if self._is_stale(holder):
                    # Reclaim the stale lock and retry.
                    try:
                        self._lock_path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise LockHeldError(holder or {}, self._lock_path)

            payload = {
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
                "acquired_at": datetime.now(timezone.utc).isoformat(),
            }
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            self._acquired = True
            return self

        # A concurrent process won the retry race.
        raise LockHeldError(self._read_holder() or {}, self._lock_path)

    def release(self) -> None:
        """Release the lock if this object acquired it (idempotent)."""
        if not self._acquired:
            return
        try:
            self._lock_path.unlink()
        except FileNotFoundError:
            pass
        self._acquired = False

    # Holder inspection and stale-lock detection.

    def _read_holder(self) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(self._lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _is_stale(self, holder: Optional[Dict[str, Any]]) -> bool:
        """
        A lock is stale if its content is unreadable (a crash during writing)
        or if the holder PID no longer exists on THIS host. Locks from other
        hosts are never considered stale.
        """
        if holder is None:
            return True
        if holder.get("hostname") != socket.gethostname():
            return False
        pid = holder.get("pid")
        if not isinstance(pid, int):
            return True
        return not _pid_alive(pid)

    # Context-manager protocol.

    def __enter__(self) -> "AgentLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
