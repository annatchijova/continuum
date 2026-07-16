"""
legacy/core/lockfile.py
========================
Lock of instancia unica by data_dir  mitiga KL-007.

KL-007: dos instancias of LegacyAgent over the same vault pierden data
in silencio (the segundo seal() pisa to the first). Este module provee a
lock file cooperativo for that the puntos of entry (CLI, daemons) puedan
garantizar exclusion mutua without depender of fcntl (that does not exist in Windows).

Mecanismo:
  - Adquisicion atomica via os.open(O_CREAT | O_EXCL)  the filesystem
    garantiza that only a proceso crea the file.
  - the lock file contiene JSON {pid, hostname, acquired_at} for diagnosis.
  - Deteccion of locks stale: if the PID of the holder already does not exist in este
    host, the lock is considera orphan (crash without release) and is roba.
    the verificacion of vida only is concluyente in the same hostname;
    for a lock of another host is asume vivo (no is roba).

Uso:
    from legacy.core.lockfile import AgentLock, LockHeldError

    with AgentLock(data_dir):
        ...operar over the vault...

the lock is COOPERATIVO: protege a quienes it usan between si. code that
abra the vault without pasar by the lock no is detenido  igual that any
flock/lockfile of the industria.
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
    """the lock is in poder of another proceso vivo."""

    def __init__(self, holder: Dict[str, Any], lock_path: Path) -> None:
        self.holder = holder
        self.lock_path = lock_path
        super().__init__(
            f"El data_dir ya está en uso por pid={holder.get('pid')} "
            f"host={holder.get('hostname')} desde {holder.get('acquired_at')} "
            f"(lock: {lock_path}). Si ese proceso murió sin liberar, "
            f"borrá el lock manualmente."
        )


def _pid_alive(pid: int) -> bool:
    """True if exists a proceso with ese PID in este host."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Implementation note.
        return True
    except OSError:
        # Implementation note.
        # Implementation note.
        return True


class AgentLock:
    """
    Lock cooperativo of instancia unica over a data_dir.

    data_dir : directory of data of the agente (is crea if does not exist).
    """

    def __init__(self, data_dir: Path) -> None:
        self._lock_path = Path(data_dir) / LOCK_FILENAME
        self._acquired = False

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def acquire(self) -> "AgentLock":
        """
        Adquiere the lock. if hay a lock stale (holder muerto in este
        host), it roba once. Lanza LockHeldError if the holder vive.
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
                    # Implementation note.
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

        # Implementation note.
        raise LockHeldError(self._read_holder() or {}, self._lock_path)

    def release(self) -> None:
        """releases the lock if este objeto it adquirio (idempotente)."""
        if not self._acquired:
            return
        try:
            self._lock_path.unlink()
        except FileNotFoundError:
            pass
        self._acquired = False

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _read_holder(self) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(self._lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _is_stale(self, holder: Optional[Dict[str, Any]]) -> bool:
        """
        a lock is stale if su content is unreadable (crash a mitad of
        escritura) o if the PID of the holder already no vive in ESTE host.
        Locks of otros hosts nunca is consideran stale.
        """
        if holder is None:
            return True
        if holder.get("hostname") != socket.gethostname():
            return False
        pid = holder.get("pid")
        if not isinstance(pid, int):
            return True
        return not _pid_alive(pid)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def __enter__(self) -> "AgentLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
