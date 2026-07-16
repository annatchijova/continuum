"""
tests/test_lockfile.py
=======================
AgentLock: cooperative mutual exclusion by data_dir (mitigates KL-007).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys

import pytest

from legacy.core.lockfile import AgentLock, LockHeldError, LOCK_FILENAME


def test_acquire_and_release(tmp_path):
    lock = AgentLock(tmp_path)
    lock.acquire()
    assert (tmp_path / LOCK_FILENAME).exists()
    lock.release()
    assert not (tmp_path / LOCK_FILENAME).exists()


def test_second_acquire_while_held_raises(tmp_path):
    with AgentLock(tmp_path):
        with pytest.raises(LockHeldError) as exc:
            AgentLock(tmp_path).acquire()
        assert exc.value.holder["pid"] == os.getpid()


def test_reacquire_after_release(tmp_path):
    a = AgentLock(tmp_path)
    a.acquire()
    a.release()
    with AgentLock(tmp_path):
        pass  # must not raise


def test_context_manager_releases_on_exception(tmp_path):
    with pytest.raises(ValueError):
        with AgentLock(tmp_path):
            raise ValueError("boom")
    assert not (tmp_path / LOCK_FILENAME).exists()


def test_stale_lock_from_dead_pid_is_stolen(tmp_path):
    # A dead process must not retain the lock.
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    dead_pid = p.pid

    (tmp_path / LOCK_FILENAME).write_text(json.dumps({
        "pid": dead_pid,
        "hostname": socket.gethostname(),
        "acquired_at": "2020-01-01T00:00:00+00:00",
    }), encoding="utf-8")

    with AgentLock(tmp_path):             # steal the orphaned lock
        holder = json.loads((tmp_path / LOCK_FILENAME).read_text())
        assert holder["pid"] == os.getpid()


def test_corrupt_lockfile_is_stolen(tmp_path):
    (tmp_path / LOCK_FILENAME).write_text("{basura", encoding="utf-8")
    with AgentLock(tmp_path):
        pass  # unreadable content is treated as stale


def test_lock_from_other_host_is_never_stolen(tmp_path):
    (tmp_path / LOCK_FILENAME).write_text(json.dumps({
        "pid": 1,                          # PID 1 exists on this host, but
        "hostname": "another-host-remote",    # the hostname does not match
        "acquired_at": "2020-01-01T00:00:00+00:00",
    }), encoding="utf-8")
    with pytest.raises(LockHeldError):
        AgentLock(tmp_path).acquire()


def test_release_is_idempotent(tmp_path):
    lock = AgentLock(tmp_path)
    lock.acquire()
    lock.release()
    lock.release()                         # must not raise


def test_release_without_acquire_does_not_delete_foreign_lock(tmp_path):
    holder = AgentLock(tmp_path)
    holder.acquire()
    other = AgentLock(tmp_path)            # never acquired the lock
    other.release()
    assert (tmp_path / LOCK_FILENAME).exists(),\
        "release() by a non-holder must not delete a foreign lock"
    holder.release()
