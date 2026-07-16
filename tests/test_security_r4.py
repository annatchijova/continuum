"""
tests/test_security_r4.py
==========================
Ronda R4 of red-team (ver SECURITY_AUDIT_R4.md).

R4-001 (CONFIRMADA by INDUCCION, corregida): seal() with passphrase
incorrect over a envelope legible reemplazaba the vault in silencio,
destruyendo the payload and the slot of recovery  the shares of the
custodios quedaban inservibles without no evento.

the demas tests fijan as regresion permanente the vectores DESCARTADOS
of the ronda (H2, H4): that sigan descartados.
"""
from __future__ import annotations

import json
import secrets as _secrets

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.locker import Vault, VaultAuthError

PASS = "passphrase-correcta"


# Implementation note.
# Implementation note.
# Implementation note.

def test_r4_001_seal_wrong_passphrase_fails_closed_v2(tmp_path):
    """the experiment H1, now as regresion: seal with passphrase
    incorrect must lanzar, and data + custodia deben sobrevivir."""
    v = Vault(tmp_path / "t.vault")
    v.seal({"legado": "original"}, PASS)
    rk = _secrets.token_bytes(32)
    v.add_recovery_slot(PASS, rk)

    with pytest.raises(VaultAuthError):
        v.seal({"reemplazo": "malicioso o buggy"}, "passphrase-incorrect")

    # Implementation note.
    assert v.open(PASS) == {"legado": "original"}
    assert v.open_with_recovery(rk) == {"legado": "original"}
    assert v.has_recovery_slot()


def test_r4_001_seal_wrong_passphrase_fails_closed_v1(tmp_path):
    """a v1 legible also exige the passphrase correcta for migrar."""
    from tests.test_vault_v2 import _make_v1_envelope
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, {"legado": "v1"}, PASS)
    v = Vault(path)
    with pytest.raises(VaultAuthError):
        v.seal({"pisado": True}, "incorrect")
    assert v.open(PASS) == {"legado": "v1"}
    assert v.info()["version"] == "1"        # ni siquiera migro


def test_r4_001_corrupt_envelope_can_still_be_replaced(tmp_path):
    """the camino of recovery of desastre is conserva: a envelope
    unreadable SI can reemplazarse (no hay nada that proteger)."""
    v = Vault(tmp_path / "t.vault")
    v._path.write_text("{esto no is json", encoding="utf-8")
    v.seal({"new": "vault"}, PASS)          # no lanza
    assert v.open(PASS) == {"new": "vault"}


def test_r4_001_reseal_with_correct_passphrase_still_works(tmp_path):
    """the operation legitima (lock/heartbeat) no cambio."""
    v = Vault(tmp_path / "t.vault")
    v.seal({"v": 1}, PASS)
    v.seal({"v": 2}, PASS)
    assert v.open(PASS) == {"v": 2}


def test_r4_001_agent_flows_unaffected(tmp_path):
    """initialize/lock/heartbeat/rekey siguen funcionando with the fix."""
    from datetime import datetime, timezone
    from legacy.vault.conditions import AccessPolicy, InactivityCondition
    pol = AccessPolicy([InactivityCondition(
        days=30, last_activity_iso=datetime.now(timezone.utc).isoformat(),
    )])
    a = LegacyAgent(tmp_path, "anna")
    a.initialize(PASS, policy=pol)
    a.lock(PASS)
    a.heartbeat(PASS)
    a.rekey(PASS, "another")
    a.lock("another")
    b = LegacyAgent(tmp_path, "anna")
    b.open_owner("another")


# Implementation note.
# Implementation note.
# Implementation note.

def test_h2_store_key_never_leaves_the_vault(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    src = tmp_path / "doc.txt"
    src.write_text("testamento ante notario and last voluntad", encoding="utf-8")
    a.ingest(src)
    a.archive_artifact(src, PASS)
    key_hex = a._index.store_key_hex
    assert key_hex

    assert key_hex not in a.heir_guide(actor="anna")
    assert key_hex not in json.dumps(a.summary("anna"), default=str)
    assert key_hex not in json.dumps(a._audit.events())
    a.lock(PASS)
    for p in (tmp_path / "data").rglob("*"):
        if p.is_file():
            # Implementation note.
            assert key_hex.encode() not in p.read_bytes(), p.name


# Implementation note.
# Implementation note.
# Implementation note.

def test_h4_heirs_lock_after_recovery_preserves_custody(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    shares = a.setup_custody(PASS, shares=3, threshold=2)
    a.lock(PASS)

    heirs = LegacyAgent(tmp_path / "data", "anna")
    heirs.set_passphrase_from_recovery(shares[:2], "pw-heirs", actor="olga")
    heirs.lock("pw-heirs")

    assert heirs._vault.has_recovery_slot()
    # Implementation note.
    again = LegacyAgent(tmp_path / "data", "anna")
    again.recover_with_shares(shares[1:], actor="olga")
