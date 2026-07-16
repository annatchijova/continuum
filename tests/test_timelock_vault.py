"""
tests/test_timelock_vault.py
=============================
Integration of the time-lock puzzle as a vault keyslot and agent component
(offline component of KL-011). Small T keeps tests fast.

Central invariant: the vault can open by solving the puzzle without the
passphrase or custodians; the slot is INDEPENDENT and survives rekey alongside
the other v2 keyslots.
"""
from __future__ import annotations

import json

import pytest

from legacy.vault.locker import Vault, VaultAuthError
from legacy.agent.memory_agent import LegacyAgent

PASS = "passphrase-of the-owner"
DATA = {"owner_id": "anna", "artifacts": [{"a": 1}]}
T = 30_000          # ~0.3 s of resolucion; suficiente for ejercer the camino


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "t.vault")
    v.seal(DATA, PASS)
    return v


# Vault time-lock behavior.

def test_open_with_timelock(vault):
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.has_timelock_slot()
    assert vault.timelock_info()["squarings"] == T
    assert vault.open_with_timelock() == DATA          # without a passphrase


def test_timelock_slot_is_independent(vault):
    """Adding a time-lock does not break the passphrase; both open the payload."""
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.open(PASS) == DATA
    assert vault.open_with_timelock() == DATA


def test_timelock_survives_rekey(vault):
    """The time-lock slot survives passphrase rewrapping (v2 keyslots)."""
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    vault.rewrap_passphrase(PASS, "new")
    assert vault.open("new") == DATA
    assert vault.open_with_timelock() == DATA          # remains valid


def test_timelock_coexists_with_recovery(vault):
    import secrets
    rk = secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, rk)
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.open(PASS) == DATA
    assert vault.open_with_recovery(rk) == DATA
    assert vault.open_with_timelock() == DATA          # three independent paths


def test_remove_timelock(vault):
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.remove_timelock_slot(PASS) is True
    assert not vault.has_timelock_slot()
    with pytest.raises(VaultAuthError):
        vault.open_with_timelock()
    assert vault.remove_timelock_slot(PASS) is False


def test_open_with_timelock_without_slot_raises(vault):
    """A v2 vault without a configured time-lock slot cannot open that way."""
    assert not vault.has_timelock_slot()
    with pytest.raises(VaultAuthError):
        vault.open_with_timelock()


def test_open_with_timelock_on_v1_raises(tmp_path):
    """A v1 envelope reports that time-lock recovery is unavailable."""
    from tests.test_vault_v2 import _make_v1_envelope
    path = tmp_path / "old.vault"
    _make_v1_envelope(path, DATA, PASS)
    with pytest.raises(VaultAuthError, match="v1"):
        Vault(path).open_with_timelock()


def test_tampered_puzzle_fails_closed(vault):
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    raw = json.loads(vault._path.read_text())
    for slot in raw["keyslots"]:
        if slot["type"] == "timelock":
            n = int(slot["puzzle"]["n"], 16)
            slot["puzzle"]["n"] = format(n + 2, "x")   # another N
    vault._path.write_text(json.dumps(raw))
    with pytest.raises(VaultAuthError):
        vault.open_with_timelock()


# Agent integration behavior.

def test_agent_timelock_recovery_reads_everything(tmp_path):
    """End-to-end flow: the owner configures a time-lock; later, without a
    passphrase or custodians, the puzzle is solved and the encrypted legacy is read."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "t.txt"
    src.write_text("will inheritance notary zzyzx", encoding="utf-8")
    a.ingest(src)
    a.encrypt_database("pw")
    a.add_timelock("pw", T, modulus_bits=1024)
    a.lock("pw")

    rec = LegacyAgent(tmp_path / "data", "anna")
    rec.recover_with_timelock(actor="olga")            # without a passphrase
    assert rec._index.owner_id == "anna"
    assert len(rec.query("will inheritance", actor="olga")) >= 1   # encrypted memory is readable
    assert "VAULT_RECOVERED_TIMELOCK" in [
        e["event_type"] for e in rec._audit.events()
    ]


def test_agent_timelock_survives_rekey(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("old")
    a.add_timelock("old", T, modulus_bits=1024)
    a.lock("old")

    b = LegacyAgent(tmp_path / "data", "anna")
    b.rekey("old", "new")
    b.lock("new")

    rec = LegacyAgent(tmp_path / "data", "anna")
    rec.recover_with_timelock(actor="olga")
    assert rec._index.owner_id == "anna"


def test_agent_set_passphrase_from_timelock(tmp_path):
    """The heirs take possession by solving the puzzle once and setting their
    own passphrase; the old one is replaced."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("old")
    a.add_timelock("old", T, modulus_bits=1024)
    a.lock("old")

    heir = LegacyAgent(tmp_path / "data", "anna")
    heir.set_passphrase_from_timelock("inherited", actor="olga")
    assert heir._index.owner_id == "anna"

    final = LegacyAgent(tmp_path / "data", "anna")
    final.open_owner("inherited")                      # the new one opens
    with pytest.raises(VaultAuthError):
        LegacyAgent(tmp_path / "data", "anna").open_owner("old")  # the old fails


def test_agent_remove_timelock(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    a.add_timelock("pw", T, modulus_bits=1024)
    assert a.remove_timelock("pw") is True
    a.lock("pw")
    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        rec.recover_with_timelock(actor="x")
