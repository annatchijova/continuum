"""
tests/test_timelock_vault.py
=============================
Integracion of the time-lock puzzle as keyslot of the vault and in the agente
(componente offline of KL-011). T pequeno  fast.

Invariante central: the vault is can open resolviendo the puzzle, without the
passphrase ni custodios; and the slot is INDEPENDIENTE (no rompe the demas,
sobrevive to the rekey as the resto of keyslots v2).
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


# Implementation note.
# Implementation note.
# Implementation note.

def test_open_with_timelock(vault):
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.has_timelock_slot()
    assert vault.timelock_info()["squarings"] == T
    assert vault.open_with_timelock() == DATA          # without a passphrase


def test_timelock_slot_is_independent(vault):
    """Agregar time-lock no rompe the passphrase; ambos abren the same payload."""
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.open(PASS) == DATA
    assert vault.open_with_timelock() == DATA


def test_timelock_survives_rekey(vault):
    """the slot time-lock sobrevive to the rewrap of passphrase (keyslot v2)."""
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    vault.rewrap_passphrase(PASS, "new")
    assert vault.open("new") == DATA
    assert vault.open_with_timelock() == DATA          # sigue valid


def test_timelock_coexists_with_recovery(vault):
    import secrets
    rk = secrets.token_bytes(32)
    vault.add_recovery_slot(PASS, rk)
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.open(PASS) == DATA
    assert vault.open_with_recovery(rk) == DATA
    assert vault.open_with_timelock() == DATA          # tres caminos independientes


def test_remove_timelock(vault):
    vault.add_timelock_slot(PASS, T, modulus_bits=1024)
    assert vault.remove_timelock_slot(PASS) is True
    assert not vault.has_timelock_slot()
    with pytest.raises(VaultAuthError):
        vault.open_with_timelock()
    assert vault.remove_timelock_slot(PASS) is False


def test_open_with_timelock_without_slot_raises(vault):
    """a vault v2 without slot time-lock configurado no opens by esa via."""
    assert not vault.has_timelock_slot()
    with pytest.raises(VaultAuthError):
        vault.open_with_timelock()


def test_open_with_timelock_on_v1_raises(tmp_path):
    """over a envelope v1 (formato original) the via time-lock avisa that is v1."""
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


# Implementation note.
# Implementation note.
# Implementation note.

def test_agent_timelock_recovery_reads_everything(tmp_path):
    """Flujo real: owner configura time-lock; more tarde, without a passphrase ni
    custodios, is resuelve the puzzle and is reads the legado (incl. memory encrypted)."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    src = tmp_path / "t.txt"
    src.write_text("testamento herencia notario zzyzx", encoding="utf-8")
    a.ingest(src)
    a.encrypt_database("pw")
    a.add_timelock("pw", T, modulus_bits=1024)
    a.lock("pw")

    rec = LegacyAgent(tmp_path / "data", "anna")
    rec.recover_with_timelock(actor="olga")            # without a passphrase
    assert rec._index.owner_id == "anna"
    assert len(rec.query("testamento herencia", actor="olga")) >= 1   # memory encrypted legible
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
    """the heirs toman posesion: resuelven the puzzle once and fijan su
    propia passphrase; the old remains reemplazada."""
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("old")
    a.add_timelock("old", T, modulus_bits=1024)
    a.lock("old")

    heir = LegacyAgent(tmp_path / "data", "anna")
    heir.set_passphrase_from_timelock("heredada", actor="olga")
    assert heir._index.owner_id == "anna"

    final = LegacyAgent(tmp_path / "data", "anna")
    final.open_owner("heredada")                       # the new opens
    with pytest.raises(VaultAuthError):
        LegacyAgent(tmp_path / "data", "anna").open_owner("old")  # the old no


def test_agent_remove_timelock(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize("pw")
    a.add_timelock("pw", T, modulus_bits=1024)
    assert a.remove_timelock("pw") is True
    a.lock("pw")
    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        rec.recover_with_timelock(actor="x")
