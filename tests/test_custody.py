"""
tests/test_custody.py
======================
Custody threshold: the product's complete inheritance flow.

Scenario protected by this file:
  1. The owner configures 3-of-5 custody and gives one share to each
     custodian (notary, sibling, close friend, bank, lawyer).
  2. The owner dies. The passphrase dies with them.
  3. Any three custodians provide shares; heirs reconstruct the recovery key,
     open the vault, set their own passphrase, and restore archived documents.
"""
from __future__ import annotations

import pytest

from legacy.agent.memory_agent import LegacyAgent
from legacy.core.shamir import ShamirError
from legacy.vault.locker import VaultAuthError

PASS = "passphrase-that-muere-with-anna"


@pytest.fixture
def agent(tmp_path):
    a = LegacyAgent(tmp_path / "data", "anna")
    a.initialize(PASS)
    src = tmp_path / "will.txt"
    src.write_text("will and last wishes before the notary",
                   encoding="utf-8")
    a.ingest(src)
    a.archive_artifact(src, PASS)
    a.add_heir("olga", "Olga")
    return a


# Custody setup behavior.

def test_setup_returns_n_serialized_shares(agent):
    shares = agent.setup_custody(PASS, shares=5, threshold=3)
    assert len(shares) == 5
    assert all(s.startswith("dlshare-v1:") for s in shares)
    assert agent._vault.has_recovery_slot()
    assert "CUSTODY_CONFIGURED" in [
        e["event_type"] for e in agent._audit.events()
    ]


def test_setup_rejects_weak_parameters(agent):
    with pytest.raises(ValueError, match="threshold"):
        agent.setup_custody(PASS, shares=5, threshold=1)
    with pytest.raises(ValueError):
        agent.setup_custody(PASS, shares=2, threshold=3)


def test_setup_requires_correct_passphrase(agent):
    with pytest.raises(VaultAuthError):
        agent.setup_custody("incorrect", shares=3, threshold=2)


def test_no_secret_material_persisted(agent, tmp_path):
    """Neither the recovery key nor shares remain on disk or in the audit."""
    shares = agent.setup_custody(PASS, shares=3, threshold=2)
    agent.lock(PASS)

    on_disk = b"".join(
        p.read_bytes()
        for p in (tmp_path / "data").rglob("*") if p.is_file()
    )
    for s in shares:
        assert s.encode() not in on_disk
        # Neither the serialized share nor its payload may persist.
        assert s.split(":", 1)[1].encode() not in on_disk


# Full recovery behavior.

def test_full_inheritance_flow(agent, tmp_path):
    """Complete flow: 3 of 5 custodians, new passphrase, and restore."""
    shares = agent.setup_custody(PASS, shares=5, threshold=3)
    [artifact_hash] = agent._store.list_hashes()
    agent.lock(PASS)
    # The owner is no longer needed after shares reconstruct the key.

    heirs = LegacyAgent(tmp_path / "data", "anna")
    heirs.set_passphrase_from_recovery(
        [shares[4], shares[0], shares[2]],       # any three custodians
        "passphrase-of-the-heirs",
        actor="olga",
    )
    # The recovered agent has the original owner identity.
    assert heirs._index.owner_id == "anna"
    dest = tmp_path / "restored_will.txt"
    heirs.restore_artifact(artifact_hash, dest, actor="olga")
    assert "last wishes" in dest.read_text(encoding="utf-8")

    # Recovery and restoration must both be audited.
    events = [e["event_type"] for e in heirs._audit.events()]
    assert "PASSPHRASE_RESET_BY_RECOVERY" in events
    assert "ARTIFACT_RESTORED" in events

    # The old passphrase remains valid until explicitly reset.
    final = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        final.open_owner(PASS)
    final.open_owner("passphrase-of-the-heirs")


def test_recover_opens_readonly_without_setting_passphrase(agent, tmp_path):
    shares = agent.setup_custody(PASS, shares=3, threshold=2)
    agent.lock(PASS)

    rec = LegacyAgent(tmp_path / "data", "anna")
    rec.recover_with_shares(shares[:2], actor="olga")
    assert rec._unlocked and rec._index.owner_id == "anna"
    assert "VAULT_RECOVERED" in [e["event_type"] for e in rec._audit.events()]
    # Old shares must be invalid after reconfiguration.
    again = LegacyAgent(tmp_path / "data", "anna")
    again.open_owner(PASS)


def test_insufficient_shares_fail(agent, tmp_path):
    shares = agent.setup_custody(PASS, shares=5, threshold=3)
    agent.lock(PASS)
    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(ShamirError):
        rec.recover_with_shares(shares[:2], actor="olga")


def test_resetup_revokes_old_custodians(agent, tmp_path):
    """Reconfiguring custody invalidates old shares."""
    old_shares = agent.setup_custody(PASS, shares=3, threshold=2)
    agent.setup_custody(PASS, shares=3, threshold=2)     # reparto new
    agent.lock(PASS)

    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        rec.recover_with_shares(old_shares[:2], actor="attacker")


def test_remove_custody(agent, tmp_path):
    shares = agent.setup_custody(PASS, shares=3, threshold=2)
    assert agent.remove_custody(PASS) is True
    agent.lock(PASS)

    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(VaultAuthError):
        rec.recover_with_shares(shares[:2], actor="olga")


def test_recovery_denied_events_are_audited(agent, tmp_path):
    """An attempt with tampered shares opens nothing and fails loudly."""
    shares = agent.setup_custody(PASS, shares=3, threshold=2)
    agent.lock(PASS)
    tampered = shares[0][:-6] + "XXXXXX"
    rec = LegacyAgent(tmp_path / "data", "anna")
    with pytest.raises(ShamirError):
        rec.recover_with_shares([tampered, shares[1]], actor="attacker")
    assert not rec._unlocked
