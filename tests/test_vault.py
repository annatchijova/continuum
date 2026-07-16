"""
tests/test_vault.py
====================
Tests of the vault AES-256-GCM.
"""
import json
import pytest
from pathlib import Path

from legacy.vault.locker import (
    Vault,
    VaultAuthError,
    VaultCorruptError,
    VaultNotFoundError,
)
from legacy.vault.conditions import (
    AccessPolicy,
    ConditionOperator,
    DateCondition,
    HeirKeyCondition,
    InactivityCondition,
    ManualCondition,
    condition_from_dict,
)
from datetime import datetime, timezone, timedelta


@pytest.fixture
def tmp_vault(tmp_path):
    return Vault(tmp_path / "test.vault")


# Basic vault behavior.

def test_seal_and_open(tmp_vault):
    data = {"name": "Ana", "documents": ["doc1.pdf", "doc2.pdf"]}
    tmp_vault.seal(data, passphrase="s3cr3t!")
    recovered = tmp_vault.open("s3cr3t!")
    assert recovered == data


def test_wrong_passphrase_raises(tmp_vault):
    tmp_vault.seal({"k": "v"}, passphrase="correct")
    with pytest.raises(VaultAuthError):
        tmp_vault.open("wrong")


def test_not_found_raises(tmp_vault):
    with pytest.raises(VaultNotFoundError):
        tmp_vault.open("any")


def test_vault_not_exists_initially(tmp_vault):
    assert not tmp_vault.exists()


def test_vault_exists_after_seal(tmp_vault):
    tmp_vault.seal({}, passphrase="x")
    assert tmp_vault.exists()


def test_envelope_hash_matches(tmp_vault):
    import hashlib
    data = {"test": True}
    tmp_vault.seal(data, passphrase="p")
    plaintext = json.dumps(data, sort_keys=True, ensure_ascii=True).encode()
    expected = hashlib.sha256(plaintext).hexdigest()
    assert tmp_vault.envelope_hash() == expected


def test_corrupt_envelope_raises(tmp_vault):
    tmp_vault.seal({"k": "v"}, passphrase="p")
    # Alter the ciphertext in the envelope.
    raw = json.loads(tmp_vault._path.read_text())
    raw["ciphertext"] = "deadbeef"
    tmp_vault._path.write_text(json.dumps(raw))
    with pytest.raises((VaultAuthError, VaultCorruptError)):
        tmp_vault.open("p")


def test_overwrites_on_reseal(tmp_vault):
    tmp_vault.seal({"v": 1}, passphrase="p")
    tmp_vault.seal({"v": 2}, passphrase="p")
    recovered = tmp_vault.open("p")
    assert recovered["v"] == 2


def test_unicode_data(tmp_vault):
    data = {"mensaje": "Hola, , ", "emoji": ""}
    tmp_vault.seal(data, passphrase="unicode_test")
    recovered = tmp_vault.open("unicode_test")
    assert recovered == data


# Access-policy conditions.

def test_inactivity_condition_not_met():
    now = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    last = datetime(2026, 7, 5, 12, 0, tzinfo=timezone.utc)  # one day
    cond = InactivityCondition(days=30, last_activity_iso=last.isoformat())
    assert not cond.is_met(now=now)


def test_inactivity_condition_met():
    now = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    last = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)  # about 62 days
    cond = InactivityCondition(days=30, last_activity_iso=last.isoformat())
    assert cond.is_met(now=now)


def test_date_condition_not_met():
    future = datetime(2030, 1, 1, tzinfo=timezone.utc)
    cond = DateCondition(unlock_after_iso=future.isoformat())
    assert not cond.is_met()


def test_date_condition_met():
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    cond = DateCondition(unlock_after_iso=past.isoformat())
    assert cond.is_met()


def test_heir_key_condition():
    cond = HeirKeyCondition.create("heir_1", "my_secret_key")
    assert cond.is_met("my_secret_key")
    assert not cond.is_met("incorrect_key")


def test_heir_key_constant_time():
    """Constant-time verification uses compare_digest, not ==."""
    cond = HeirKeyCondition.create("h1", "abc")
    # Inputs of different lengths must also be rejected safely.
    assert not cond.is_met("")
    assert not cond.is_met("a" * 1000)


def test_manual_condition():
    cond = ManualCondition()
    assert not cond.is_met()
    cond.activate()
    assert cond.is_met()


def test_policy_and_operator():
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    manual = ManualCondition(activated=True)
    date_cond = DateCondition(unlock_after_iso=past.isoformat())
    policy = AccessPolicy([manual, date_cond], operator=ConditionOperator.AND)
    assert policy.evaluate()


def test_policy_and_fails_if_one_fails():
    future = datetime(2030, 1, 1, tzinfo=timezone.utc)
    manual = ManualCondition(activated=True)
    date_cond = DateCondition(unlock_after_iso=future.isoformat())
    policy = AccessPolicy([manual, date_cond], operator=ConditionOperator.AND)
    assert not policy.evaluate()


def test_policy_or_passes_if_one_passes():
    future = datetime(2030, 1, 1, tzinfo=timezone.utc)
    manual = ManualCondition(activated=True)
    date_cond = DateCondition(unlock_after_iso=future.isoformat())
    policy = AccessPolicy([manual, date_cond], operator=ConditionOperator.OR)
    assert policy.evaluate()


def test_policy_serialization_roundtrip():
    cond = HeirKeyCondition.create("h1", "key")
    policy = AccessPolicy([cond], operator=ConditionOperator.AND)
    d = policy.to_dict()
    restored = AccessPolicy.from_dict(d)
    assert restored.evaluate(heir_key="key")
    assert not restored.evaluate(heir_key="incorrect")
