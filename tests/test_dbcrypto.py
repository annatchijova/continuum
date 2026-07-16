"""
tests/test_dbcrypto.py
=======================
FieldCipher: encrypted of field with AAD and coexistencia plaintext/ciphertext.
"""
from __future__ import annotations

import secrets

import pytest

from legacy.core.dbcrypto import (
    FieldCipher,
    FieldCryptoError,
    FIELD_PREFIX,
    is_encrypted,
)

KEY = secrets.token_bytes(32)
AAD = "mem-123:content"


@pytest.fixture
def cipher():
    return FieldCipher(KEY)


# Field encryption and authentication behavior.

def test_roundtrip(cipher):
    for text in ["will before the notary", "", "    ", "x" * 10000]:
        token = cipher.encrypt_field(text, AAD)
        assert is_encrypted(token)
        assert token.startswith(FIELD_PREFIX)
        assert cipher.decrypt_field(token, AAD) == text


def test_ciphertext_hides_plaintext(cipher):
    token = cipher.encrypt_field("SECRET-IN-PLAINTEXT", AAD)
    assert "SECRET" not in token


def test_nonce_is_random(cipher):
    a = cipher.encrypt_field("same text", AAD)
    b = cipher.encrypt_field("same text", AAD)
    assert a != b                                # fresh nonce for the same value
    assert cipher.decrypt_field(a, AAD) == cipher.decrypt_field(b, AAD)


# Associated-data binding.

def test_wrong_aad_fails(cipher):
    token = cipher.encrypt_field("value", "mem-1:content")
    with pytest.raises(FieldCryptoError):
        cipher.decrypt_field(token, "mem-2:content")     # value moved to another row
    with pytest.raises(FieldCryptoError):
        cipher.decrypt_field(token, "mem-1:tags")        # movido of column


def test_wrong_key_fails():
    token = FieldCipher(KEY).encrypt_field("dato", AAD)
    with pytest.raises(FieldCryptoError):
        FieldCipher(secrets.token_bytes(32)).decrypt_field(token, AAD)


def test_tampered_token_fails(cipher):
    token = cipher.encrypt_field("dato", AAD)
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    with pytest.raises(FieldCryptoError):
        cipher.decrypt_field(tampered, AAD)


# Tamper detection and plaintext escaping.

def test_decrypt_passes_through_plaintext(cipher):
    """A partially migrated database reads plaintext values unchanged."""
    assert cipher.decrypt_field("plaintext value", AAD) == "plaintext value"
    assert not is_encrypted("plaintext value")


def test_encrypt_always_encrypts_even_prefix_like_plaintext(cipher):
    """FIX R5-001: encrypt_field encrypts su entry aunque the plaintext starts
    with the prefijo of ciphertext  no adivina if 'already parece encrypted'."""
    prefixy = FIELD_PREFIX + "esto is text real, no a token"
    token = cipher.encrypt_field(prefixy, AAD)
    assert token != prefixy
    assert cipher.decrypt_field(token, AAD) == prefixy      # roundtrip exacto


def test_maybe_decrypt(cipher):
    assert cipher.maybe_decrypt(None, AAD) is None
    assert cipher.maybe_decrypt("claro", AAD) == "claro"
    token = cipher.encrypt_field("encrypted", AAD)
    assert cipher.maybe_decrypt(token, AAD) == "encrypted"


# Key validation.

def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        FieldCipher(b"corta")
    with pytest.raises(ValueError):
        FieldCipher(secrets.token_bytes(31))


def test_is_encrypted_edge_cases():
    assert not is_encrypted(None)
    assert not is_encrypted("")
    assert not is_encrypted("gcmf1")            # prefijo incompleto
    assert is_encrypted(FIELD_PREFIX + "abc")
