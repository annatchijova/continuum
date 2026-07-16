"""
tests/test_shamir.py
=====================
Shamir Secret Sharing: mathematical properties and share format.
"""
from __future__ import annotations

import itertools
import secrets as _secrets

import pytest

from legacy.core.shamir import (
    Share,
    ShamirError,
    combine_shares,
    split_secret,
    _mul, _div, _EXP, _LOG,
)


# Implementation note.
# Implementation note.
# Implementation note.

def test_gf_multiplication_agrees_with_schoolbook():
    """the tablas exp/log deben match with the multiplicacion polinomial
    directa module 0x11B for all the pares (exhaustivo, 64k casos)."""
    def slow_mul(a: int, b: int) -> int:
        r = 0
        while b:
            if b & 1:
                r ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return r

    for a in range(256):
        for b in range(256):
            assert _mul(a, b) == slow_mul(a, b), (a, b)


def test_gf_division_inverts_multiplication():
    for a in range(1, 256):
        for b in range(1, 256):
            assert _div(_mul(a, b), b) == a


def test_gf_div_by_zero_raises():
    with pytest.raises(ZeroDivisionError):
        _div(5, 0)


# Implementation note.
# Implementation note.
# Implementation note.

def test_roundtrip_basic():
    secret = _secrets.token_bytes(32)
    shares = split_secret(secret, shares=5, threshold=3)
    assert len(shares) == 5
    assert combine_shares(shares[:3]) == secret


def test_any_k_of_n_subset_reconstructs():
    secret = _secrets.token_bytes(16)
    shares = split_secret(secret, shares=5, threshold=3)
    for subset in itertools.combinations(shares, 3):
        assert combine_shares(list(subset)) == secret


def test_more_than_k_shares_also_work():
    secret = _secrets.token_bytes(16)
    shares = split_secret(secret, shares=5, threshold=3)
    assert combine_shares(shares) == secret


def test_k_minus_one_shares_fail():
    secret = _secrets.token_bytes(16)
    shares = split_secret(secret, shares=5, threshold=3)
    with pytest.raises(ShamirError, match="Missing shares"):
        combine_shares(shares[:2])


def test_threshold_one_and_equal_to_n():
    secret = b"top secret material"
    [s] = split_secret(secret, shares=1, threshold=1)
    assert combine_shares([s]) == secret
    shares = split_secret(secret, shares=4, threshold=4)
    assert combine_shares(shares) == secret
    with pytest.raises(ShamirError):
        combine_shares(shares[:3])


def test_invalid_parameters():
    with pytest.raises(ShamirError):
        split_secret(b"", shares=3, threshold=2)
    with pytest.raises(ShamirError):
        split_secret(b"x", shares=2, threshold=3)      # k > n
    with pytest.raises(ShamirError):
        split_secret(b"x", shares=256, threshold=2)    # n > 255
    with pytest.raises(ShamirError):
        split_secret(b"x", shares=3, threshold=0)


def test_two_splits_produce_incompatible_shares():
    """Shares of repartos distintos of the same secreto no deben mezclarse
    in silencio: the polinomios are distintos and the mezcla reconstruye
    basura  the digest it detects."""
    secret = _secrets.token_bytes(8)
    a = split_secret(secret, shares=3, threshold=2)
    b = split_secret(secret, shares=3, threshold=2)
    # Implementation note.
    # Implementation note.
    with pytest.raises(ShamirError, match="verification failed"):
        combine_shares([a[0], b[1]])


def test_tampered_share_detected():
    secret = _secrets.token_bytes(8)
    shares = split_secret(secret, shares=3, threshold=2)
    bad = Share(
        x=shares[0].x, threshold=2, total=3, digest=shares[0].digest,
        data=bytes(b ^ 0xFF for b in shares[0].data),
    )
    with pytest.raises(ShamirError, match="verification failed"):
        combine_shares([bad, shares[1]])


def test_duplicate_share_rejected():
    secret = _secrets.token_bytes(8)
    shares = split_secret(secret, shares=3, threshold=2)
    with pytest.raises(ShamirError, match="Duplicate shares"):
        combine_shares([shares[0], shares[0]])


def test_shares_leak_nothing_individually():
    """a share only no determina the secreto: dos secretos distintos
    can producir shares with the same abscisa and data of igual longitud.
    (Sanity of forma, no prueba criptografica  the garantia is matematica.)"""
    s1 = split_secret(b"\x00" * 16, shares=3, threshold=2)[0]
    s2 = split_secret(b"\xff" * 16, shares=3, threshold=2)[0]
    assert len(s1.data) == len(s2.data)
    assert s1.data != bytes(16)  # the share NO is the secreto in plaintext


# Implementation note.
# Implementation note.
# Implementation note.

def test_serialization_roundtrip():
    secret = _secrets.token_bytes(32)
    shares = split_secret(secret, shares=5, threshold=3)
    texts = [s.serialize() for s in shares]
    assert all(t.startswith("dlshare-v1:") and "\n" not in t for t in texts)
    assert combine_shares(texts[:3]) == secret          # acepta strings


def test_deserialize_garbage_raises():
    with pytest.raises(ShamirError):
        Share.deserialize("no-is-a-share")
    with pytest.raises(ShamirError):
        Share.deserialize("dlshare-v1:!!!invalid-base64!!!")


def test_serialized_share_tamper_detected():
    secret = _secrets.token_bytes(8)
    shares = split_secret(secret, shares=3, threshold=2)
    text = shares[0].serialize()
    # Implementation note.
    with pytest.raises(ShamirError):
        Share.deserialize(text[: len(text) // 2])
