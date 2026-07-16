"""
tests/test_hash_chain.py
=========================
Hash-chain verification, tamper detection, dual-layer HMAC, and edge cases.
"""
import pytest
from legacy.core.hash_chain import (
    GENESIS_HASH,
    ChainLink,
    build_link,
    canonical_hash,
    compute_entry_hash,
    compute_entry_hmac,
    verify_chain,
)


# Canonical hashing behavior.

def test_canonical_hash_deterministic():
    payload = {"a": 1, "b": "hello", "c": True, "d": None}
    h1 = canonical_hash(payload)
    h2 = canonical_hash(payload)
    assert h1 == h2


def test_canonical_hash_key_order_independent():
    h1 = canonical_hash({"x": 1, "and": 2})
    h2 = canonical_hash({"and": 2, "x": 1})
    assert h1 == h2


def test_canonical_hash_type_sensitive():
    # Integer and boolean values must remain type-sensitive.
    h_int = canonical_hash({"v": 1})
    h_bool = canonical_hash({"v": True})
    assert h_int != h_bool


# Chain construction and verification.

def _build_chain(n: int, hmac_key=None):
    links = []
    prev = GENESIS_HASH
    for i in range(1, n + 1):
        payload = {"event": f"event_{i}", "data": i}
        link = build_link(i, prev, payload, hmac_key)
        links.append(link)
        prev = link.entry_hash
    return links


def test_valid_chain():
    links = _build_chain(5)
    result = verify_chain(links)
    assert result.valid
    assert result.length == 5
    assert result.first_invalid_seq is None


def test_valid_chain_with_hmac():
    key = b"a" * 32
    links = _build_chain(5, hmac_key=key)
    result = verify_chain(links, hmac_key=key)
    assert result.valid
    assert result.hmac_checked


def test_empty_chain():
    result = verify_chain([])
    assert result.valid
    assert result.length == 0


# Tamper and structural failure detection.

def test_tampered_content_detected():
    links = _build_chain(3)
    # Change payload while retaining the old entry hash.
    original = links[1]
    tampered_payload = {**original.payload, "data": 9999}
    links[1] = ChainLink(
        seq=original.seq,
        prev_hash=original.prev_hash,
        entry_hash=original.entry_hash,   # old hash with new payload
        payload=tampered_payload,
        entry_hmac=original.entry_hmac,
    )
    result = verify_chain(links)
    assert not result.valid
    assert result.first_invalid_seq == 2
    assert len(result.tampered_content) >= 1


def test_deleted_link_detected():
    links = _build_chain(5)
    # Remove one link from the sequence.
    reduced = [l for l in links if l.seq != 3]
    result = verify_chain(reduced)
    assert not result.valid
    assert len(result.seq_discontinuities) >= 1
    assert len(result.broken_links) >= 1


def test_inserted_link_detected():
    links = _build_chain(3)
    # Insert a forged link into the sequence.
    fake = build_link(2, links[0].entry_hash, {"event": "injected"})
    # The sequence now contains a forged link.
    mixed = [links[0], fake, links[1], links[2]]
    result = verify_chain(mixed)
    assert not result.valid


def test_broken_linkage_detected():
    links = _build_chain(3)
    original = links[2]
    # Break the previous-hash linkage.
    links[2] = ChainLink(
        seq=original.seq,
        prev_hash="0" * 64,   # prev_hash incorrect
        entry_hash=original.entry_hash,
        payload=original.payload,
    )
    result = verify_chain(links)
    assert not result.valid
    assert len(result.broken_links) >= 1


def test_recomputed_chain_without_hmac_passes():
    """
    An attacker who recomputes the entire chain without HMAC is not detectable
    with SHA-256 alone. This is documented and expected.
    """
    links = _build_chain(3)
    # Recompute every link with modified content.
    new_links = []
    prev = GENESIS_HASH
    for i, link in enumerate(links):
        tampered_payload = {**link.payload, "data": 9999}
        new_link = build_link(i + 1, prev, tampered_payload)
        new_links.append(new_link)
        prev = new_link.entry_hash
    # A freshly recomputed unsigned chain is internally valid.
    result = verify_chain(new_links)
    assert result.valid


def test_recomputed_chain_with_hmac_fails():
    """
    With HMAC, an attacker cannot recompute entry_hmac without the key.
    """
    key = b"secret_key_32bytes_padded_xxxxxx"
    links = _build_chain(3, hmac_key=key)

    # Recompute links without the HMAC key.
    new_links = []
    prev = GENESIS_HASH
    for i, link in enumerate(links):
        tampered_payload = {**link.payload, "data": 9999}
        new_link = build_link(i + 1, prev, tampered_payload)  # without key
        new_links.append(new_link)
        prev = new_link.entry_hash

    result = verify_chain(new_links, hmac_key=key)
    assert not result.valid
    assert result.hmac_checked
    assert len(result.hmac_failures) >= 1


# Error accumulation behavior.

def test_accumulates_all_errors():
    """verify_chain must report all errors instead of stopping at the first."""
    links = _build_chain(5)

    # Tamper with multiple links.
    for i in [1, 3]:  # indices 0-based
        original = links[i]
        tampered_payload = {**original.payload, "data": -1}
        links[i] = ChainLink(
            seq=original.seq,
            prev_hash=original.prev_hash,
            entry_hash=original.entry_hash,
            payload=tampered_payload,
        )

    result = verify_chain(links)
    assert not result.valid
    # Both tampered links must be reported.
    assert len(result.tampered_content) >= 2


# Missing-HMAC behavior.

def test_hmac_absent_flagged():
    """A link without entry_hmac fails verification when an HMAC key is supplied."""
    key = b"k" * 32
    links = _build_chain(3)  # construido without HMAC
    result = verify_chain(links, hmac_key=key)
    assert not result.valid
    assert len(result.hmac_failures) == 3
