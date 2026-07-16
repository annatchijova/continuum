"""
tests/test_hash_chain.py
=========================
Tests of the hash chain  verificacion, deteccion of manipulacion,
HMAC dual layer, and casos of borde.
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


# Implementation note.
# Implementation note.
# Implementation note.

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
    # Implementation note.
    h_int = canonical_hash({"v": 1})
    h_bool = canonical_hash({"v": True})
    assert h_int != h_bool


# Implementation note.
# Implementation note.
# Implementation note.

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


# Implementation note.
# Implementation note.
# Implementation note.

def test_tampered_content_detected():
    links = _build_chain(3)
    # Implementation note.
    original = links[1]
    tampered_payload = {**original.payload, "data": 9999}
    links[1] = ChainLink(
        seq=original.seq,
        prev_hash=original.prev_hash,
        entry_hash=original.entry_hash,   # hash old, payload new  detectable
        payload=tampered_payload,
        entry_hmac=original.entry_hmac,
    )
    result = verify_chain(links)
    assert not result.valid
    assert result.first_invalid_seq == 2
    assert len(result.tampered_content) >= 1


def test_deleted_link_detected():
    links = _build_chain(5)
    # Implementation note.
    reduced = [l for l in links if l.seq != 3]
    result = verify_chain(reduced)
    assert not result.valid
    assert len(result.seq_discontinuities) >= 1
    assert len(result.broken_links) >= 1


def test_inserted_link_detected():
    links = _build_chain(3)
    # Implementation note.
    fake = build_link(2, links[0].entry_hash, {"event": "injected"})
    # Implementation note.
    mixed = [links[0], fake, links[1], links[2]]
    result = verify_chain(mixed)
    assert not result.valid


def test_broken_linkage_detected():
    links = _build_chain(3)
    original = links[2]
    # Implementation note.
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
    a attacker that recomputa toda the chain without HMAC no is detectable
    by SHA-256 only. Documentado and esperado.
    """
    links = _build_chain(3)
    # Implementation note.
    new_links = []
    prev = GENESIS_HASH
    for i, link in enumerate(links):
        tampered_payload = {**link.payload, "data": 9999}
        new_link = build_link(i + 1, prev, tampered_payload)
        new_links.append(new_link)
        prev = new_link.entry_hash
    # Implementation note.
    result = verify_chain(new_links)
    assert result.valid


def test_recomputed_chain_with_hmac_fails():
    """
    with HMAC, the attacker no can recomputar the entry_hmac without the key.
    """
    key = b"secret_key_32bytes_padded_xxxxxx"
    links = _build_chain(3, hmac_key=key)

    # Implementation note.
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


# Implementation note.
# Implementation note.
# Implementation note.

def test_accumulates_all_errors():
    """verify_chain no is detiene in the primer error  reporta all."""
    links = _build_chain(5)

    # Implementation note.
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
    # Implementation note.
    assert len(result.tampered_content) >= 2


# Implementation note.
# Implementation note.
# Implementation note.

def test_hmac_absent_flagged():
    """link without entry_hmac when is verifica with key  ruling HMAC."""
    key = b"k" * 32
    links = _build_chain(3)  # construido without HMAC
    result = verify_chain(links, hmac_key=key)
    assert not result.valid
    assert len(result.hmac_failures) == 3
