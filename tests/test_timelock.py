"""
tests/test_timelock.py
=======================
Time-lock puzzle RSW96 (legacy/core/timelock.py)  the componente realizable
of KL-011.

all the tests usan T pequeno (sub-segundo). Defienden: correctitud of the
roundtrip, the piso of trabajo secuencial (the atajo no must existir without ),
fail-closed ante manipulacion, and the bounds of entry.
"""
from __future__ import annotations

import secrets

import pytest

from legacy.core.timelock import (
    TimeLockError,
    _is_probable_prime,
    calibrate,
    create_puzzle,
    estimate_squarings,
    solve_puzzle,
)

SECRET = secrets.token_bytes(32)


# Implementation note.
# Implementation note.
# Implementation note.

@pytest.mark.parametrize("T", [1, 2, 1000, 20_000])
def test_roundtrip(T):
    puz = create_puzzle(SECRET, T, modulus_bits=1024)
    assert solve_puzzle(puz) == SECRET


def test_secret_not_in_puzzle_plaintext(tmp_path):
    puz = create_puzzle(b"SECRETO-in-CLARO-NO-must-APARECER", 500, modulus_bits=1024)
    blob = repr(puz).encode()
    assert b"SECRETO-in-CLARO" not in blob


def test_puzzle_discards_factorization():
    """the puzzle serializado NO contiene p, q ni  (the atajo is descarta)."""
    puz = create_puzzle(SECRET, 100, modulus_bits=1024)
    assert set(puz.keys()) == {
        "version", "modulus_bits", "squarings", "n", "a", "nonce", "ciphertext"
    }


def test_serializable_json_roundtrip():
    import json
    puz = create_puzzle(SECRET, 500, modulus_bits=1024)
    reparsed = json.loads(json.dumps(puz))
    assert solve_puzzle(reparsed) == SECRET


# Implementation note.
# Implementation note.
# Implementation note.

def test_more_squarings_costs_more_time():
    """the tiempo of resolucion crece with T (no hay atajo publico)."""
    import time
    small = create_puzzle(SECRET, 5_000, modulus_bits=2048)
    big = create_puzzle(SECRET, 200_000, modulus_bits=2048)
    t0 = time.time(); solve_puzzle(small); t_small = time.time() - t0
    t0 = time.time(); solve_puzzle(big); t_big = time.time() - t0
    assert t_big > t_small * 5      # ~40x more trabajo  claramente more slow


def test_setup_is_fast_regardless_of_T():
    """Setup O(log T): crear a puzzle of T enorme is instantaneo (the cost
    is in resolverlo, no in crearlo)."""
    import time
    t0 = time.time()
    create_puzzle(SECRET, 10 ** 12, modulus_bits=1024)   # no it resolvemos
    assert time.time() - t0 < 2.0


# Implementation note.
# Implementation note.
# Implementation note.

def test_tampered_modulus_fails():
    puz = create_puzzle(SECRET, 1000, modulus_bits=1024)
    puz["n"] = format(int(puz["n"], 16) + 2, "x")     # another N  another solucion
    with pytest.raises(TimeLockError):
        solve_puzzle(puz)


def test_tampered_base_fails():
    puz = create_puzzle(SECRET, 1000, modulus_bits=1024)
    puz["a"] = format(int(puz["a"], 16) ^ 0xFF, "x")
    with pytest.raises(TimeLockError):
        solve_puzzle(puz)


def test_tampered_squarings_fails():
    puz = create_puzzle(SECRET, 1000, modulus_bits=1024)
    puz["squarings"] = 999                              # T distinto  another solucion
    with pytest.raises(TimeLockError):
        solve_puzzle(puz)


def test_tampered_ciphertext_fails():
    puz = create_puzzle(SECRET, 500, modulus_bits=1024)
    ct = bytearray.fromhex(puz["ciphertext"]); ct[-1] ^= 0xFF
    puz["ciphertext"] = ct.hex()
    with pytest.raises(TimeLockError):
        solve_puzzle(puz)


def test_garbage_puzzle_fails():
    with pytest.raises(TimeLockError):
        solve_puzzle({"version": "1", "n": "zzz"})
    with pytest.raises(TimeLockError):
        solve_puzzle({"version": "9"})


# Implementation note.
# Implementation note.
# Implementation note.

def test_bounds():
    with pytest.raises(TimeLockError):
        create_puzzle(b"", 100)                        # secreto empty
    with pytest.raises(TimeLockError):
        create_puzzle(SECRET, 0)                       # T < 1
    with pytest.raises(TimeLockError):
        create_puzzle(SECRET, 10 ** 20)                # T > techo
    with pytest.raises(TimeLockError):
        create_puzzle(SECRET, 100, modulus_bits=512)   # module debil


# Implementation note.
# Implementation note.
# Implementation note.

def test_miller_rabin_basic():
    assert _is_probable_prime(2) and _is_probable_prime(97)
    assert not _is_probable_prime(1) and not _is_probable_prime(91)  # 91=713


def test_calibrate_and_estimate():
    rate = calibrate(seconds=0.2, modulus_bits=1024)
    assert rate > 0
    assert estimate_squarings(1.0, rate) == min(86_400 * rate, 10 ** 13)
    with pytest.raises(TimeLockError):
        estimate_squarings(-1, rate)
