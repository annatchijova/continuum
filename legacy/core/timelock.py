"""
legacy/core/timelock.py
========================
Offline time-lock puzzle (RSW96 / LCS35): the REALIZABLE component of KL-011.

This closes one part of KL-011 and NOT the other; that distinction is the core
of this module and must remain explicit:

  WHAT IT PROVIDES (a sequential, cryptographic, offline work floor):
    Recovering the wrapped secret requires >= T SEQUENTIAL modular squarings.
    A squaring chain cannot be parallelized (x_{i+1} = x_i^2 mod N depends on
    x_i), and factoring N is the only shortcut. The factorization (and φ(N))
    is discarded during setup.

  WHAT IT DOES **NOT** PROVIDE (a wall clock):
    It does NOT mean "it opens on 2030-01-01". It means "it costs ~T
    sequential squarings." Wall-clock time = T / the solver's squarings per
    second. Faster hardware (or a squaring ASIC) solves it proportionally
    sooner. Therefore T is chosen against the ADVERSARY'S hardware, not the
    heir's. This is a cost floor, not a date.

Threat model:
  - The attacker can read the puzzle, run arbitrary computation (including
    massive parallel computation), and use faster hardware.
  - The attacker cannot parallelize the squaring chain or factor N to recover
    the discarded shortcut φ(N).

Intended use: an ADDITIONAL independent vault keyslot (opt-in) for the
scenario "no custodians are available, but heirs can open it by spending
computation." It complements the passphrase and Shamir custody; it does not
replace them.

Construction (RSW96):
  N = pq (primes generated with Miller-Rabin); φ = (p-1)(q-1).
  a = random base in [2, N).
  solution = a^(2^T mod φ) mod N       (shortcut: O(log T), requires φ)
           = a squared T times modulo N (no shortcut: T sequential steps)
  key = SHA-256(solution); AES-256-GCM wraps the secret.
  Persist N, T, a, nonce, and ciphertext. Discard p, q, φ, and solution.

Dependencies: stdlib + `cryptography` (AES-GCM). No network or sympy.

Future work (cryptographic wall clock; see KL-011 in KNOWN_LIMITATIONS.md):
this module provides a WORK floor, not a date. A lock tied to an absolute date
would require a temporal trust root that does not exist today by design
(offline, no third parties). Candidates, each moving the trust boundary:
  1. tlock over a drand beacon (timelock encryption): network dependency during
     recovery; the most likely option if an optional network is accepted.
  2. RFC 3161 timestamp authority: a trusted third party.
  3. TEE/HSM with a monotonic clock: hardware dependency.
None is implemented; adopting one is a product decision about accepted
external trust, not a code TODO.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any, Callable, Dict, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

PUZZLE_VERSION = "1"
_AAD = b"legacy-timelock-v1"
_NONCE_LEN = 12
_MIN_MODULUS_BITS = 1024
# Implementation note.
# Implementation note.
# Implementation note.
_MAX_SQUARINGS = 10 ** 13


class TimeLockError(ValueError):
    """Invalid parameters, corrupted puzzle, or incorrect solution."""


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("The 'cryptography' package is required for the time-lock.")


# Implementation note.
# Implementation note.
# Implementation note.

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    """Generate a probable prime with exactly `bits` bits (MSB and LSB set)."""
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def _int_to_bytes(x: int, n_bits: int) -> bytes:
    return x.to_bytes((n_bits + 7) // 8, "big")


def _solution_to_key(solution: int, modulus_bits: int) -> bytes:
    return hashlib.sha256(_int_to_bytes(solution, modulus_bits)).digest()


# Implementation note.
# Implementation note.
# Implementation note.

def create_puzzle(
    secret: bytes,
    squarings: int,
    *,
    modulus_bits: int = 2048,
) -> Dict[str, Any]:
    """
    Wrap `secret` in a time-lock puzzle: it can be recovered only after
    `squarings` sequential squarings (or with the discarded factorization).
    Return a serializable dictionary. Setup is O(log T) and effectively instant.

    Bounds (fail-closed): secret is non-empty; 1 <= squarings <= _MAX_SQUARINGS;
    modulus_bits >= 1024.
    """
    _require_crypto()
    if not secret:
        raise TimeLockError("The secret cannot be empty.")
    if not (1 <= squarings <= _MAX_SQUARINGS):
        raise TimeLockError(
            f"Squarings out of range: 1 <= T <= {_MAX_SQUARINGS} (received {squarings})."
        )
    if modulus_bits < _MIN_MODULUS_BITS:
        raise TimeLockError(
            f"modulus_bits must be >= {_MIN_MODULUS_BITS} (received {modulus_bits})."
        )

    p = _gen_prime(modulus_bits // 2)
    q = _gen_prime(modulus_bits // 2)
    while q == p:
        q = _gen_prime(modulus_bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    a = 2 + secrets.randbelow(n - 3)
    # Implementation note.
    e = pow(2, squarings, phi)
    solution = pow(a, e, n)
    key = _solution_to_key(solution, modulus_bits)

    nonce = secrets.token_bytes(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, secret, _AAD)

    # Implementation note.
    return {
        "version": PUZZLE_VERSION,
        "modulus_bits": modulus_bits,
        "squarings": squarings,
        "n": format(n, "x"),
        "a": format(a, "x"),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def solve_puzzle(
    puzzle: Dict[str, Any],
    *,
    progress: Optional[Callable[[int, int], None]] = None,
    progress_every: int = 1_000_000,
) -> bytes:
    """
    Solve the puzzle: T sequential squarings derive the key that decrypts the
    secret. Slow by design. `progress(done, total)` is called every
    `progress_every` squarings for UX.

    Raise TimeLockError if the puzzle is corrupted or the secret fails
    authentication (fail-closed: tampered N/a/T values produce another
    solution and GCM fails).
    """
    _require_crypto()
    try:
        if puzzle.get("version") != PUZZLE_VERSION:
            raise TimeLockError(f"Unknown puzzle version: {puzzle.get('version')}")
        modulus_bits = int(puzzle["modulus_bits"])
        t = int(puzzle["squarings"])
        n = int(puzzle["n"], 16)
        x = int(puzzle["a"], 16) % n
        nonce = bytes.fromhex(puzzle["nonce"])
        ciphertext = bytes.fromhex(puzzle["ciphertext"])
    except (KeyError, ValueError, TypeError) as exc:
        raise TimeLockError(f"Unreadable or damaged puzzle: {exc}") from exc

    if not (1 <= t <= _MAX_SQUARINGS):
        raise TimeLockError("Puzzle squarings are out of range.")

    for i in range(t):
        x = x * x % n
        if progress is not None and (i + 1) % progress_every == 0:
            progress(i + 1, t)

    key = _solution_to_key(x, modulus_bits)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _AAD)
    except Exception as exc:
        raise TimeLockError(
            "Puzzle authentication failed: parameters were tampered with or corrupted."
        ) from exc


# Implementation note.
# Implementation note.
# Implementation note.

def calibrate(*, seconds: float = 1.0, modulus_bits: int = 2048) -> int:
    """
    Measure this machine's squarings per second at the selected modulus size.
    This translates 'days' into T, remembering that an adversary may be faster;
    T should therefore be multiplied by the hardware margin to cover.
    """
    import time
    n = _gen_prime(modulus_bits // 2) * _gen_prime(modulus_bits // 2)
    x = 2 + secrets.randbelow(n - 3)
    count = 0
    batch = 10_000
    t0 = time.time()
    while time.time() - t0 < seconds:
        for _ in range(batch):
            x = x * x % n
        count += batch
    dt = time.time() - t0
    return int(count / dt)


def estimate_squarings(days: float, rate_per_second: int) -> int:
    """Return T for `days` at `rate_per_second`, a work floor at that rate."""
    if days <= 0 or rate_per_second <= 0:
        raise TimeLockError("days and rate_per_second must be > 0.")
    return min(int(days * 86_400 * rate_per_second), _MAX_SQUARINGS)
