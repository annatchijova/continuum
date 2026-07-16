"""
legacy/core/shamir.py
======================
Shamir Secret Sharing over GF(2^8): threshold-based secret splitting.

A B-byte secret is split into N shares so that any subset of K shares
reconstructs it, while K-1 shares reveal nothing (information-theoretic
security: every subset of K-1 shares is consistent with every possible secret
with equal probability).

Construction (similar in spirit to HashiCorp Vault / classic SSSS):
  - The field is GF(2^8) with the AES polynomial (x^8+x^4+x^3+x+1, 0x11B).
  - For each secret byte, generate a random polynomial of degree K-1 whose
    constant term is that secret byte.
  - Share i (x=i, i in 1..N) receives the polynomial evaluation at x=i,
    byte by byte.
  - Reconstruction uses Lagrange interpolation at x=0.

Share format (one printable line, suitable for paper or transcription):

    dlshare-v1:<base64url of JSON>

  JSON: {"v":1, "x":i, "k":umbral, "n":total, "d":<sha256(secreto)[:4] hex>,
         "and":<hex of the bytes of the share>}

  Field "d" verifies that reconstruction produced the correct secret and
  detects mixing shares from different splits. It contains 32 bits of the
  hash: enough for verification and useless as an oracle when the secret is
  a random 32-byte value, the only use in this project. Do not use this module
  to split low-entropy secrets (such as a human password) without removing
  the digest.

Pure module: no I/O or state; only `secrets` is used for randomness.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Dict, List, Sequence

SHARE_PREFIX = "dlshare-v1:"
_DIGEST_LEN = 4          # bytes of sha256(secreto) incluidos in each share


class ShamirError(ValueError):
    """Invalid parameters, inconsistent shares, or failed reconstruction."""


# GF(2^8) lookup-table construction.

def _build_tables() -> tuple[List[int], List[int]]:
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # Reduce with the AES irreducible polynomial.
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 510):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _build_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Evaluate the polynomial (coeffs[0] is the constant term) using Horner."""
    result = 0
    for c in reversed(coeffs):
        result = _mul(result, x) ^ c
    return result


def _interpolate_at_zero(points: Sequence[tuple[int, int]]) -> int:
    """Interpolate at x=0 over GF(2^8); points are [(x_i, y_i)] with unique x."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = _mul(num, xj)            # (0 - x_j) = x_j (subtraction is XOR)
            den = _mul(den, xi ^ xj)       # (x_i - x_j)
        secret ^= _mul(yi, _div(num, den))
    return secret


# Share representation and serialization.

@dataclass(frozen=True)
class Share:
    x: int                # 1..255, x-coordinate of the share
    threshold: int        # K
    total: int            # N
    digest: str           # sha256(secret)[:4] in hex, for verification
    data: bytes           # polynomial evaluations, one per secret byte

    def serialize(self) -> str:
        payload = {
            "v": 1, "x": self.x, "k": self.threshold, "n": self.total,
            "d": self.digest, "and": self.data.hex(),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return SHARE_PREFIX + base64.urlsafe_b64encode(
            blob.encode("ascii")
        ).decode("ascii")

    @staticmethod
    def deserialize(text: str) -> "Share":
        text = text.strip()
        if not text.startswith(SHARE_PREFIX):
            raise ShamirError(
                f"Invalid share: missing prefix {SHARE_PREFIX!r}."
            )
        try:
            blob = base64.urlsafe_b64decode(text[len(SHARE_PREFIX):])
            payload = json.loads(blob)
            if payload["v"] != 1:
                raise ShamirError(f"Unknown share version: {payload['v']}")
            share = Share(
                x=int(payload["x"]),
                threshold=int(payload["k"]),
                total=int(payload["n"]),
                digest=str(payload["d"]),
                data=bytes.fromhex(payload["and"]),
            )
        except ShamirError:
            raise
        except Exception as exc:
            raise ShamirError(f"Unreadable or damaged share: {exc}") from exc
        if not (1 <= share.x <= 255):
            raise ShamirError(f"Share x-coordinate out of range: {share.x}")
        return share


def _secret_digest(secret: bytes) -> str:
    return hashlib.sha256(secret).digest()[:_DIGEST_LEN].hex()


# Secret splitting and reconstruction.

def split_secret(secret: bytes, *, shares: int, threshold: int) -> List[Share]:
    """
    Split `secret` into `shares` parts with the given `threshold`.

    Constraints: 1 <= threshold <= shares <= 255, and the secret is non-empty.
    Each call uses fresh polynomials: splitting the same secret twice produces
    incompatible shares, distinguished by the digest during combination.
    """
    if not secret:
        raise ShamirError("The secret cannot be empty.")
    if not (1 <= threshold <= shares <= 255):
        raise ShamirError(
            f"Invalid parameters: require 1 <= threshold({threshold}) "
            f"<= shares({shares}) <= 255."
        )

    digest = _secret_digest(secret)
    # Each share evaluates every secret-byte polynomial at its x-coordinate.
    polys = [
        [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for byte in secret
    ]
    return [
        Share(
            x=x,
            threshold=threshold,
            total=shares,
            digest=digest,
            data=bytes(_eval_poly(poly, x) for poly in polys),
        )
        for x in range(1, shares + 1)
    ]


def combine_shares(shares: Sequence[Share | str]) -> bytes:
    """
    Reconstruct the secret from at least threshold shares.

    Accept Share objects or serialized strings. Validate consistency (same
    split, same parameters, unique x-coordinates) and verify the result against
    the digest. Mixing splits or tampering with a share raises ShamirError;
    an incorrect secret is never returned silently.
    """
    if not shares:
        raise ShamirError("No shares were provided.")

    parsed: List[Share] = [
        s if isinstance(s, Share) else Share.deserialize(s) for s in shares
    ]

    ref = parsed[0]
    for s in parsed[1:]:
        if (s.threshold, s.digest, len(s.data)) != (
            ref.threshold, ref.digest, len(ref.data)
        ):
            raise ShamirError(
                "Inconsistent shares — they belong to different splits."
            )
    xs = [s.x for s in parsed]
    if len(set(xs)) != len(xs):
        raise ShamirError("Duplicate shares (same x-coordinate).")
    if len(parsed) < ref.threshold:
        raise ShamirError(
            f"Missing shares: {ref.threshold} are required, {len(parsed)} provided."
        )

    # Any threshold-sized subset is sufficient for interpolation.
    subset = parsed[: ref.threshold]
    secret = bytes(
        _interpolate_at_zero([(s.x, s.data[i]) for s in subset])
        for i in range(len(ref.data))
    )

    if _secret_digest(secret) != ref.digest:
        raise ShamirError(
            "Reconstruction verification failed: shares are tampered, mixed, "
            "or insufficient for this split."
        )
    return secret
