"""
legacy/core/shamir.py
======================
Shamir Secret Sharing over GF(2^8)  reparto of secretos with umbral.

a secreto of B bytes is reparte in N shares of forma that any
subconjunto of K shares it reconstruye, and K-1 shares no revelan NADA
(seguridad information-theoretic: each subconjunto of K-1 shares is
consistente with all the secretos posibles, with igual probabilidad).

Construccion (identica in espiritu a HashiCorp Vault / SSSS clasico):
  - the cuerpo is GF(2^8) with the polinomio of AES (x^8+x^4+x^3+x+1, 0x11B).
  - by each byte of the secreto is generates a polinomio aleatorio of grado
    K-1 cuyo term constante is the byte of the secreto.
  - the share i (with x = i, i  1..N) recibe the evaluation of the polinomio
    in x=i, byte a byte.
  - Reconstruccion: interpolacion of Lagrange in x=0.

Formato of share (a linea, imprimible, apta for papel/over):

    dlshare-v1:<base64url of JSON>

  JSON: {"v":1, "x":i, "k":umbral, "n":total, "d":<sha256(secreto)[:4] hex>,
         "and":<hex of the bytes of the share>}

  the field "d" allows verificar that the reconstruccion produjo the secreto
  correcto (and detects mezclas of shares of repartos distintos). are 32
  bits of the hash: suficiente for verificacion, inservible as oraculo
  when the secreto is aleatorio of 32 bytes  the unico uso in este
  proyecto. NO usar este module for repartir secretos of baja entropia
  (a contrasena humana) without quitar the digest.

module puro: without I/O, without state, only `secrets` for the aleatoriedad.
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
    """parameters invalidos, shares inconsistentes o reconstruccion fallida."""


# Implementation note.
# Implementation note.
# Implementation note.

def _build_tables() -> tuple[List[int], List[int]]:
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # Implementation note.
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
        raise ZeroDivisionError("division by cero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Evalua the polinomio (coeffs[0] = term constante) in x  Horner."""
    result = 0
    for c in reversed(coeffs):
        result = _mul(result, x) ^ c
    return result


def _interpolate_at_zero(points: Sequence[tuple[int, int]]) -> int:
    """Lagrange in x=0 over GF(2^8). points = [(x_i, y_i)] with x_i unicos."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = _mul(num, xj)            # (0 - x_j) = x_j  (resta = XOR)
            den = _mul(den, xi ^ xj)       # (x_i - x_j)
        secret ^= _mul(yi, _div(num, den))
    return secret


# Implementation note.
# Implementation note.
# Implementation note.

@dataclass(frozen=True)
class Share:
    x: int                # 1..255  abscisa of the share
    threshold: int        # K
    total: int            # N
    digest: str           # sha256(secreto)[:4] in hex  verificacion
    data: bytes           # evaluaciones, a byte by byte of the secreto

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
                f"Share inválido: falta el prefijo {SHARE_PREFIX!r}."
            )
        try:
            blob = base64.urlsafe_b64decode(text[len(SHARE_PREFIX):])
            payload = json.loads(blob)
            if payload["v"] != 1:
                raise ShamirError(f"Versión de share desconocida: {payload['v']}")
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
            raise ShamirError(f"Share ilegible o dañado: {exc}") from exc
        if not (1 <= share.x <= 255):
            raise ShamirError(f"Share con x fuera de rango: {share.x}")
        return share


def _secret_digest(secret: bytes) -> str:
    return hashlib.sha256(secret).digest()[:_DIGEST_LEN].hex()


# Implementation note.
# Implementation note.
# Implementation note.

def split_secret(secret: bytes, *, shares: int, threshold: int) -> List[Share]:
    """
    Reparte `secret` in `shares` partes with umbral `threshold`.

    Restricciones: 1 <= threshold <= shares <= 255, secreto no empty.
    each call usa polinomios frescos: repartir dos veces the same
    secreto produce shares incompatibles between repartos (the digest the
    distingue in combine).
    """
    if not secret:
        raise ShamirError("the secreto no can be empty.")
    if not (1 <= threshold <= shares <= 255):
        raise ShamirError(
            f"Parámetros inválidos: se requiere 1 <= threshold({threshold}) "
            f"<= shares({shares}) <= 255."
        )

    digest = _secret_digest(secret)
    # Implementation note.
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
    Reconstruye the secreto a partir of >= threshold shares.

    Acepta objetos Share o strings serializados. Valida consistencia
    (same reparto, same parameters, x unicos) and verifica the result
    contra the digest  a mezcla of repartos o a share adulterado
    produce ShamirError, nunca a secreto incorrect in silencio.
    """
    if not shares:
        raise ShamirError("No is proveyeron shares.")

    parsed: List[Share] = [
        s if isinstance(s, Share) else Share.deserialize(s) for s in shares
    ]

    ref = parsed[0]
    for s in parsed[1:]:
        if (s.threshold, s.digest, len(s.data)) != (
            ref.threshold, ref.digest, len(ref.data)
        ):
            raise ShamirError(
                "Shares inconsistentes  pertenecen a repartos distintos."
            )
    xs = [s.x for s in parsed]
    if len(set(xs)) != len(xs):
        raise ShamirError("Hay shares duplicados (same index x).")
    if len(parsed) < ref.threshold:
        raise ShamirError(
            f"Missing shares: {ref.threshold} are required, {len(parsed)} provided."
        )

    # Implementation note.
    # Implementation note.
    subset = parsed[: ref.threshold]
    secret = bytes(
        _interpolate_at_zero([(s.x, s.data[i]) for s in subset])
        for i in range(len(ref.data))
    )

    if _secret_digest(secret) != ref.digest:
        raise ShamirError(
            "the reconstruccion no verifica: shares adulterados, mezclados "
            "o insuficientes for este reparto."
        )
    return secret
