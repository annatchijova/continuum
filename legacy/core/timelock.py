"""
legacy/core/timelock.py
========================
Time-lock puzzle offline (RSW96 / LCS35)  the componente REALIZABLE of KL-011.

closes a parte of KL-011 and NO another; the distincion is the corazon of este
module and no must difuminarse:

  it that PROVEE (piso of trabajo secuencial, criptografico and offline):
    recover the secreto envuelto exige >= T cuadraturas modulares
    SECUENCIALES. a sola chain of cuadraturas cannot paralelizar
    (x_{i+1} = x_i^2 mod N depende of x_i), and without the factorizacion of N no
    hay atajo. the factorizacion (and (N)) is descarta in the setup.

  it that **NO** PROVEE (reloj of pared):
    NO is "is opens the 2030-01-01". is "cuesta ~T cuadraturas secuenciales".
    the tiempo of pared = T / (cuadraturas-by-segundo of the that resuelve).
    Hardware more fast (o a ASIC of squaring) resuelve proporcionalmente
    before. by eso T is elige asumiendo the hardware of the ADVERSARIO, no the of the
    heir. is a piso of cost, no a fecha.

Modelo of amenaza:
  - the attacker can: leer the puzzle; correr computo arbitrario, incluso
    masivamente paralelo; tener hardware more fast.
  - the attacker NO can: paralelizar a chain of cuadraturas; factorizar N;
    recover the atajo (N) (descartado).

Uso previsto: a keyslot ADICIONAL e independiente of the vault (opt-in), for the
escenario "without custodios disponibles, pero the heirs can open quemando
computo". is compone with the passphrase and the custodia Shamir; no the replaces.

Construccion (RSW96):
  N = pq (primos generados with Miller-Rabin);  = (p-1)(q-1).
  a = database aleatoria in [2, N).
  solucion = a^(2^T mod ) mod N        (atajo: O(log T), requires )
           = a elevado to the cuadrado T veces mod N   (without atajo: T secuencial)
  key = SHA-256(solucion)    AES-256-GCM envuelve the secreto.
  is persisten N, T, a, nonce, ciphertext. is DESCARTAN p, q, , solucion.

Dependencias: stdlib + `cryptography` (AES-GCM). without red, without sympy.

Trabajo futuro (reloj of pared criptografico  ver KL-011 in
KNOWN_LIMITATIONS.md): este module da a piso of TRABAJO, no a fecha. a
lock atado a fecha absoluta necesitaria a raiz of confianza temporal that
hoy does not exist by design (offline, without terceros). Candidatos, each uno
moviendo the frontera of confianza:
  1. tlock over a beacon drand (timelock encryption)  dependencia of red
     to the recover; the more probable if is acepta a red opcional.
  2. autoridad of timestamp RFC 3161  a tercero of confianza.
  3. TEE/HSM with reloj monotonico  dependencia of hardware.
No is implementa no: adoptar a is a decision of producto over what
confianza externa is acepta, no a TODO of code.
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
    """parameters invalidos, puzzle corrupto o solucion incorrect."""


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("the paquete 'cryptography' is required for the time-lock.")


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
    """Primo probable of exactamente `bits` bits (MSB and LSB in 1)."""
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
    Envuelve `secret` in a time-lock puzzle: only is recupera tras
    `squarings` cuadraturas secuenciales (o with the factorizacion, that is
    descarta). returns a dict serializable. Setup O(log T): instantaneo.

    Bounds (fail-closed): secret no empty; 1 <= squarings <= _MAX_SQUARINGS;
    modulus_bits >= 1024.
    """
    _require_crypto()
    if not secret:
        raise TimeLockError("the secreto no can be empty.")
    if not (1 <= squarings <= _MAX_SQUARINGS):
        raise TimeLockError(
            f"squarings fuera de rango: 1 <= T <= {_MAX_SQUARINGS} (recibido {squarings})."
        )
    if modulus_bits < _MIN_MODULUS_BITS:
        raise TimeLockError(
            f"modulus_bits debe ser >= {_MIN_MODULUS_BITS} (recibido {modulus_bits})."
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
    Resuelve the puzzle: T cuadraturas secuenciales  key  decrypts the
    secreto. slow by design (ese is the punto). `progress(done, total)` is
    llama each `progress_every` cuadraturas for UX.

    Lanza TimeLockError if the puzzle is corrupto o the secreto no autentica
    (fail-closed: N/a/T tampered producen another solucion  GCM falla).
    """
    _require_crypto()
    try:
        if puzzle.get("version") != PUZZLE_VERSION:
            raise TimeLockError(f"Versión de puzzle desconocida: {puzzle.get('version')}")
        modulus_bits = int(puzzle["modulus_bits"])
        t = int(puzzle["squarings"])
        n = int(puzzle["n"], 16)
        x = int(puzzle["a"], 16) % n
        nonce = bytes.fromhex(puzzle["nonce"])
        ciphertext = bytes.fromhex(puzzle["ciphertext"])
    except (KeyError, ValueError, TypeError) as exc:
        raise TimeLockError(f"Puzzle ilegible o dañado: {exc}") from exc

    if not (1 <= t <= _MAX_SQUARINGS):
        raise TimeLockError("squarings of the puzzle fuera of rango.")

    for i in range(t):
        x = x * x % n
        if progress is not None and (i + 1) % progress_every == 0:
            progress(i + 1, t)

    key = _solution_to_key(x, modulus_bits)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _AAD)
    except Exception as exc:
        raise TimeLockError(
            "the puzzle no autentica: parameters tampered o corrupcion."
        ) from exc


# Implementation note.
# Implementation note.
# Implementation note.

def calibrate(*, seconds: float = 1.0, modulus_bits: int = 2048) -> int:
    """
    Mide cuantas cuadraturas by segundo does ESTA maquina with este size of
    module. Sirve for traducir 'dias' a T  recordando that the adversario
    can be more fast, asi that T should multiplicarse by the margen of
    hardware that uno quiera cubrir.
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
    """T  dias  rate. Piso of cuadraturas for ese tiempo A ESE ritmo."""
    if days <= 0 or rate_per_second <= 0:
        raise TimeLockError("days and rate deben be > 0.")
    return min(int(days * 86_400 * rate_per_second), _MAX_SQUARINGS)
