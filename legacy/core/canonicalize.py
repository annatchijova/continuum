"""
legacy/core/canonicalize.py
============================
Deterministic canonical serialization for SHA-256.

Adapted from vigia-repo/vigia/core/canonicalize.py (schema v1).
Standalone module with no external dependencies or imports from this package.
The same input always produces the same hash on every platform.

Rules (schema v1):
  bool   "true" / "false"    (before int: bool is a subclass of int)
  int    "N:int"
  float  "N.NNNNNNNN" (8 decimal places); "nan" / "inf" / "-inf"
  str    unchanged
  None   "null"
  dict   sorted keys, recursively canonicalized values
  list/tuple  recursively canonicalized elements
  other  str() fallback; never breaks the hash
"""
from __future__ import annotations

import unicodedata
from typing import Any

CANONICALIZE_VERSION: str = "1"


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"   # +0.0 normaliza -0.0
    if isinstance(obj, str):
        # NFC normalization makes canonically equivalent Unicode strings match.
        # This is required for cross-platform filename and text consistency.
        return unicodedata.normalize("NFC", obj)
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    return str(obj)
