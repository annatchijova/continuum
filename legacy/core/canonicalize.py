"""
legacy/core/canonicalize.py
============================
Serializacion canonica determinista for SHA-256.

Adaptado of vigia-repo/vigia/core/canonicalize.py (esquema v1).
module standalone  without dependencias externas ni imports of este paquete.
the same input siempre produce the same hash, in any plataforma.

Reglas (esquema v1):
  bool   "true" / "false"    (before of int  bool is subclase of int)
  int    "N:int"
  float  "N.NNNNNNNN" (8 decimales); "nan" / "inf" / "-inf"
  str    without cambios
  None   "null"
  dict   keys ordenadas, valores recursivos
  list/tuple  elementos recursivos
  otros  str()  fallback, no rompe the hash
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
        # Implementation note.
        # Implementation note.
        return unicodedata.normalize("NFC", obj)
    if obj is None:
        return "null"
    if isinstance(obj, dict):
        return {k: _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    return str(obj)
