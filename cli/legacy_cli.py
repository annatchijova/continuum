# Implementation note.
"""
cli/legacy_cli.py  shim of compatibilidad.

the implementation vive in `legacy.cli` (instalable as console script
`legacy` via pyproject). Este file exists for no break invocaciones
historicas: `python3 cli/legacy_cli.py ...` sigue funcionando.
"""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from legacy.cli import *          # noqa: F401,F403
from legacy.cli import main

if __name__ == "__main__":
    main()
