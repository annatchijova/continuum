"""
cli/legacy_cli.py  compatibility shim.

The implementation lives in `legacy.cli` (installable as the `legacy`
console script via pyproject). This file preserves historical invocations:
`python3 cli/legacy_cli.py ...` continues to work.
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
