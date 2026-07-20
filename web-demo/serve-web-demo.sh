#!/usr/bin/env bash
set -euo pipefail

demo_port="${1:-8793}"
exec python3 -m http.server "$demo_port" --bind 127.0.0.1
