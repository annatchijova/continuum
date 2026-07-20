#!/usr/bin/env bash
# Run Continuum Studio using its project-local Python environment.
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="$project_dir/.venv/bin/python"

# Confirmed working on this NVIDIA account (2026-07-20); kimi-k2.6 (the
# narrator.py default) 404s — the account has no entitlement for it.
# Override by exporting CONTINUUM_NVIDIA_MODEL before running this script.
: "${CONTINUUM_NVIDIA_MODEL:=meta/llama-3.1-8b-instruct}"
export CONTINUUM_NVIDIA_MODEL

if [[ ! -x "$python_bin" ]]; then
  echo "Missing $python_bin. Create the local environment first:" >&2
  echo "  python3 -m venv .venv" >&2
  echo "  .venv/bin/python -m pip install -e '.[agents]'" >&2
  exit 1
fi

exec "$python_bin" -m continuum_web.server "$@"
