#!/usr/bin/env bash
# SSH Launcher — portable interface in app/, private data in keys/.
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: Python 3.9 or newer is required.' >&2
  exit 1
fi
# Prevent __pycache__ creation. The entire folder remains portable.
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$ROOT/app/launcher.py" "$@"
