#!/usr/bin/env bash
# SSH Vault - portable, encrypted SSH connection launcher
set -eu
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null; then
  printf 'ERROR: Python 3.9+ is required.\n' >&2
  exit 2
fi
for tool in ssh ssh-keygen ssh-agent ssh-add bash; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR: Missing dependency: %s\n' "$tool" >&2; exit 2; }
done
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$ROOT/app/bootstrap.py" "$@"
