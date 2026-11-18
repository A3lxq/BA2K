#!/usr/bin/env bash
# Install the framework into an isolated environment (pipx preferred; PEP 668 safe). Run from the repository root.
set -euo pipefail
if command -v pipx >/dev/null 2>&1; then
  pipx install --force .
else
  python3 -m venv .venv
  .venv/bin/pip install .
  echo "Installed into .venv; run: .venv/bin/blackarch2kali --help"
fi
blackarch2kali init 2>/dev/null || true
