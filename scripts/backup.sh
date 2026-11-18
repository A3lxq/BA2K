#!/usr/bin/env bash
# Consistent backup of the SQLite state database (uses SQLite's online backup API).
set -euo pipefail
state="${BLACKARCH2KALI_HOME:-./state}"
dest="${1:-$state/backups}"
mkdir -p "$dest"
out="$dest/blackarch2kali-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
python3 - "$state/blackarch2kali.sqlite" "$out" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2])
with dst: src.backup(dst)
PY
echo "backup written: $out"
