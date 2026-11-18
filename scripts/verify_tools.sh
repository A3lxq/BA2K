#!/usr/bin/env bash
# Verify tools: pass tool names, or none to verify every tool that has a verification profile.
set -euo pipefail
if [ "$#" -eq 0 ]; then exec blackarch2kali verify --all; fi
rc=0
for t in "$@"; do blackarch2kali verify "$t" || rc=$?; done
exit "$rc"
