#!/usr/bin/env bash
# Plans (default) or installs every tool the framework considers installable.
# Default is DRY RUN. --confirm is required to execute, followed by interactive approval of the plan digest.
set -euo pipefail
mode=(--dry-run)
extra=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) mode=(--dry-run) ;;
    --confirm) mode=(--confirm) ;;
    --verbose|--json) extra+=("$arg") ;;
    --plan-digest=*) extra+=("$arg") ;;
    -h|--help) echo "usage: $0 [--dry-run|--confirm] [--plan-digest=SHA256] [--verbose]"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
exec blackarch2kali install --all "${mode[@]}" ${extra[@]+"${extra[@]}"}
