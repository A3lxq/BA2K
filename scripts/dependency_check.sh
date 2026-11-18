#!/usr/bin/env bash
# Show dependency resolution for a tool, or a summary for all tools. Read-only.
set -euo pipefail
exec blackarch2kali dependencies "$@"
