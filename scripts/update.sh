#!/usr/bin/env bash
# Update framework metadata. Equivalent to `blackarch2kali update`.
set -euo pipefail
exec blackarch2kali update "$@"
