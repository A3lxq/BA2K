#!/usr/bin/env bash
# Refresh metadata (incremental sync + reports). Never installs or upgrades software.
set -euo pipefail
exec blackarch2kali update "$@"
