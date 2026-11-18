#!/usr/bin/env bash
# Developer verification: lint, types, security scan, tests with coverage.
set -euo pipefail
ruff check .
mypy
bandit -q -r blackarch2kali -c pyproject.toml
pytest --cov
