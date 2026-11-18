.PHONY: sync-defaults venv lint type security test cov build check docker sync clean
PY ?= python3
venv:
	$(PY) -m venv .venv && .venv/bin/pip install -e ".[dev]"
lint:
	.venv/bin/ruff check .
type:
	.venv/bin/mypy
security:
	.venv/bin/bandit -q -r blackarch2kali -c pyproject.toml
test:
	.venv/bin/pytest
cov:
	.venv/bin/pytest --cov
build:
	.venv/bin/python -m build
check: lint type security cov build
docker:
	docker build -t ba2k:local .
sync:
	.venv/bin/blackarch2kali sync
clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage

sync-defaults:
	cp config/*.yaml blackarch2kali/defaults/
