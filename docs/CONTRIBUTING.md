# Contributing

```bash
make venv
make check          # ruff, mypy --strict, bandit, pytest --cov (≥80%), build
```

Rules: no placeholder implementations, no invented metadata (use `UNKNOWN`/`None`), validate every external string
before it reaches a path, argv or script, keep discovery/analysis/planning free of execution, and add a regression test
for every bug (`tests/regression`, name it after the defect). Tests must be offline and deterministic — use
`tests/fixtures` and `httpx.MockTransport` (see `tests/conftest.py::world_handler`).

New installer ecosystem: subclass `Installer`, define `step_patterns()` as exact regex shapes, add it to the registry,
and add tampered-command cases to `tests/security`. New risk rule: emit a `RiskFinding` with evidence and `scope`.
Commit messages: imperative, explain *why*.
