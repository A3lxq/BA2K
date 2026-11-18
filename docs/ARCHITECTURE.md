# Architecture

## Pipeline

```
 Discovery            Analysis              Planning           Approval        Execution
 ─────────            ────────              ────────           ────────        ─────────
 collectors/*   →     analyzers/*     →     compatibility/* →  plan digest →   installers/*
 (BlackArch db,       security/*            install_strategy   (user approves  validators/*
  Kali/Debian idx,    analysis.py           plans.py           exact digest)   (verify)
  GitHub API)         → ToolRecord
        └────────── synchronization/ (discovery + analysis + planning data only) ──────────┘
```

The `synchronization` package cannot reach the `installers` package — `tests/integration/test_sync_engine.py`
imports the sync modules in an isolated interpreter and fails if any `blackarch2kali.installers.*` module is loaded.

## Modules

| Package | Responsibility |
|---|---|
| `collectors/` | `blackarch` (pacman sync DB parser, duplicate detection), `kali`/`debian` (`Packages` index), `github` (REST API, rate limits, README as inert text), `upstream` (URL classification) |
| `analyzers/` | maintenance classification (configurable thresholds), license, language, README, text-risk heuristics |
| `compatibility/` | `package_mapper` (exact name + homepage identity), `engine` (states + ranked options), `install_strategy` (evidence-based options, scoring), `dependency_resolver` (graph, cycles, version/arch conflicts, Debian version compare), `platform_detector` |
| `installers/` | one class per ecosystem; strict per-ecosystem command patterns; digest-bound approval; dry-run default |
| `validators/` | binary/ownership/dependency checks, safe version/help probes, diagnostics, framework health |
| `security/` | `command_safety` (validators, safe writes), `source_validation` (upstream identity), `installer_audit`, `risk_engine` (4 dimensions) |
| `database/` | SQLite via a small `Database` class + forward-only migrations (dialect-light SQL so PostgreSQL can be added behind the same interface) |
| `reporting/` | JSON, CSV (formula-injection safe), Markdown (escaped), HTML (escaped, CSP) |
| `synchronization/` | engine, change detection (added/removed/renamed/changed), history, scheduler |
| `analysis.py` | assembles a `ToolRecord` from all of the above |
| `cli.py` / `services.py` | Typer CLI and dependency wiring |

## Data flow and provenance

Each `BlackArchPackage`, `RepoInfo` and `DebMatch` carries `Provenance(source, url, retrieved_at)`.
`ToolRecord.reproducibility` records the BlackArch version + sha256, upstream HEAD commit, latest release,
and Kali/Debian version + sha256 + filename. Install plans pin the commit SHA (or release tag).

## Decisions

* **Name-only distro matches are allowed but flagged** (`exact-name`), because name collisions are real
  (e.g. BlackArch `ace` is not Kali's `ace`). They need `--allow-unverified` to execute.
* **Registry-name installs (gem) are never "verified"**; cargo/go/npm install from the verified git repo at a pinned ref instead of a registry name.
* **Source builds fetch a pinned checkout only**; no upstream Makefile is executed.
* **Upstream-scoped risk findings don't block distro (APT) installs** — a risky README says nothing about a Kali-packaged binary.
* **Partial syncs (rate limit) are `partial`, not `success`**, so the scheduler retries sooner and missing data stays `UNKNOWN`.
* **404 vs. not-fetched-yet** are distinguished (`repo_status` table) so unfetched repositories are not reported as missing.
* **Redirects are followed manually** and every hop is re-validated (https only, no IPs/localhost); tokens are attached per-host.
