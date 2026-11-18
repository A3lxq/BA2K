# Usage

Global options: `-v/--verbose`, `--json`, `--config-dir DIR`, `--home STATE_DIR` (or `BLACKARCH2KALI_HOME`).

| Command | Purpose |
|---|---|
| `init` | Create state dir and database |
| `sync [--full] [--schedule] [--max-repos N] [--no-reports]` | Discovery + analysis + planning data. Never installs |
| `update` | Incremental sync + reports (metadata only) |
| `inventory [--category G] [--risk R] [--compat S] [--limit N]` | List tools |
| `search TERM` | Case-insensitive search over local names/descriptions |
| `categories` | Official BlackArch groups and research-category mapping (official vs derived) |
| `analyze TOOL` | Full record: upstream, maintenance, risk findings, notes |
| `compatibility TOOL` | States and ranked install options (with block reasons) |
| `dependencies [TOOL]` | Dependency resolution (missing, cycles, conflicts) |
| `plan TOOL [--method M]` | Installation plan + approval digest (executes nothing) |
| `install TOOL\|--category C\|--all` | Dry run by default; `--confirm` executes after digest approval |
| `verify TOOL\|--all` | Passive checks; runs version/help only for tools with a verification profile |
| `report [--format ...]` | Regenerate reports from stored data (no network) |
| `security-audit [--fail-on LEVEL]` | Risk summary; non-zero exit if threshold reached |
| `health` | Framework/host health |

## Approval model

`plan` prints a SHA-256 digest over *tool + method + exact argv steps*. `install --confirm` recomputes the plan,
and either asks you to confirm the digest interactively or requires `--plan-digest` to equal it. If metadata changed
between review and execution the digest differs and nothing runs. `--allow-unverified` is separately required for
options whose upstream identity could not be verified.

## Outputs

`generated/reports/` (`full_inventory.{json,csv,md,html}`, `github_index.json`, `compatibility_report.md`,
`dead_or_legacy_tools.md`, `security_findings.md`, `dependency_report.md`, `installation_report.md`),
`generated/dependency_graph.json`, `generated/categories/*.json` (per-category plans),
`generated/installers/install_<category>.sh` (static wrappers generated from `config/categories.yaml` only),
and `data/{tools.json,tools.yaml,compatibility.json,dependency_graph.json}`.

## Configuration

`config/settings.yaml` (sources, HTTP, maintenance thresholds, sync interval), `config/installation_policies.yaml`
(blocked risk levels, method scores, trusted registries), `config/categories.yaml`, `config/dependency_aliases.yaml`
(Arch→Debian names, used only if the target exists in the index), `config/verification_profiles.yaml`.

## Verification profiles

Add a tool to `config/verification_profiles.yaml` (`binary`, `version_args`, `help_args`) to allow `verify` to run
those probes. Tools without a profile are checked passively and never executed.
