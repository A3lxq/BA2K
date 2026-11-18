# BA2K — BlackArch2Kali

An automated BlackArch package-intelligence, compatibility-analysis, dependency-resolution and
installation-planning platform for **Kali Linux** (Debian-based).

BlackArch packages are pacman packages. They **cannot be installed with `pacman` on Kali**, and an
Arch package name is not a reliable Debian package name. BA2K reads BlackArch's official metadata,
verifies each tool's upstream, finds the *real* Kali/Debian equivalent (or another safe, reproducible
install route), and produces plans you review and approve before anything runs.

## Principles

| Stage | What it does | Can it change your system? |
|---|---|---|
| **Discovery** | Collects the BlackArch inventory, Kali/Debian indexes, GitHub metadata | No |
| **Analysis** | Maintenance, compatibility, dependencies, explainable risk | No |
| **Planning** | Ranked, pinned, validated install plans with an approval digest | No |
| **Approval** | You review the plan and approve its exact digest | — |
| **Execution** | Runs the approved argv lists, then verifies | Only here |

* Default is **dry run**. Installing needs `--confirm` *and* approval of the plan digest.
* Scheduled/manual **sync never installs, never executes upstream code, never edits apt sources**
  (a test asserts the sync code path cannot even import the installers).
* A repository listed in BlackArch metadata is **not trusted automatically**: ownership, forks,
  renames, archival and distro-homepage corroboration are checked and shown.
* Unknown data is `UNKNOWN`/`null`. Nothing is estimated or invented. Every record carries
  provenance and retrieval timestamps; plans pin commit SHAs and record package checksums.

## Quick start (Kali)

```bash
sudo apt install pipx git && pipx ensurepath
git clone https://github.com/A3lxq/BA2K.git && cd BA2K
./scripts/install.sh            # pipx install (PEP 668 safe)
export GITHUB_TOKEN=...         # optional; raises GitHub limits from 60/h to 5000/h (never commit it)
blackarch2kali init
blackarch2kali sync             # discovery + analysis (no installs)
blackarch2kali search nmap
blackarch2kali analyze amass
blackarch2kali plan amass
blackarch2kali install amass            # dry run
blackarch2kali install amass --confirm  # prompts to approve the plan digest
blackarch2kali verify amass
```

Example dry-run plan (real output shape):

```
Plan for amass via APT  (digest 70fed375...a888a)
  $ sudo apt-get install --no-install-recommends -- amass
  note: kali package amass 5.1.3-0kali1 (amd64)
  note: index sha256=539b289c...
  rollback: Remove with: sudo apt-get remove -- <package> ...
DRY RUN - nothing was executed. Re-run with --confirm to execute.
```

## Commands

`init`, `sync [--full] [--schedule] [--max-repos N]`, `update`, `inventory`, `search`, `categories`,
`analyze`, `compatibility`, `dependencies`, `plan`, `install [--dry-run|--confirm] [--category|--all]`,
`verify [--all]`, `report [--format json|csv|markdown|html|all]`, `security-audit`, `health`.
Global: `--verbose`, `--json`, `--config-dir`, `--home`. Exit codes: `0` ok, `1` error, `2` usage/unknown
input, `3` verification/audit failed, `4` blocked by policy or approval not given.

Shell wrappers in `scripts/` (`install_all_blackarch_tools.sh`, `install_osint.sh`, `install_wireless.sh`,
`install_exploitation.sh`, `install_forensics.sh`, `install_webapp.sh`, `dependency_check.sh`,
`verify_tools.sh`, `update_tools.sh`) only call the Python CLI and support `--dry-run` / `--confirm`.

## How compatibility works

1. BlackArch's `blackarch.db` (pacman sync DB) gives names, groups (categories), URLs, versions,
   dependencies, checksums.
2. Kali (`kali-rolling`) and Debian `Packages` indexes are parsed; lookup is by **exact package name**.
3. A name match is trusted only if the distro package's Homepage matches BlackArch's upstream
   (`exact-name+homepage`). Name-only matches (e.g. unrelated projects sharing a name) are flagged
   `exact-name` and need `--allow-unverified`.
4. Other routes (pipx, venv, cargo, go, npm, gem, docker, source) are offered only with evidence
   (build files in the repo, README-declared module paths re-validated against the verified repo,
   trusted container namespaces) and are pinned to a commit/tag.
5. Options are ranked on reliability, security, reproducibility, isolation and maintenance.

States: `NATIVE_KALI`, `NATIVE_DEBIAN`, `AVAILABLE_{SOURCE,PIPX,CARGO,GO,NPM,GEM,DOCKER}`,
`SOURCE_PATCH_REQUIRED`, `LEGACY`, `INCOMPATIBLE`, `UNKNOWN`. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Security model

Risk is reported in four separate dimensions (maintenance, installation, dependency, compatibility)
with evidence per finding. `HIGH`/`CRITICAL` options are excluded from automated installation until
reviewed. Installers accept only exact, validated command shapes; plans edited on disk are rejected.
No `curl | bash`, no system-wide pip, no privileged containers, no repository changes, no secrets in logs.
Details: [docs/SECURITY.md](docs/SECURITY.md).

## Docker

```bash
docker build -t ba2k:local .
docker compose up -d        # scheduled metadata sync; non-root, read-only rootfs, no privileges
```

The container analyses metadata only; it never installs or runs security tools.

## Development

```bash
make venv && make check      # ruff, mypy --strict, bandit, pytest (coverage gate 80%), build
```

Tests are deterministic and offline (recorded fixtures and mocked HTTP): unit, integration, security
(12 attack scenarios), regression. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Kali installation](docs/INSTALLATION.md) · [Usage](docs/USAGE.md) ·
[Compatibility](docs/COMPATIBILITY.md) · [Security](docs/SECURITY.md) · [API](docs/API_REFERENCE.md) ·
[Troubleshooting](docs/TROUBLESHOOTING.md)

## Responsible use

These are offensive-security tools. Use them only on systems you own or have written permission to test.

## License

MIT. BlackArch and Kali are trademarks of their respective projects; this project is not affiliated with them.
