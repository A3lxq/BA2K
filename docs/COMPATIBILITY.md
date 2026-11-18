# Compatibility mapping

## Sources
* **BlackArch**: `blackarch.db` (pacman sync DB; gzip tar of `desc` files) — name, version, groups, URL, license, depends, checksums.
* **Kali**: `kali-rolling/main/binary-amd64/Packages.gz`. **Debian**: `stable/main/binary-amd64/Packages.gz`.
* **GitHub REST API** for repository facts. All are fetched with retries, ETag caching, and recorded with timestamps.

## Matching
1. Exact package-name lookup (no substring or `apt-cache search`).
2. Identity check: distro `Homepage` vs BlackArch `%URL%` (normalised host/path). Match → `exact-name+homepage`.
3. Name-only → flagged `exact-name`; rank penalty, `native-identity-unverified` MEDIUM finding, `--allow-unverified` needed.
4. Name transforms (`python-x`→`python3-x`) and aliases only count if the homepage also matches.
5. Architecture: `all` or host arch only (`dpkg --print-architecture`).

## States
`NATIVE_KALI` > `NATIVE_DEBIAN` > `AVAILABLE_PIPX` > `AVAILABLE_GO` > `AVAILABLE_CARGO` > `AVAILABLE_NPM` > `AVAILABLE_GEM` >
`AVAILABLE_DOCKER` > `AVAILABLE_SOURCE`. Otherwise `SOURCE_PATCH_REQUIRED` (Python 2-only upstream), `LEGACY`
(archived/stale, nothing else available), `INCOMPATIBLE` (e.g. wrong architecture), `UNKNOWN`. A tool keeps *all* applicable states.

## Evidence required for non-APT routes
| Method | Requires | Command shape |
|---|---|---|
| PIPX / PYTHON_VENV | `pyproject.toml`/`setup.py`/`setup.cfg` in repo root, not Python 2-only, a pinned ref | `pipx install -- git+https://github.com/o/r@<sha>` |
| CARGO | `Cargo.toml`, pinned ref | `cargo install --locked --git <repo> --rev <sha>` |
| GO | `go.mod` and a README `go install` path *under the verified repo*; `@latest` replaced by the pinned ref | `go install github.com/o/r/...@<sha>` |
| NPM | `package.json` | `npm install --global --ignore-scripts --prefix ~/.local github:o/r#<sha>` |
| GEM | `*.gemspec` (identity unverifiable → always `verified=false`) | `gem install --user-install ...` |
| DOCKER | image in a trusted namespace owned by upstream; README usage without privileged/host flags | `docker pull <image>` (pull only) |
| SOURCE_BUILD | Makefile/CMake/configure | pinned `git clone` + checkout only; building is manual after review |
| OFFICIAL_BINARY_RELEASE | https URL **and** pinned SHA-256 | `installers/binary.py` verifies before placing the file |

## Ranking
`score = 0.25 reliability + 0.25 security + 0.20 reproducibility + 0.15 isolation + 0.15 maintenance` (weights in
code, per-method scores in `config/installation_policies.yaml`); −3 if unverified. Ties break by policy order.

## Dependencies
Arch names are resolved against the BlackArch inventory, then Debian/Kali indexes (exact names, validated aliases,
`python-x`→`python3-x`, virtual `Provides`). Reports: missing, version conflicts (Debian-algorithm compare; epoch/revision
stripped — an approximation), architecture conflicts, `Conflicts:` between selected packages, alternatives, cycles (Tarjan SCC).
BA2K never changes apt sources.

## Categories
Official = BlackArch `%GROUPS%`. Research categories map to official groups where one exists; others use keyword matching
and are labelled **derived** (never presented as official BlackArch categories).
