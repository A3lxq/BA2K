# Installing on Kali Linux

> BlackArch packages are Arch (`pacman`) packages. They are **not** installable with `pacman` on Kali,
> and Arch names often differ from Debian names. BA2K maps each tool to a real Kali/Debian package or another
> verified route; see [COMPATIBILITY.md](COMPATIBILITY.md).

## Requirements

* Kali Linux (any Debian-family host works for analysis), Python ≥ 3.11, `git`
* Recommended: `pipx` (Kali enforces PEP 668, so never use system-wide `pip`)
* Optional per-ecosystem tools (only needed to *execute* that kind of plan): `go`, `cargo`, `npm`, `gem`, `docker`

## Install the framework

```bash
sudo apt update && sudo apt install -y pipx git python3
pipx ensurepath
git clone https://github.com/A3lxq/BA2K.git
cd BA2K
./scripts/install.sh
blackarch2kali health
```

Without pipx the script falls back to a local `.venv`.

## Authenticate to GitHub (optional, recommended)

Unauthenticated GitHub API access is limited to 60 requests/hour; a token raises this to 5000/hour.
Provide it only via the environment, never in files or chat:

```bash
gh auth login                     # or create a fine-grained read-only token
export GITHUB_TOKEN="$(gh auth token)"
```

## First synchronization

```bash
blackarch2kali sync                 # incremental; resumes where the rate limit stopped it
blackarch2kali sync --max-repos 300
blackarch2kali report
```

A full first run touches ~2,200 upstream repositories (~8 API calls each). Without a token the run is `partial`
and later runs continue; repositories not yet fetched are reported as pending, not missing.

## Installing a tool

```bash
blackarch2kali plan amass                      # shows steps, notes, rollback, approval digest
blackarch2kali install amass                   # dry run (default)
blackarch2kali install amass --confirm         # interactive approval of the digest
blackarch2kali install amass --confirm --plan-digest <sha256>   # non-interactive, exact plan
blackarch2kali verify amass
```

Categories: `blackarch2kali install --category Wireless [--confirm]` or `./scripts/install_wireless.sh [--confirm]`.

## Uninstall

`pipx uninstall blackarch2kali`, and delete the `state/` directory if you want to drop local data.
