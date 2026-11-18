# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `sync` finishes `partial`, "GitHub rate limit reached" | Set `GITHUB_TOKEN`; re-run — remaining repos continue. Use `--max-repos` to pace. |
| Many tools show `maintenance UNKNOWN` | Their GitHub data hasn't been fetched yet (see above) or upstream isn't on GitHub. |
| `no installable option` (exit 4) | All options blocked by risk policy or no verified route; see `compatibility TOOL` for block reasons. |
| `unverified identity evidence` | Name-only distro match or registry-name option. Review, then `--allow-unverified`. |
| `Approval does not match this plan` | Metadata changed after you reviewed. Re-run `plan` and approve the new digest. |
| `required tool not found on PATH: X` | Install that ecosystem's tool (e.g. `sudo apt install golang-go`). BA2K never installs toolchains for you. |
| `externally-managed-environment` | Expected (PEP 668). Use `pipx`/`install.sh`; BA2K never calls system `pip`. |
| `Database is corrupted` | Restore from `scripts/backup.sh` output or delete `state/blackarch2kali.sqlite` and re-sync. |
| `verify` says binary not found | Installed via pipx/go/cargo? Ensure `~/.local/bin`, `~/go/bin`, `~/.cargo/bin` are on PATH. |
| Kali index unavailable warning | Mirror outage; analysis falls back to Debian/none and marks results accordingly. Re-run later. |
| Not running on Kali | Analysis works on any Debian-family host; native-Kali checks use the remote Kali index. |
