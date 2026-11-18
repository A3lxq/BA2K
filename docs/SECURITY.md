# Security model

## Threat model
Inputs from the network (BlackArch DB, Kali/Debian indexes, GitHub, README text) are untrusted. A hostile or
compromised upstream must not be able to get code executed, write outside the state/generated directories, or
smuggle commands into generated scripts.

## Controls
| Area | Control |
|---|---|
| Discovery vs execution | `sync` code cannot import installers (tested); no subprocess during sync (tested) |
| Approval | dry-run default; `--confirm` + digest approval; plans re-validated at execution |
| Commands | argv lists, `shell=False`, scrubbed environment (no tokens), per-ecosystem exact-pattern validation |
| Python | pipx / virtualenv only (PEP 668); never system-wide pip |
| Remote execution | `curl\|bash`-style text detected and never turned into a plan |
| Docker | pull only; trusted namespaces; no privileged/host flags; compose has no privileges |
| Source builds | pinned checkout only; no upstream script is run |
| Archives | tar members read in memory only; size/count limits; hostile names rejected |
| URLs | https only, no raw IPs/localhost/credentials; every redirect hop re-validated |
| Tokens | environment only; sent solely to the API host; redacted in logs; absent from `repr` |
| Files | atomic writes, refuses symlinks (file, parent, temp), `O_EXCL|O_NOFOLLOW` |
| Reports | Markdown/HTML escaped; CSV formula-injection neutralised |
| Generated scripts | static templates filled only from `config/categories.yaml`; flag whitelist |
| CI sync | PR only, path allow-list guard, never touches scripts/workflows |

## Risk engine
Four dimensions — maintenance, installation, dependency, compatibility — each with levels LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
and per-finding evidence. Examples: archived repo (MEDIUM, maintenance), upstream is a fork (HIGH), README pipes a download
into a shell (HIGH), two independent HIGH installation findings (CRITICAL), Python 2 dependencies (MEDIUM), unverified identity (MEDIUM).
Popularity is never used as evidence of safety, and keywords alone never label software malicious. `HIGH`/`CRITICAL`
(policy `blocked_risk_levels`) block automated installation per method; upstream-scoped findings don't block distro-package installs.

## Reporting vulnerabilities
Open a private security advisory on the repository. Do not include working exploits.

## Limits
Maintenance classification does not yet use issue/advisory activity (stale results say "verify manually"). The
Debian version comparison ignores epochs. Upstream identity is corroborated only by distro homepages and GitHub metadata.
