"""Map BlackArch packages to real Kali/Debian packages by exact name + identity validation.

Never substring/`apt-cache search` matching. A name-only match is reported but flagged as an
unverified identity (names can collide across projects); a match whose Homepage points at the same
upstream as BlackArch's %URL% is "exact-name+homepage". Transformed names (python-x -> python3-x)
are accepted ONLY when the homepage also matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..collectors.debian import DebIndex
from ..models import BlackArchPackage, DebMatch


def normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    p = urlparse(url.strip())
    host = (p.hostname or "").lower().removeprefix("www.")
    path = re.sub(r"(\.git)?/*$", "", p.path).lower()
    return f"{host}{path}" if host else None


def same_upstream(a: str | None, b: str | None) -> bool:
    na, nb = normalize_url(a), normalize_url(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    # same github owner/repo even when one side has extra path segments (e.g. /releases)
    ga, gb = na.split("/")[:3], nb.split("/")[:3]
    return len(ga) == 3 and ga[0] == "github.com" and ga == gb


@dataclass
class PackageMapping:
    kali: DebMatch | None = None
    debian: DebMatch | None = None
    notes: list[str] = field(default_factory=list)


def candidate_names(name: str) -> list[tuple[str, bool]]:
    """(candidate, is_transformed). The exact name is always first."""
    out = [(name, False)]
    if name.startswith("python-"):
        out.append((f"python3-{name[7:]}", True))
    if not name.startswith(("python3-", "python-")):
        out.append((f"python3-{name}", True))
    if name.endswith("-git"):
        out.append((name[:-4], True))
    return out


def _match(index: DebIndex, pkg: BlackArchPackage, aliases: dict[str, list[str]]) -> tuple[DebMatch | None, list[str]]:
    notes: list[str] = []
    names = candidate_names(pkg.name) + [(a, True) for a in aliases.get(pkg.name, [])]
    for cand, transformed in names:
        m = index.get(cand)
        if m is None:
            continue
        verified = same_upstream(pkg.url, m.homepage)
        if transformed and not verified:
            notes.append(f"rejected {index.distribution}:{cand} (name transform without matching homepage)")
            continue
        conf = "exact-name+homepage" if verified else "exact-name"
        if not verified:
            notes.append(f"{index.distribution}:{cand} matched by name only; upstream identity unverified (homepage={m.homepage})")
        return m.model_copy(update={"confidence": conf}), notes
    return None, notes


def map_package(pkg: BlackArchPackage, kali: DebIndex | None, debian: DebIndex | None, package_aliases: dict[str, list[str]] | None = None) -> PackageMapping:
    aliases = package_aliases or {}
    result = PackageMapping()
    if kali is not None:
        result.kali, n = _match(kali, pkg, aliases)
        result.notes += n
    if debian is not None:
        result.debian, n = _match(debian, pkg, aliases)
        result.notes += n
    return result
