"""License normalisation and policy classification."""

from __future__ import annotations

import re

_PERMISSIVE = {"mit", "bsd", "bsd-2-clause", "bsd-3-clause", "isc", "apache", "apache-2.0", "apache2", "unlicense", "zlib", "cc0-1.0", "cc0", "psf", "python", "mpl-2.0"}
_COPYLEFT = {"gpl", "gpl2", "gpl3", "gpl-2.0", "gpl-3.0", "gpl-2.0-only", "gpl-3.0-only", "gpl-2.0-or-later", "gpl-3.0-or-later", "lgpl", "lgpl2", "lgpl3", "lgpl-2.1", "lgpl-3.0", "agpl", "agpl3", "agpl-3.0", "mpl", "mpl2", "eupl", "cddl", "epl"}
_NONFREE = {"custom", "custom:unknown", "unknown", "proprietary", "commercial", "none", "other", "noassertion", "custom:none"}


def normalize(licenses: list[str] | str | None) -> list[str]:
    if not licenses:
        return []
    items = [licenses] if isinstance(licenses, str) else licenses
    return [re.sub(r"^custom:\s*", "custom:", x.strip().lower()) for x in items if x and x.strip()]


def classify_license(licenses: list[str] | str | None) -> str:
    """Return one of: permissive, copyleft, restricted, unknown."""
    norm = normalize(licenses)
    if not norm:
        return "unknown"
    kinds = set()
    for lic in norm:
        base = lic.split(" ")[0]
        if base in _NONFREE or lic.startswith("custom:") and base not in _PERMISSIVE | _COPYLEFT:
            kinds.add("restricted")
        elif base in _COPYLEFT or any(base.startswith(c) for c in ("gpl", "lgpl", "agpl")):
            kinds.add("copyleft")
        elif base in _PERMISSIVE or any(base.startswith(p) for p in ("bsd", "apache", "mit")):
            kinds.add("permissive")
        else:
            kinds.add("unknown")
    for k in ("restricted", "unknown", "copyleft", "permissive"):
        if k in kinds:
            return k
    return "unknown"


def license_mismatch(blackarch: list[str], github: str | None) -> bool:
    """True when both sides are known, classified, and disagree materially."""
    a, b = classify_license(blackarch), classify_license(github)
    return "unknown" not in (a, b) and a != b
