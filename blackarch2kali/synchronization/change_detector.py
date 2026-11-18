"""Detect inventory and record-level changes between synchronizations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import BlackArchPackage, ToolRecord


@dataclass
class InventoryDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)  # (old, new)
    changed: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (old_version, new_version)

    def summary(self) -> dict[str, int]:
        return {"added": len(self.added), "removed": len(self.removed), "renamed": len(self.renamed), "changed": len(self.changed)}


def _norm_url(url: str | None) -> str | None:
    return url.lower().rstrip("/").removesuffix(".git") if url else None


def diff_inventory(old: dict[str, BlackArchPackage], new: dict[str, BlackArchPackage]) -> InventoryDiff:
    d = InventoryDiff()
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    for n in sorted(set(old) & set(new)):
        if old[n].version != new[n].version:
            d.changed[n] = (old[n].version, new[n].version)
    # Rename: explicit %REPLACES%, else same upstream URL (unique on both sides).
    by_url_removed: dict[str, list[str]] = {}
    for r in removed:
        u = _norm_url(old[r].url)
        if u:
            by_url_removed.setdefault(u, []).append(r)
    taken: set[str] = set()
    for a in added:
        explicit = [r for r in removed if r in {x.split("<")[0].split(">")[0].split("=")[0] for x in new[a].replaces}]
        cands = explicit or by_url_removed.get(_norm_url(new[a].url) or "", [])
        cands = [c for c in cands if c not in taken]
        if len(cands) == 1:
            d.renamed.append((cands[0], a))
            taken.add(cands[0])
    renamed_new = {b for _, b in d.renamed}
    d.added = [a for a in added if a not in renamed_new]
    d.removed = [r for r in removed if r not in taken]
    return d


def diff_records(old: ToolRecord | None, new: ToolRecord) -> dict[str, Any]:
    """Material changes in analysis outputs (not timestamps)."""
    if old is None:
        return {"new": True}
    out: dict[str, Any] = {}
    for f in ("kali_compatibility", "security_risk", "maintenance_status", "preferred_install_method", "github_repo"):
        a, b = getattr(old, f), getattr(new, f)
        if a != b:
            out[f] = [a, b]
    return out
