"""Category mapping. Official BlackArch groups are authoritative; keyword matches are labelled DERIVED."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .config import load_yaml
from .models import BlackArchPackage


def load_category_config(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    cats = load_yaml(path).get("categories", {})
    return cats if isinstance(cats, dict) else {}


def official_groups(packages: dict[str, BlackArchPackage]) -> dict[str, int]:
    """Discover categories from package metadata first."""
    counts: dict[str, int] = {}
    for p in packages.values():
        for g in p.groups:
            counts[g] = counts.get(g, 0) + 1
    return dict(sorted(counts.items()))


def research_categories(pkg: BlackArchPackage, config: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(official_mapped, derived). Derived entries come only from keyword matches on name/description."""
    official: list[str] = []
    derived: list[str] = []
    text = f"{pkg.name} {pkg.description}".lower()
    for cat, rule in config.items():
        groups = set(rule.get("official_groups", []) or [])
        if groups & set(pkg.groups):
            official.append(cat)
            continue
        for kw in rule.get("keywords", []) or []:
            if re.search(rf"(?<![a-z0-9]){re.escape(str(kw).lower())}(?![a-z0-9])", text):
                derived.append(cat)
                break
    return official, derived
