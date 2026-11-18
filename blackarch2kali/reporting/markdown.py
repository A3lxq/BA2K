"""Markdown report builders. All upstream-derived text is escaped: README/description content is untrusted."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence

from ..models import ToolRecord


def esc(value: object) -> str:
    """Escape text for a Markdown table cell (no HTML, no pipes, no newlines, no link/emphasis injection)."""
    text = "" if value is None else str(value)
    text = re.sub(r"\s+", " ", text).strip()
    for ch in ("\\", "|", "`", "<", ">", "[", "]", "*", "_", "#", "!"):
        text = text.replace(ch, "\\" + ch)
    return text[:300]


def table(headers: list[str], rows: Iterable[Sequence[object]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _head(title: str, n: int, stamp: str) -> str:
    return f"# {title}\n\nGenerated: {stamp} | Tools: {n}\n\nUnknown values are shown as UNKNOWN/empty; nothing is estimated.\n\n"


def full_inventory(tools: dict[str, ToolRecord], stamp: str) -> str:
    rows = [[t.tool_name, ", ".join(t.category), t.kali_compatibility, t.preferred_install_method or "-", t.maintenance_status, t.security_risk, t.github_repo or "-"] for t in sorted(tools.values(), key=lambda x: x.tool_name)]
    return _head("Full Inventory", len(tools), stamp) + table(["Tool", "BlackArch categories", "Kali compatibility", "Preferred method", "Maintenance", "Risk", "Upstream"], rows)


def compatibility_report(tools: dict[str, ToolRecord], stamp: str) -> str:
    c = Counter(t.kali_compatibility for t in tools.values())
    out = _head("Compatibility Report", len(tools), stamp) + "## Summary\n\n" + table(["State", "Count"], c.most_common())
    for state in sorted(c):
        group = sorted((t for t in tools.values() if t.kali_compatibility == state), key=lambda t: t.tool_name)
        out += f"\n## {state} ({len(group)})\n\n" + table(["Tool", "Methods", "Preferred"], [[t.tool_name, ", ".join(t.installation_methods), t.preferred_install_method or "-"] for t in group[:500]])
        if len(group) > 500:
            out += f"\n_{len(group) - 500} more omitted; see full_inventory.json_\n"
    return out


def dead_or_legacy(tools: dict[str, ToolRecord], stamp: str) -> str:
    sel = [t for t in tools.values() if t.maintenance_status in {"ARCHIVED", "STALE"} or t.kali_compatibility in {"LEGACY", "SOURCE_PATCH_REQUIRED"}]
    rows = [[t.tool_name, t.maintenance_status, t.kali_compatibility, t.last_commit or "UNKNOWN", t.replacement_if_dead or "-", "; ".join(n for n in t.notes if n.startswith("maintenance"))] for t in sorted(sel, key=lambda x: x.tool_name)]
    return _head("Dead or Legacy Tools", len(sel), stamp) + "STALE means no recent activity was detected; verify manually before treating a project as dead.\n\n" + table(["Tool", "Maintenance", "Compatibility", "Last commit", "Replacement (BlackArch %REPLACES%)", "Notes"], rows)


def security_findings(tools: dict[str, ToolRecord], stamp: str) -> str:
    c = Counter(t.security_risk for t in tools.values())
    out = _head("Security Findings", len(tools), stamp) + "Risk is explained by evidence; popularity is never treated as safety. HIGH/CRITICAL are excluded from automated installation.\n\n## Summary\n\n" + table(["Risk", "Count"], sorted(c.items()))
    for t in sorted(tools.values(), key=lambda x: x.tool_name):
        notable = [f for f in t.risk_findings if f.get("level") in {"MEDIUM", "HIGH", "CRITICAL"}]
        if not notable:
            continue
        out += f"\n### {esc(t.tool_name)} - {t.security_risk}\n\n" + table(["Dimension", "Level", "Rule", "Message", "Evidence"], [[f["dimension"], f["level"], f["rule"], f["message"], f.get("evidence") or ""] for f in notable])
    return out


def dependency_report(tools: dict[str, ToolRecord], stamp: str) -> str:
    missing = {t.tool_name: t.dependency_resolution["missing"] for t in tools.values() if t.dependency_resolution.get("missing")}
    cyc = {t.tool_name: t.dependency_resolution["cycles"] for t in tools.values() if t.dependency_resolution.get("cycles")}
    ver = {t.tool_name: t.dependency_resolution["version_conflicts"] for t in tools.values() if t.dependency_resolution.get("version_conflicts")}
    arch = {t.tool_name: t.dependency_resolution["arch_conflicts"] for t in tools.values() if t.dependency_resolution.get("arch_conflicts")}
    out = _head("Dependency Report", len(tools), stamp)
    out += f"- Tools with unresolved dependencies: {len(missing)}\n- Tools in dependency cycles: {len(cyc)}\n- Tools with version conflicts: {len(ver)}\n- Tools with architecture conflicts: {len(arch)}\n\n"
    out += "## Unresolved dependencies\n\n" + table(["Tool", "Missing (no verified Debian/Kali equivalent)"], [[k, ", ".join(v[:12])] for k, v in sorted(missing.items())][:1000])
    out += "\n## Cycles\n\n" + table(["Tool", "Cycle members"], [[k, "; ".join(",".join(c) for c in v)] for k, v in sorted(cyc.items())])
    out += "\n## Version conflicts\n\n" + table(["Tool", "Conflicts"], [[k, "; ".join(f"{c['dependency']} {c['required']} vs {c['available']}" for c in v)] for k, v in sorted(ver.items())])
    return out


def installation_report(tools: dict[str, ToolRecord], stamp: str) -> str:
    pm = Counter(t.preferred_install_method or "NONE" for t in tools.values())
    out = _head("Installation Report", len(tools), stamp) + "Plans are advisory. Installation is dry-run by default and needs explicit approval.\n\n## Preferred methods\n\n" + table(["Method", "Tools"], pm.most_common())
    blocked = [t for t in tools.values() if t.installation_methods and not t.preferred_install_method]
    out += f"\n## Blocked pending manual review ({len(blocked)})\n\n" + table(["Tool", "Risk", "Methods"], [[t.tool_name, t.security_risk, ", ".join(t.installation_methods)] for t in sorted(blocked, key=lambda x: x.tool_name)])
    none = [t for t in tools.values() if not t.installation_methods]
    out += f"\n## No verified installation method ({len(none)})\n\n" + table(["Tool", "Compatibility"], [[t.tool_name, t.kali_compatibility] for t in sorted(none, key=lambda x: x.tool_name)][:1000])
    return out
