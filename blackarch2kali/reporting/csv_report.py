"""CSV report with spreadsheet formula-injection protection."""

from __future__ import annotations

import csv
import io

from ..models import ToolRecord

COLUMNS = ["tool_name", "blackarch_package", "category", "description", "github_repo", "official_website", "language", "stars", "forks", "open_issues",
           "last_commit", "latest_release", "license", "maintained", "maintenance_status", "kali_compatibility", "installation_methods",
           "preferred_install_method", "dependencies", "install_commands", "verification_command", "docker_support", "security_risk",
           "last_checked", "notes", "replacement_if_dead"]


def safe_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = "; ".join(" ".join(v) if isinstance(v, list) else str(v) for v in value)
    s = str(value).replace("\r", " ").replace("\n", " ")
    return "'" + s if s[:1] in {"=", "+", "-", "@", "\t"} else s


def inventory_csv(tools: dict[str, ToolRecord]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    for t in sorted(tools.values(), key=lambda x: x.tool_name):
        d = t.model_dump(mode="json")
        w.writerow([safe_cell(d.get(c)) for c in COLUMNS])
    return buf.getvalue()
