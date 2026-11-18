"""Write the full report set to generated/ (atomic, symlink-safe)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import RepoInfo, ToolRecord, utcnow_iso
from ..plans import generate_category_artifacts
from ..security.command_safety import safe_write_text
from . import csv_report, html_report, json_report, markdown


def generate_reports(tools: dict[str, ToolRecord], repos: dict[str, RepoInfo], out_dir: Path, category_cfg: dict[str, dict[str, Any]] | None = None) -> list[Path]:
    stamp = utcnow_iso()
    r = out_dir / "reports"
    files = {
        r / "full_inventory.json": json_report.inventory_json(tools, stamp),
        r / "full_inventory.csv": csv_report.inventory_csv(tools),
        r / "full_inventory.md": markdown.full_inventory(tools, stamp),
        r / "full_inventory.html": html_report.inventory_html(tools, stamp),
        r / "github_index.json": json_report.github_index_json(repos, stamp),
        r / "compatibility_report.md": markdown.compatibility_report(tools, stamp),
        r / "dead_or_legacy_tools.md": markdown.dead_or_legacy(tools, stamp),
        r / "security_findings.md": markdown.security_findings(tools, stamp),
        r / "dependency_report.md": markdown.dependency_report(tools, stamp),
        r / "installation_report.md": markdown.installation_report(tools, stamp),
        out_dir / "dependency_graph.json": json_report.dependency_graph_json(tools, stamp),
        out_dir / "dependency_report.md": markdown.dependency_report(tools, stamp),
    }
    for path, content in files.items():
        safe_write_text(path, content)
    written = list(files)
    if category_cfg:
        written += generate_category_artifacts(tools, category_cfg, out_dir)
    return written
