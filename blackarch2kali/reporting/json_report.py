"""JSON reports."""

from __future__ import annotations

import json
from typing import Any

from ..models import RepoInfo, ToolRecord


def inventory_json(tools: dict[str, ToolRecord], stamp: str) -> str:
    return json.dumps({"generated": stamp, "count": len(tools), "tools": [t.model_dump(mode="json") for t in sorted(tools.values(), key=lambda x: x.tool_name)]}, indent=2, sort_keys=True) + "\n"


def github_index_json(repos: dict[str, RepoInfo], stamp: str) -> str:
    items = [r.model_dump(mode="json", exclude={"readme_findings", "readme_install_commands"}) for r in sorted(repos.values(), key=lambda r: r.full_name)]
    return json.dumps({"generated": stamp, "count": len(items), "repositories": items}, indent=2, sort_keys=True) + "\n"


def dependency_graph_json(tools: dict[str, ToolRecord], stamp: str) -> str:
    nodes = sorted({*tools, *(d for t in tools.values() for d in t.dependencies)})
    edges = [{"from": t.tool_name, "to": d} for t in sorted(tools.values(), key=lambda x: x.tool_name) for d in sorted(t.dependencies)]
    graph: dict[str, Any] = {"generated": stamp, "nodes": nodes, "edges": edges,
                             "cycles": sorted({tuple(c) for t in tools.values() for c in t.dependency_resolution.get("cycles", [])})}
    return json.dumps(graph, indent=2, sort_keys=True) + "\n"
