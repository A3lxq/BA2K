"""Synchronization history helpers."""

from __future__ import annotations

import json
from typing import Any

from ..database.repository import Database


def recent_runs(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    out = []
    for r in db.list_runs(limit):
        summary = json.loads(r["summary"]) if r.get("summary") else {}
        out.append({**{k: r[k] for k in ("id", "mode", "started_at", "finished_at", "status")}, "summary": summary})
    return out
