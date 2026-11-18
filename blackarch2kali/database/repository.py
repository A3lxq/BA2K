"""SQLite persistence for packages, repos, tool records, and sync history."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..errors import DatabaseError
from ..models import BlackArchPackage, RepoInfo, ToolRecord, utcnow_iso
from .migrations import migrate


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self.conn = sqlite3.connect(self.path)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys=ON")
            row = self.conn.execute("PRAGMA quick_check").fetchone()
            if row is None or row[0] != "ok":
                raise DatabaseError(f"Database integrity check failed: {self.path}")
            migrate(self.conn)
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(f"Database is corrupted or unreadable ({self.path}): {exc}") from exc

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            with self.conn:
                yield self.conn
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    # ---- packages -------------------------------------------------------------------------
    def load_packages(self, include_removed: bool = False) -> dict[str, BlackArchPackage]:
        q = "SELECT data FROM packages WHERE removed_at IS NULL" if not include_removed else "SELECT data FROM packages"
        return {p.name: p for p in (BlackArchPackage.model_validate_json(r["data"]) for r in self.conn.execute(q))}

    def removed_packages(self) -> list[str]:
        return [r["name"] for r in self.conn.execute("SELECT name FROM packages WHERE removed_at IS NOT NULL")]

    def upsert_package(self, pkg: BlackArchPackage) -> bool:
        """Insert/update; archive previous data into history on change. Returns True if changed."""
        now = utcnow_iso()
        data = pkg.model_dump_json()
        row = self.conn.execute("SELECT data FROM packages WHERE name=?", (pkg.name,)).fetchone()
        with self.transaction() as c:
            if row is None:
                c.execute("INSERT INTO packages(name,data,first_seen,last_seen) VALUES (?,?,?,?)", (pkg.name, data, now, now))
                return True
            old = BlackArchPackage.model_validate_json(row["data"])
            changed = old.model_dump(exclude={"provenance"}) != pkg.model_dump(exclude={"provenance"})
            if changed:
                c.execute("INSERT INTO package_history(name,data,recorded_at) VALUES (?,?,?)", (pkg.name, row["data"], now))
            c.execute("UPDATE packages SET data=?, last_seen=?, removed_at=NULL WHERE name=?", (data, now, pkg.name))
            return changed

    def mark_removed(self, name: str) -> None:
        with self.transaction() as c:
            c.execute("UPDATE packages SET removed_at=? WHERE name=? AND removed_at IS NULL", (utcnow_iso(), name))

    def package_history(self, name: str) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT data, recorded_at FROM package_history WHERE name=? ORDER BY id", (name,))
        return [{"recorded_at": r["recorded_at"], "data": json.loads(r["data"])} for r in rows]

    # ---- repos ----------------------------------------------------------------------------
    def save_repo(self, repo: RepoInfo) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO repos(full_name,data,fetched_at) VALUES (?,?,?) "
                "ON CONFLICT(full_name) DO UPDATE SET data=excluded.data, fetched_at=excluded.fetched_at",
                (repo.full_name.lower(), repo.model_dump_json(), utcnow_iso()),
            )

    def load_repos(self) -> dict[str, RepoInfo]:
        return {r["full_name"]: RepoInfo.model_validate_json(r["data"]) for r in self.conn.execute("SELECT full_name,data FROM repos")}

    def set_repo_status(self, key: str, status: str) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO repo_status(full_name,status,checked_at) VALUES (?,?,?) "
                "ON CONFLICT(full_name) DO UPDATE SET status=excluded.status, checked_at=excluded.checked_at",
                (key.lower(), status, utcnow_iso()),
            )

    def repo_status_times(self) -> dict[str, tuple[str, str]]:
        return {r["full_name"]: (r["status"], r["checked_at"]) for r in self.conn.execute("SELECT full_name,status,checked_at FROM repo_status")}

    def missing_repos(self) -> set[str]:
        return {r["full_name"] for r in self.conn.execute("SELECT full_name FROM repo_status WHERE status='missing'")}

    # ---- tool records ---------------------------------------------------------------------
    def save_tool(self, tool: ToolRecord) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO tools(tool_name,data,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(tool_name) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (tool.tool_name, tool.model_dump_json(), utcnow_iso()),
            )

    def load_tools(self) -> dict[str, ToolRecord]:
        return {r["tool_name"]: ToolRecord.model_validate_json(r["data"]) for r in self.conn.execute("SELECT tool_name,data FROM tools")}

    def delete_tool(self, name: str) -> None:
        with self.transaction() as c:
            c.execute("DELETE FROM tools WHERE tool_name=?", (name,))

    # ---- sync history ---------------------------------------------------------------------
    def start_run(self, mode: str) -> int:
        with self.transaction() as c:
            cur = c.execute("INSERT INTO sync_runs(mode,started_at,status) VALUES (?,?,?)", (mode, utcnow_iso(), "running"))
            return int(cur.lastrowid or 0)

    def finish_run(self, run_id: int, status: str, summary: dict[str, Any]) -> None:
        with self.transaction() as c:
            c.execute("UPDATE sync_runs SET finished_at=?, status=?, summary=? WHERE id=?", (utcnow_iso(), status, json.dumps(summary), run_id))

    def record_change(self, run_id: int, kind: str, subject: str, detail: dict[str, Any] | None = None) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO changes(run_id,kind,subject,detail,recorded_at) VALUES (?,?,?,?,?)",
                (run_id, kind, subject, json.dumps(detail or {}), utcnow_iso()),
            )

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def list_changes(self, run_id: int) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM changes WHERE run_id=? ORDER BY id", (run_id,))]

    def last_successful_run(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM sync_runs WHERE status='success' ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
