"""Forward-only schema migrations."""

from __future__ import annotations

import sqlite3

from ..errors import DatabaseError
from .schema import MIGRATIONS, SCHEMA_VERSION


def current_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


def migrate(conn: sqlite3.Connection) -> int:
    version = current_version(conn)
    if version > SCHEMA_VERSION:
        raise DatabaseError(f"Database schema v{version} is newer than supported v{SCHEMA_VERSION}")
    try:
        for target in range(version + 1, SCHEMA_VERSION + 1):
            with conn:
                for stmt in MIGRATIONS[target]:
                    conn.execute(stmt)
                conn.execute("INSERT INTO schema_version(version) VALUES (?)", (target,))
    except sqlite3.Error as exc:
        raise DatabaseError(f"Migration failed: {exc}") from exc
    return SCHEMA_VERSION
