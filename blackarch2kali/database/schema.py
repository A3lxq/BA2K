"""SQL schema. Kept dialect-light (TEXT/INTEGER) so a PostgreSQL backend can reuse it."""

SCHEMA_VERSION = 1

MIGRATIONS: dict[int, list[str]] = {
    1: [
        """CREATE TABLE packages (
            name TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            removed_at TEXT
        )""",
        """CREATE TABLE repos (
            full_name TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )""",
        """CREATE TABLE tools (
            tool_name TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mode TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            summary TEXT
        )""",
        """CREATE TABLE changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER REFERENCES sync_runs(id),
            kind TEXT NOT NULL,
            subject TEXT NOT NULL,
            detail TEXT,
            recorded_at TEXT NOT NULL
        )""",
        """CREATE TABLE package_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""",
        "CREATE INDEX idx_changes_run ON changes(run_id)",
        "CREATE INDEX idx_history_name ON package_history(name)",
    ]
}
