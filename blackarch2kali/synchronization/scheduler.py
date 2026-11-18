"""Interval scheduling. The scheduler only ever triggers synchronization (discovery + analysis + planning)."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ..analyzers.maintenance import parse_ts
from ..database.repository import Database


def is_due(db: Database, interval_hours: float, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    last = db.last_successful_run()
    finished = parse_ts(last["finished_at"]) if last else None
    return finished is None or now - finished >= timedelta(hours=interval_hours)


def run_loop(job: Callable[[], Any], interval_hours: float, *, max_iterations: int | None = None, sleep: Callable[[float], None] = time.sleep) -> int:
    """Run `job` every interval. Failures are logged by the job and do not stop the loop."""
    n = 0
    while max_iterations is None or n < max_iterations:
        try:
            job()
        except Exception:  # noqa: BLE001 - keep the scheduler alive; job records its own failure
            import logging

            logging.getLogger(__name__).exception("scheduled synchronization failed")
        n += 1
        if max_iterations is not None and n >= max_iterations:
            break
        sleep(interval_hours * 3600)
    return n
