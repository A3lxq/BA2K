"""Maintenance classification. Thresholds are configurable; stale commits alone never mean "dead"."""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import MaintenanceThresholds
from ..models import Maintenance, RepoInfo


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def classify_maintenance(repo: RepoInfo | None, th: MaintenanceThresholds, now: datetime | None = None) -> tuple[Maintenance, list[str]]:
    now = now or datetime.now(UTC)
    if repo is None:
        return Maintenance.UNKNOWN, ["no verified upstream repository"]
    if repo.archived:
        return Maintenance.ARCHIVED, ["repository is archived (read-only)"]
    commit, push, release = parse_ts(repo.last_commit), parse_ts(repo.pushed_at), parse_ts(repo.latest_release_date)
    candidates = [d for d in (commit, push) if d]
    if not candidates and not release:
        return Maintenance.UNKNOWN, ["no activity timestamps available"]
    reasons: list[str] = []
    code_age = (now - max(candidates)).days if candidates else None
    rel_age = (now - release).days if release else None
    if code_age is not None:
        reasons.append(f"last code activity {code_age}d ago")
    if rel_age is not None:
        reasons.append(f"latest release {rel_age}d ago")
    best = min(a for a in (code_age, rel_age) if a is not None)
    if best <= th.active_days:
        return Maintenance.ACTIVE, reasons
    if best <= th.maintained_days:
        return Maintenance.MAINTAINED, reasons
    if best <= th.low_activity_days:
        return Maintenance.LOW_ACTIVITY, reasons
    if rel_age is not None and rel_age <= th.release_grace_days:
        return Maintenance.LOW_ACTIVITY, [*reasons, "recent release prevents STALE"]
    reasons.append("stale by age; issue/advisory activity not assessed - verify manually before declaring dead")
    return Maintenance.STALE, reasons
