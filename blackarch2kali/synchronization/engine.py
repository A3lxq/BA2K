"""Synchronization engine: discovery -> analysis -> planning data. NEVER executes installers.

This module deliberately does not import blackarch2kali.installers (enforced by a test), so scheduled
or manual syncs cannot install packages, run upstream scripts, or touch system repositories.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ..analysis import AnalysisContext, analyze_package
from ..analyzers.maintenance import parse_ts
from ..collectors.blackarch import BlackArchCollector
from ..collectors.debian import DebianCollector, DebIndex
from ..collectors.github import GitHubCollector
from ..collectors.kali import KaliCollector
from ..collectors.upstream import classify
from ..config import Settings
from ..database.repository import Database
from ..errors import CollectorError, RateLimitError
from ..http import HttpClient
from ..models import BlackArchPackage, RepoInfo
from .change_detector import diff_inventory, diff_records

log = logging.getLogger(__name__)

ContextFactory = Callable[[dict[str, BlackArchPackage], DebIndex | None, DebIndex | None], AnalysisContext]


@dataclass
class SyncResult:
    run_id: int
    mode: str
    status: str
    inventory: dict[str, int] = field(default_factory=dict)
    repos_fetched: int = 0
    repos_missing: int = 0
    tools_analyzed: int = 0
    record_changes: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class SyncEngine:
    def __init__(self, db: Database, http: HttpClient, settings: Settings, ctx_factory: ContextFactory, *, interval_hours: float = 24,
                 max_repos: int = 0, include_debian: bool = True) -> None:
        """`ctx_factory(packages, kali, debian) -> AnalysisContext` keeps policy/config loading out of the engine."""
        self.db = db
        self.http = http
        self.settings = settings
        self.ctx_factory = ctx_factory
        self.interval = timedelta(hours=interval_hours)
        self.max_repos = max_repos
        self.include_debian = include_debian

    def _distro_index(self, collector: DebianCollector, warnings: list[str]) -> DebIndex | None:
        try:
            return collector.collect()
        except CollectorError as exc:
            warnings.append(f"{collector.distribution} index unavailable: {exc}")
            return None

    def run(self, mode: str = "incremental") -> SyncResult:
        if mode not in {"full", "incremental"}:
            raise ValueError("mode must be 'full' or 'incremental'")
        run_id = self.db.start_run(mode)
        result = SyncResult(run_id=run_id, mode=mode, status="running")
        try:
            self._run(mode, result)
            # 'partial' (e.g. rate limited) is recorded but is not a clean success, so the scheduler retries sooner.
            result.status = "partial" if result.warnings else "success"
        except Exception as exc:
            result.status = "failed"
            result.warnings.append(f"{type(exc).__name__}: {exc}")
            self.db.finish_run(run_id, "failed", result.to_dict())
            raise
        self.db.finish_run(run_id, result.status, result.to_dict())
        return result

    def _run(self, mode: str, result: SyncResult) -> None:
        src = self.settings.sources
        # ---- 1. discovery -----------------------------------------------------------------
        inv = BlackArchCollector(self.http, src.blackarch_db_urls).collect()
        old = self.db.load_packages()
        diff = diff_inventory(old, inv.packages)
        if old and not inv.packages:
            raise CollectorError("refusing to apply an empty inventory over existing data")
        for pkg in inv.packages.values():
            self.db.upsert_package(pkg)
        for name in diff.removed:
            self.db.mark_removed(name)
        for kind, items in (("added", diff.added), ("removed", diff.removed)):
            for n in items:
                self.db.record_change(result.run_id, f"package-{kind}", n)
        for a, b in diff.renamed:
            self.db.record_change(result.run_id, "package-renamed", a, {"new_name": b})
        for n, (o, v) in diff.changed.items():
            self.db.record_change(result.run_id, "package-version-changed", n, {"old": o, "new": v})
        for name, kept, dropped in inv.duplicates:
            self.db.record_change(result.run_id, "duplicate-entry", name, {"kept": kept, "dropped": dropped})
        if inv.errors:
            result.warnings.append(f"{len(inv.errors)} malformed inventory entries skipped")
        result.inventory = {**diff.summary(), "total": len(inv.packages), "duplicates": len(inv.duplicates), "malformed": len(inv.errors)}
        # ---- 2. distro indexes ------------------------------------------------------------
        kali = self._distro_index(KaliCollector(self.http, src.kali_packages_url), result.warnings)
        debian = self._distro_index(DebianCollector(self.http, src.debian_packages_url), result.warnings) if self.include_debian else None
        # ---- 3. upstream repository intelligence -----------------------------------------
        repos = self.db.load_repos()
        self._refresh_repos(mode, inv.packages, set(diff.added) | set(diff.changed) | {b for _, b in diff.renamed}, repos, result)
        repos = self.db.load_repos()
        # ---- 4. analysis (local, deterministic) ------------------------------------------
        ctx = self.ctx_factory(inv.packages, kali, debian)
        ctx.missing_repos = self.db.missing_repos()
        old_tools = self.db.load_tools()
        for name, pkg in inv.packages.items():
            gh = classify(pkg.url).github
            repo = repos.get(f"{gh[0]}/{gh[1]}".lower()) if gh else None
            repo = repo or self._follow_rename(gh, repos)
            tool = analyze_package(pkg, repo, ctx)
            self.db.save_tool(tool)
            ch = diff_records(old_tools.get(name), tool)
            if ch and ch != {"new": True}:
                self.db.record_change(result.run_id, "record-changed", name, ch)
                result.record_changes += 1
            result.tools_analyzed += 1
        for name in diff.removed:
            self.db.delete_tool(name)

    @staticmethod
    def _follow_rename(gh: tuple[str, str] | None, repos: dict[str, RepoInfo]) -> RepoInfo | None:
        if not gh:
            return None
        key = f"{gh[0]}/{gh[1]}".lower()
        for r in repos.values():
            if r.renamed_from and r.renamed_from.lower() == key:
                return r
        return None

    def _refresh_repos(self, mode: str, packages: dict[str, Any], touched: set[str], repos: dict[str, RepoInfo], result: SyncResult) -> None:
        gh = GitHubCollector(self.http, self.settings)
        now = datetime.now(UTC)
        todo: dict[str, tuple[str, str]] = {}
        statuses = self.db.repo_status_times()
        for name, pkg in packages.items():
            slug = classify(pkg.url).github
            if not slug:
                continue
            key = f"{slug[0]}/{slug[1]}".lower()
            known = repos.get(key) or self._follow_rename(slug, repos)
            fetched = parse_ts(known.provenance.retrieved_at) if known else None
            if known is None and key in statuses and statuses[key][0] == "missing":
                fetched = parse_ts(statuses[key][1])  # recently confirmed 404: don't hammer the API every run
            stale = fetched is None or now - fetched >= self.interval
            if mode == "full" or (known is None and fetched is None) or name in touched or stale:
                todo.setdefault(key, slug)
        limit = self.max_repos or len(todo)
        for key, (owner, repo_name) in list(todo.items())[:limit]:
            try:
                info = gh.fetch_repo(owner, repo_name)
            except RateLimitError as exc:
                result.warnings.append(f"GitHub rate limit reached; remaining repositories deferred to the next run ({exc})")
                break
            except CollectorError as exc:
                result.warnings.append(f"{owner}/{repo_name}: {exc}")
                continue
            if info is None:
                result.repos_missing += 1
                self.db.record_change(result.run_id, "repo-missing", key)
                self.db.set_repo_status(key, "missing")
                continue
            self.db.save_repo(info)
            self.db.set_repo_status(key, "found")
            result.repos_fetched += 1
        if len(todo) > limit:
            result.warnings.append(f"{len(todo) - limit} repositories deferred (max_repos_per_sync)")
