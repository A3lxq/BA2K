"""Wiring: builds settings, database, HTTP client, policy and analysis context for the CLI."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analysis import AnalysisContext
from .categories import load_category_config
from .collectors.debian import DebIndex
from .compatibility.platform_detector import Platform, detect
from .config import Settings, load_settings, load_yaml
from .database.repository import Database
from .http import HttpClient
from .models import BlackArchPackage
from .synchronization.engine import SyncEngine
from .validators.installation import load_profiles


@dataclass
class Services:
    settings: Settings
    db: Database
    platform: Platform
    policy: dict[str, Any]
    categories_cfg: dict[str, dict[str, Any]]
    config_dir: Path

    def http(self) -> HttpClient:
        s = self.settings
        return HttpClient(s.http, cache_dir=s.cache_dir, token=s.github_token, token_host=_host(s.sources.github_api))

    def context(self, packages: dict[str, BlackArchPackage], kali: DebIndex | None, debian: DebIndex | None) -> AnalysisContext:
        aliases_file = self.config_dir / "dependency_aliases.yaml"
        aliases = (load_yaml(aliases_file).get("aliases") or {}) if aliases_file.exists() else {}
        profiles = load_profiles(self.config_dir / "verification_profiles.yaml")
        return AnalysisContext(self.settings, self.policy, self.platform, packages, kali, debian, self.categories_cfg, aliases, profiles)

    def sync_engine(self, http: HttpClient) -> SyncEngine:
        return SyncEngine(self.db, http, self.settings, self.context, interval_hours=self.settings.sync.interval_hours, max_repos=self.settings.github.max_repos_per_sync)


def _host(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).hostname or ""


def packaged_defaults() -> Path:
    return Path(__file__).parent / "defaults"


def build_services(config_dir: Path = Path("config"), home: Path | None = None) -> Services:
    """Use `config_dir` when it has settings.yaml; otherwise fall back to the packaged defaults and
    keep state under the user's data directory (so a pipx install works from any directory)."""
    using_defaults = not (config_dir / "settings.yaml").exists()
    if using_defaults:
        config_dir = packaged_defaults()
    settings = load_settings(config_dir / "settings.yaml", home)
    if using_defaults:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "blackarch2kali"
        if home is None and not os.environ.get("BLACKARCH2KALI_HOME"):
            settings.state_dir = base / "state"
        settings.generated_dir = base / "generated"
        settings.data_dir = base / "data"
    policy = load_yaml(config_dir / "installation_policies.yaml") if (config_dir / "installation_policies.yaml").exists() else {}
    cats = load_category_config(config_dir / "categories.yaml")
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    return Services(settings, Database(settings.db_path), detect(), policy, cats, config_dir)
