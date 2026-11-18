"""Centralised configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from .errors import ConfigError


class Sources(BaseModel):
    blackarch_db_urls: list[str] = Field(default_factory=lambda: ["https://www.blackarch.org/blackarch/blackarch/os/x86_64/blackarch.db"])
    kali_packages_url: str = "https://kali.download/kali/dists/kali-rolling/main/binary-amd64/Packages.gz"
    debian_packages_url: str = "https://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz"
    github_api: str = "https://api.github.com"


class HttpSettings(BaseModel):
    timeout_seconds: float = 30
    max_retries: int = 4
    backoff_base_seconds: float = 1.0
    cache_ttl_seconds: int = 21600


class GithubSettings(BaseModel):
    max_repos_per_sync: int = 0
    request_pause_seconds: float = 0.0


class MaintenanceThresholds(BaseModel):
    active_days: int = 90
    maintained_days: int = 365
    low_activity_days: int = 730
    release_grace_days: int = 365


class SyncSettings(BaseModel):
    interval_hours: float = 24
    incremental: bool = True


class Settings(BaseModel):
    state_dir: Path = Path("./state")
    generated_dir: Path = Path("./generated")
    data_dir: Path = Path("./data")
    sources: Sources = Field(default_factory=Sources)
    http: HttpSettings = Field(default_factory=HttpSettings)
    github: GithubSettings = Field(default_factory=GithubSettings)
    maintenance: MaintenanceThresholds = Field(default_factory=MaintenanceThresholds)
    sync: SyncSettings = Field(default_factory=SyncSettings)
    policy_file: Path = Path("config/installation_policies.yaml")
    categories_file: Path = Path("config/categories.yaml")

    @property
    def github_token(self) -> str | None:
        """Token comes only from the environment; never persisted or logged."""
        return os.environ.get("GITHUB_TOKEN") or None

    @property
    def db_path(self) -> Path:
        return self.state_dir / "blackarch2kali.sqlite"

    @property
    def cache_dir(self) -> Path:
        return self.state_dir / "cache"

    def __repr_args__(self) -> Any:  # never include secrets
        return [(k, v) for k, v in super().__repr_args__() if k != "github_token"]


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at top level")
    return data


def load_settings(path: Path | None = None, home: Path | None = None) -> Settings:
    """Load settings from YAML (if present) with BLACKARCH2KALI_HOME override for state."""
    cfg_path = path or Path("config/settings.yaml")
    data: dict[str, Any] = load_yaml(cfg_path) if cfg_path.exists() else {}
    try:
        settings = Settings(**data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid settings: {exc}") from exc
    env_home = os.environ.get("BLACKARCH2KALI_HOME")
    override = home or (Path(env_home) if env_home else None)
    if override:
        settings.state_dir = override
    return settings
