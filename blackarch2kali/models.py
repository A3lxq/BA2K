"""Domain models shared across the framework."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

UNKNOWN = "UNKNOWN"


def utcnow() -> datetime:
    return datetime.now(UTC)


def utcnow_iso() -> str:
    return utcnow().isoformat(timespec="seconds")


class Compatibility(StrEnum):
    NATIVE_KALI = "NATIVE_KALI"
    NATIVE_DEBIAN = "NATIVE_DEBIAN"
    AVAILABLE_SOURCE = "AVAILABLE_SOURCE"
    AVAILABLE_PIPX = "AVAILABLE_PIPX"
    AVAILABLE_CARGO = "AVAILABLE_CARGO"
    AVAILABLE_GO = "AVAILABLE_GO"
    AVAILABLE_NPM = "AVAILABLE_NPM"
    AVAILABLE_GEM = "AVAILABLE_GEM"
    AVAILABLE_DOCKER = "AVAILABLE_DOCKER"
    SOURCE_PATCH_REQUIRED = "SOURCE_PATCH_REQUIRED"
    LEGACY = "LEGACY"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


class Method(StrEnum):
    APT = "APT"
    PIPX = "PIPX"
    PYTHON_VENV = "PYTHON_VENV"
    CARGO = "CARGO"
    GO = "GO"
    NPM = "NPM"
    GEM = "GEM"
    DOCKER = "DOCKER"
    SOURCE_BUILD = "SOURCE_BUILD"
    OFFICIAL_BINARY_RELEASE = "OFFICIAL_BINARY_RELEASE"


class Maintenance(StrEnum):
    ACTIVE = "ACTIVE"
    MAINTAINED = "MAINTAINED"
    LOW_ACTIVITY = "LOW_ACTIVITY"
    STALE = "STALE"
    ARCHIVED = "ARCHIVED"
    UNKNOWN = "UNKNOWN"


class Risk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


RISK_ORDER = {Risk.UNKNOWN: 0, Risk.LOW: 1, Risk.MEDIUM: 2, Risk.HIGH: 3, Risk.CRITICAL: 4}


class RiskDimension(StrEnum):
    MAINTENANCE = "maintenance"
    INSTALLATION = "installation"
    DEPENDENCY = "dependency"
    COMPATIBILITY = "compatibility"


class Provenance(BaseModel):
    """Where a piece of metadata came from and when it was fetched."""

    model_config = ConfigDict(frozen=True)
    source: str
    url: str | None = None
    retrieved_at: str = Field(default_factory=utcnow_iso)


class BlackArchPackage(BaseModel):
    name: str
    base: str | None = None
    version: str
    description: str = ""
    groups: list[str] = Field(default_factory=list)
    url: str | None = None
    license: list[str] = Field(default_factory=list)
    arch: str = UNKNOWN
    depends: list[str] = Field(default_factory=list)
    makedepends: list[str] = Field(default_factory=list)
    optdepends: list[str] = Field(default_factory=list)
    provides: list[str] = Field(default_factory=list)
    replaces: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    build_date: int | None = None
    filename: str | None = None
    sha256: str | None = None
    compressed_size: int | None = None
    provenance: Provenance

    @property
    def categories(self) -> list[str]:
        return [g for g in self.groups if g != "blackarch"]


class RepoInfo(BaseModel):
    """GitHub repository intelligence. Every field is None/UNKNOWN when not verified."""

    full_name: str
    owner: str
    name: str
    html_url: str
    description: str | None = None
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    default_branch: str | None = None
    created_at: str | None = None
    pushed_at: str | None = None
    last_commit: str | None = None
    archived: bool = False
    disabled: bool = False
    fork: bool = False
    license: str | None = None
    languages: dict[str, int] = Field(default_factory=dict)
    primary_language: str | None = None
    topics: list[str] = Field(default_factory=list)
    release_count: int | None = None
    latest_release: str | None = None
    latest_release_date: str | None = None
    has_readme: bool | None = None
    has_build_instructions: bool | None = None
    homepage: str | None = None
    renamed_from: str | None = None
    head_sha: str | None = None  # commit hash of default branch tip at retrieval time
    provenance: Provenance


class DebMatch(BaseModel):
    package: str
    version: str
    architecture: str
    homepage: str | None = None
    depends: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    distribution: str  # "kali" or "debian"
    confidence: str = "exact-name"  # or "exact-name+homepage"
    sha256: str | None = None
    filename: str | None = None
    provenance: Provenance


class InstallOption(BaseModel):
    method: Method
    commands: list[list[str]] = Field(default_factory=list)
    score: float = 0.0
    requires_root: bool = False
    notes: list[str] = Field(default_factory=list)
    verified: bool = False
    blocked_reason: str | None = None


class RiskFinding(BaseModel):
    dimension: RiskDimension
    level: Risk
    rule: str
    message: str
    evidence: str | None = None


class ToolRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    blackarch_package: str
    category: list[str] = Field(default_factory=list)
    derived_categories: list[str] = Field(default_factory=list)
    description: str | None = None
    github_repo: str | None = None
    official_website: str | None = None
    language: str | None = None
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    last_commit: str | None = None
    latest_release: str | None = None
    license: str | None = None
    maintained: bool | None = None
    maintenance_status: str = UNKNOWN
    kali_compatibility: str = UNKNOWN
    installation_methods: list[str] = Field(default_factory=list)
    preferred_install_method: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    install_commands: list[list[str]] = Field(default_factory=list)
    verification_command: list[str] | None = None
    docker_support: bool | None = None
    security_risk: str = UNKNOWN
    risk_findings: list[dict[str, Any]] = Field(default_factory=list)
    source_provenance: list[dict[str, Any]] = Field(default_factory=list)
    last_checked: str = Field(default_factory=utcnow_iso)
    notes: list[str] = Field(default_factory=list)
    replacement_if_dead: str | None = None
    upstream_verification: dict[str, Any] = Field(default_factory=dict)
    reproducibility: dict[str, Any] = Field(default_factory=dict)
