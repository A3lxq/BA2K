"""Combined repository assessment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..config import MaintenanceThresholds
from ..models import Maintenance, RepoInfo
from .language import ecosystem, primary_language
from .license import classify_license
from .maintenance import classify_maintenance


@dataclass
class RepoAssessment:
    maintenance: Maintenance
    reasons: list[str]
    language: str | None
    ecosystem: str
    license_class: str


def assess_repo(repo: RepoInfo | None, th: MaintenanceThresholds, now: datetime | None = None) -> RepoAssessment:
    status, reasons = classify_maintenance(repo, th, now)
    lang = primary_language(repo)
    return RepoAssessment(status, reasons, lang, ecosystem(lang), classify_license(repo.license if repo else None))
