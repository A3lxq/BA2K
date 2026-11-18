"""Framework self-health checks (local only; no network)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from ..compatibility.platform_detector import Platform
from ..config import Settings
from ..database.repository import Database
from ..errors import DatabaseError


@dataclass
class HealthCheck:
    name: str
    ok: bool
    detail: str


def run_health(settings: Settings, platform: Platform) -> list[HealthCheck]:
    checks = [HealthCheck("python>=3.11", sys.version_info >= (3, 11), sys.version.split()[0])]
    checks.append(HealthCheck("debian-family-host", platform.is_debian_family, f"{platform.distro_id} {platform.version}".strip()))
    checks.append(HealthCheck("kali-host", platform.is_kali, "native Kali" if platform.is_kali else "not Kali: Kali-specific checks use remote indexes"))
    try:
        db = Database(settings.db_path)
        n = db.conn.execute("SELECT COUNT(*) FROM packages").fetchone()[0]
        db.close()
        checks.append(HealthCheck("database", True, f"{settings.db_path} ({n} packages)"))
    except DatabaseError as exc:
        checks.append(HealthCheck("database", False, str(exc)))
    state = settings.state_dir
    checks.append(HealthCheck("state-dir-writable", state.exists() and os.access(state, os.W_OK), str(state)))
    checks.append(HealthCheck("github-token", bool(settings.github_token), "set (value hidden)" if settings.github_token else "unset: unauthenticated limit is 60 requests/hour"))
    for tool in ("apt-get", "pipx", "git", "go", "cargo", "npm", "gem", "docker"):
        checks.append(HealthCheck(f"tool:{tool}", platform.has(tool), "available" if platform.has(tool) else "not installed (installer for it disabled)"))
    gen = settings.generated_dir
    checks.append(HealthCheck("generated-dir", not Path(gen).is_symlink(), str(gen)))
    return checks
