"""pipx installer: isolated per-app environments; never system-wide pip (PEP 668)."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import GH_REPO, REF, Installer


class PipxInstaller(Installer):
    method: ClassVar[Method] = Method.PIPX
    binary: ClassVar[str] = "pipx"
    rollback_hint = "Remove with: pipx uninstall <app>"

    def step_patterns(self) -> list[list[str]]:
        return [["pipx", "install", "--", rf"git\+{GH_REPO}@{REF}"]]
