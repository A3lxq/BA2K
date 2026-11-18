"""RubyGems installer: per-user install (no system gems)."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import Installer


class GemInstaller(Installer):
    method: ClassVar[Method] = Method.GEM
    binary: ClassVar[str] = "gem"
    rollback_hint = "Remove with: gem uninstall <gem>"

    def step_patterns(self) -> list[list[str]]:
        return [["gem", "install", "--user-install", "--no-document", "--", r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"]]
