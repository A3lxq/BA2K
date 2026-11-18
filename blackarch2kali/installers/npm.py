"""npm installer: GitHub-sourced, pinned, lifecycle scripts disabled, user prefix."""

from __future__ import annotations

import re
from typing import ClassVar

from ..models import Method
from .base import REF, Installer


class NpmInstaller(Installer):
    method: ClassVar[Method] = Method.NPM
    binary: ClassVar[str] = "npm"
    rollback_hint = "Remove with: npm uninstall --global --prefix ~/.local <package>"

    def step_patterns(self) -> list[list[str]]:
        prefix = re.escape(str(self.home)) + r"/\.local"
        return [["npm", "install", "--global", "--ignore-scripts", "--prefix", prefix, rf"github:[A-Za-z0-9-]{{1,39}}/[A-Za-z0-9._-]{{1,100}}#{REF}"]]
