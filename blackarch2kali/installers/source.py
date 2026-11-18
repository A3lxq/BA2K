"""Source installer: fetches a pinned checkout for REVIEW. It never runs upstream build scripts."""

from __future__ import annotations

import re
from typing import ClassVar

from ..models import Method
from .base import GH_REPO, Installer


class SourceInstaller(Installer):
    method: ClassVar[Method] = Method.SOURCE_BUILD
    binary: ClassVar[str] = "git"

    def rollback_for(self, tool: str, steps: list[list[str]]) -> list[str]:
        return [f"Delete the directory {self.tool_dir(tool) / 'src'}."]

    def step_patterns(self) -> list[list[str]]:
        src = re.escape(str(self.work_dir / "tools")) + r"/[A-Za-z0-9][A-Za-z0-9+._@-]{0,127}/src"
        return [["git", "clone", "--no-checkout", GH_REPO, src], ["git", "-C", src, "checkout", "--detach", "[0-9a-f]{40}"]]
