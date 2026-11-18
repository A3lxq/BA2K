"""Dedicated virtualenv installer for Python projects needing their own dependencies."""

from __future__ import annotations

import re
from typing import ClassVar

from ..models import Method
from .base import GH_REPO, REF, Installer


class VenvInstaller(Installer):
    method: ClassVar[Method] = Method.PYTHON_VENV
    binary: ClassVar[str] = "python3"

    def rollback_for(self, tool: str, steps: list[list[str]]) -> list[str]:
        return [f"Remove the directory {self.tool_dir(tool)} (contains the virtualenv)."]

    def step_patterns(self) -> list[list[str]]:
        base = re.escape(str(self.work_dir / "tools")) + r"/[A-Za-z0-9][A-Za-z0-9+._@-]{0,127}/venv"
        return [["python3", "-m", "venv", base], [base + "/bin/pip", "install", "--", rf"git\+{GH_REPO}@{REF}"]]
