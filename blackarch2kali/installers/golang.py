"""Go installer: validated github.com module path pinned to a commit/tag (never @latest)."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import REF, Installer


class GoInstaller(Installer):
    method: ClassVar[Method] = Method.GO
    binary: ClassVar[str] = "go"
    rollback_hint = "Delete the installed binary from $GOBIN (default ~/go/bin)."

    def step_patterns(self) -> list[list[str]]:
        return [["go", "install", rf"github\.com/[A-Za-z0-9-]{{1,39}}/[A-Za-z0-9._-]{{1,100}}(?:/[A-Za-z0-9._/-]{{1,200}})?@(?!latest$){REF}"]]
