"""APT installer (Kali/Debian packages)."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import Installer


class AptInstaller(Installer):
    method: ClassVar[Method] = Method.APT
    binary: ClassVar[str] = "apt-get"
    rollback_hint = "Remove with: sudo apt-get remove -- <package> (and `apt-get autoremove` after reviewing the list)."

    def step_patterns(self) -> list[list[str]]:
        return [["apt-get", "install", "--no-install-recommends", "--", r"[A-Za-z0-9][A-Za-z0-9+.-]{0,127}"]]
