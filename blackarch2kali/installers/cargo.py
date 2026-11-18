"""Cargo installer: installs from the verified git repository, pinned and --locked."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import GH_REPO, REF, Installer


class CargoInstaller(Installer):
    method: ClassVar[Method] = Method.CARGO
    binary: ClassVar[str] = "cargo"
    rollback_hint = "Remove with: cargo uninstall <crate>"

    def step_patterns(self) -> list[list[str]]:
        return [["cargo", "install", "--locked", "--git", GH_REPO, "--(rev|tag)", REF]]
