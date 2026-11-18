"""Installer registry."""

from __future__ import annotations

from pathlib import Path

from ..models import Method
from .apt import AptInstaller
from .base import Installer
from .cargo import CargoInstaller
from .docker import DockerInstaller
from .gem import GemInstaller
from .golang import GoInstaller
from .npm import NpmInstaller
from .pipx import PipxInstaller
from .source import SourceInstaller
from .venv import VenvInstaller

_REGISTRY: dict[Method, type[Installer]] = {
    Method.APT: AptInstaller, Method.PIPX: PipxInstaller, Method.PYTHON_VENV: VenvInstaller, Method.CARGO: CargoInstaller,
    Method.GO: GoInstaller, Method.NPM: NpmInstaller, Method.GEM: GemInstaller, Method.DOCKER: DockerInstaller,
    Method.SOURCE_BUILD: SourceInstaller,
}


def get_installer(method: Method, work_dir: Path, home: Path | None = None) -> Installer:
    cls = _REGISTRY.get(method)
    if cls is None:
        raise KeyError(f"No generic installer for {method.value} (binary releases use install_binary with a pinned checksum)")
    return cls(work_dir, home)
