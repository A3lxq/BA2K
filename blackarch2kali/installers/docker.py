"""Docker installer: pulls images only. No `run`, no privileged flags, no host mounts."""

from __future__ import annotations

from typing import ClassVar

from ..models import Method
from .base import Installer


class DockerInstaller(Installer):
    method: ClassVar[Method] = Method.DOCKER
    binary: ClassVar[str] = "docker"
    rollback_hint = "Remove with: docker rmi <image>"

    def step_patterns(self) -> list[list[str]]:
        return [["docker", "pull", r"(?!-)(?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9._/-]{1,200}(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[0-9a-f]{64})?"]]
