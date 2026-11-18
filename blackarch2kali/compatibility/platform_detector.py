"""Detect the host platform (distro, architecture, available toolchains)."""

from __future__ import annotations

import platform
import shutil
import subprocess  # noqa: S404  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

_DEB_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armhf", "i686": "i386", "i386": "i386"}
_TOOLS = ("apt-get", "dpkg", "pipx", "python3", "cargo", "go", "npm", "gem", "docker", "git", "make", "gcc")


@dataclass
class Platform:
    distro_id: str = "unknown"
    distro_like: str = ""
    version: str = ""
    deb_arch: str = "amd64"
    tools: dict[str, bool] = field(default_factory=dict)

    @property
    def is_kali(self) -> bool:
        return self.distro_id == "kali"

    @property
    def is_debian_family(self) -> bool:
        return self.distro_id in {"kali", "debian", "ubuntu"} or "debian" in self.distro_like

    def has(self, tool: str) -> bool:
        return self.tools.get(tool, False)


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def detect(os_release: Path = Path("/etc/os-release"), which: Callable[[str], str | None] = shutil.which) -> Platform:
    info = parse_os_release(os_release.read_text()) if os_release.exists() else {}
    arch = _DEB_ARCH.get(platform.machine().lower(), platform.machine().lower())
    if which("dpkg"):
        try:
            res = subprocess.run([which("dpkg") or "dpkg", "--print-architecture"], capture_output=True, text=True, timeout=10, check=False)  # noqa: S603  # nosec B603
            if res.returncode == 0 and res.stdout.strip():
                arch = res.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return Platform(info.get("ID", "unknown").lower(), info.get("ID_LIKE", "").lower(), info.get("VERSION_ID", ""), arch, {t: bool(which(t)) for t in _TOOLS})
