"""README analysis: extract declared install commands as inert data. Nothing here is executed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..security.command_safety import is_unsafe_installer_text

_INSTALL_LINE = re.compile(r"^\s*(?:[$#>]\s*)?((?:sudo\s+)?(?:pip3?|pipx|go|cargo|npm|gem|apt(?:-get)?|docker|git|make|cmake|bash|sh|curl|wget|python3?|\./[\w./-]+)\s+[^\n]+)$", re.M)


@dataclass
class ReadmeAnalysis:
    install_commands: list[str] = field(default_factory=list)
    unsafe_installers: list[str] = field(default_factory=list)
    uses_pip: bool = False
    uses_pipx: bool = False
    uses_go: bool = False
    uses_cargo: bool = False
    uses_npm: bool = False
    uses_gem: bool = False
    uses_docker: bool = False
    uses_make: bool = False
    has_build_instructions: bool = False


def analyze_readme(text: str) -> ReadmeAnalysis:
    out = ReadmeAnalysis()
    for m in _INSTALL_LINE.finditer(text[:300_000]):
        cmd = m.group(1).strip()
        out.install_commands.append(cmd)
        if is_unsafe_installer_text(cmd):
            out.unsafe_installers.append(cmd)
    for line in out.install_commands:
        w = line.split()
        w = w[1:] if w and w[0] == "sudo" else w
        head = w[0] if w else ""
        sub = w[1] if len(w) > 1 else ""
        out.uses_pip |= head in {"pip", "pip3"} and sub == "install"
        out.uses_pipx |= head == "pipx"
        out.uses_go |= head == "go" and sub in {"install", "build", "get"}
        out.uses_cargo |= head == "cargo"
        out.uses_npm |= head == "npm"
        out.uses_gem |= head == "gem"
        out.uses_docker |= head == "docker"
        out.uses_make |= head in {"make", "cmake"}
    # whole-text check catches multi-line / piped forms the line regex may split
    if is_unsafe_installer_text(text[:300_000]):
        for line in text.splitlines():
            if is_unsafe_installer_text(line) and line.strip() not in out.unsafe_installers:
                out.unsafe_installers.append(line.strip())
    out.has_build_instructions = bool(out.install_commands)
    return out
