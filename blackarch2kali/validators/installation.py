"""Verification engine: binary existence, ownership, version/help probes, diagnostics."""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..config import load_yaml
from ..security.command_safety import validate_tool_name
from .commands import diagnose, find_binary, probe
from .dependencies import check_dependencies


class VerificationProfile(BaseModel):
    binary: str
    version_args: list[str] = Field(default_factory=list)
    help_args: list[str] = Field(default_factory=list)
    expected_exit_codes: list[int] = Field(default_factory=lambda: [0])


@dataclass
class VerificationReport:
    tool: str
    ok: bool = False
    binary_path: str | None = None
    owner: str | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    missing_dependencies: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    stderr: str = ""
    executed: bool = False


def load_profiles(path: Path) -> dict[str, VerificationProfile]:
    if not path.exists():
        return {}
    raw = load_yaml(path).get("profiles", {}) or {}
    return {name: VerificationProfile(**cfg) for name, cfg in raw.items()}


def package_owner(path: Path) -> str | None:
    """Which package manager owns the file? dpkg ownership, else pipx/cargo/go/npm location heuristics."""
    resolved = str(path.resolve())
    exe = shutil.which("dpkg")
    if exe:
        p = subprocess.run([exe, "-S", "--", resolved], capture_output=True, text=True, timeout=15, check=False)  # noqa: S603  # nosec B603
        if p.returncode == 0 and ":" in p.stdout:
            return "dpkg:" + p.stdout.split(":")[0].strip()
    for marker, label in (("/pipx/", "pipx"), (".cargo/bin", "cargo"), ("/go/bin", "go"), ("/node_modules/", "npm"), ("/.gem/", "gem")):
        if marker in resolved or marker in str(path):
            return label
    return None


def verify_tool(tool: str, profile: VerificationProfile | None = None, apt_deps: list[str] | None = None, extra_bin_dirs: list[Path] | None = None) -> VerificationReport:
    validate_tool_name(tool)
    rep = VerificationReport(tool=tool)
    binary_name = profile.binary if profile else tool
    path = find_binary(binary_name, extra_bin_dirs)
    rep.checks["binary_exists"] = path is not None
    if path is None:
        rep.remediation.append(f"`{binary_name}` not found on PATH; install it first (see `blackarch2kali plan {tool}`)")
        return rep
    rep.binary_path = str(path)
    rep.owner = package_owner(path)
    rep.checks["package_owner"] = rep.owner
    if apt_deps:
        dep_state = check_dependencies(apt_deps)
        rep.checks["dependencies"] = dep_state
        rep.missing_dependencies = [d for d, ok in dep_state.items() if ok is False]
        if rep.missing_dependencies:
            rep.remediation.append("install missing dependencies: apt-get install -- " + " ".join(rep.missing_dependencies))
    if profile is None:
        rep.checks["note"] = "no verification profile: tool was not executed (passive checks only)"
        rep.ok = not rep.missing_dependencies
        return rep
    rep.executed = True
    ok = True
    for label, args in (("version", profile.version_args), ("help", profile.help_args)):
        if not args:
            continue
        res = probe(path, args)
        passed = res.returncode in profile.expected_exit_codes and not res.timed_out
        rep.checks[label] = {"args": args, "exit_code": res.returncode, "passed": passed, "timed_out": res.timed_out}
        if label == "version" and passed:
            rep.checks["version_output"] = (res.stdout or res.stderr).strip().splitlines()[:1]
        if not passed:
            ok = False
            rep.stderr = res.stderr
            rep.diagnostics += diagnose(res.stderr)
    if not ok:
        rep.remediation += rep.diagnostics or ["inspect stderr above; reinstall the tool via its recorded install method"]
    rep.ok = ok and not rep.missing_dependencies
    return rep
