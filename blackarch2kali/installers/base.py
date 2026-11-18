"""Installer framework: plan -> (explicit approval of the plan digest) -> execute -> verify.

Safety properties enforced here for every ecosystem:
* default is dry-run; execution requires the exact plan digest to be supplied as approval;
* commands are argv lists executed with shell=False and a scrubbed environment (no tokens);
* every step is re-validated against a strict per-ecosystem pattern immediately before execution,
  so a tampered or hand-edited plan cannot smuggle in arbitrary commands.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

from pydantic import BaseModel, Field

from ..errors import InstallError, UnsafeInputError
from ..logging_utils import redact
from ..models import InstallOption, Method, utcnow_iso
from ..security.command_safety import SAFE_ENV_KEYS, safe_argv, validate_tool_name

log = logging.getLogger(__name__)

GH_REPO = r"https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}"
REF = r"[0-9A-Za-z][0-9A-Za-z._+/-]{0,99}"


class InstallPlan(BaseModel):
    tool: str
    method: Method
    steps: list[list[str]]
    requires_root: bool = False
    verified: bool = True
    notes: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utcnow_iso)

    @property
    def digest(self) -> str:
        """Approval binds to what will run: tool, method and exact steps (not timestamps/notes)."""
        payload = json.dumps({"tool": self.tool, "method": self.method.value, "steps": self.steps, "root": self.requires_root}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class StepResult:
    argv: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    skipped: bool = False


@dataclass
class ExecutionResult:
    plan_digest: str
    dry_run: bool
    steps: list[StepResult] = field(default_factory=list)
    success: bool = False
    error: str | None = None


class Runner(Protocol):
    def run(self, argv: list[str], timeout: float) -> tuple[int, str, str]: ...


class SubprocessRunner:
    def run(self, argv: list[str], timeout: float = 1800) -> tuple[int, str, str]:
        env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_KEYS}
        try:
            p = subprocess.run(safe_argv(argv), capture_output=True, text=True, timeout=timeout, env=env, shell=False, check=False)  # noqa: S603  # nosec B603
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {timeout}s"
        except OSError as exc:
            return 127, "", str(exc)
        return p.returncode, p.stdout[-20000:], p.stderr[-20000:]


class Installer:
    method: ClassVar[Method]
    binary: ClassVar[str]
    rollback_hint: ClassVar[str] = ""

    def __init__(self, work_dir: Path, home: Path | None = None) -> None:
        self.work_dir = work_dir
        self.home = home or Path.home()

    # -- to be provided per ecosystem -----------------------------------------------------
    def step_patterns(self) -> list[list[str]]:
        """Regexes, one list per allowed step shape (full-match per argv element)."""
        raise NotImplementedError

    def rollback_for(self, tool: str, steps: list[list[str]]) -> list[str]:
        return [self.rollback_hint] if self.rollback_hint else []

    # -- shared ---------------------------------------------------------------------------
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def tool_dir(self, tool: str) -> Path:
        validate_tool_name(tool)
        return self.work_dir / "tools" / tool

    def expand(self, tool: str, argv: list[str]) -> list[str]:
        d = self.tool_dir(tool)
        mapping = {"@HOME@": str(self.home), "@VENV@": str(d / "venv"), "@SRC@": str(d / "src")}
        out = []
        for a in argv:
            for k, v in mapping.items():
                a = a.replace(k, v)
            out.append(a)
        return out

    def validate_step(self, argv: list[str]) -> None:
        safe_argv(argv)
        for shape in self.step_patterns():
            if len(shape) == len(argv) and all(re.fullmatch(p, a) for p, a in zip(shape, argv, strict=True)):
                return
        raise UnsafeInputError(f"{self.method.value}: command not allowed: {redact(' '.join(argv))[:200]}")

    def make_plan(self, tool: str, option: InstallOption) -> InstallPlan:
        if option.method is not self.method:
            raise InstallError(f"option method {option.method} does not match installer {self.method}")
        if option.blocked_reason:
            raise InstallError(f"option blocked: {option.blocked_reason}")
        steps = [self.expand(tool, list(c)) for c in option.commands]
        for s in steps:
            self.validate_step(s)
        return InstallPlan(tool=tool, method=self.method, steps=steps, requires_root=option.requires_root, verified=option.verified,
                           notes=list(option.notes), rollback=self.rollback_for(tool, steps))

    def missing_prerequisites(self) -> list[str]:
        return [] if self.available() else [f"required tool not found on PATH: {self.binary}"]

    def execute(self, plan: InstallPlan, runner: Runner | None = None, *, dry_run: bool = True, approved_digest: str | None = None,
                allow_unverified: bool = False, timeout: float = 1800) -> ExecutionResult:
        result = ExecutionResult(plan_digest=plan.digest, dry_run=dry_run)
        for s in plan.steps:  # re-validate: plans can be edited on disk
            self.validate_step(s)
        if dry_run:
            result.steps = [StepResult(s, None, skipped=True) for s in plan.steps]
            result.success = True
            return result
        if approved_digest != plan.digest:
            raise InstallError("Approval does not match this plan (digest mismatch); re-run `plan` and approve the exact plan")
        if not plan.verified and not allow_unverified:
            raise InstallError("Plan contains unverified identity evidence; pass --allow-unverified after manual review")
        if (missing := self.missing_prerequisites()):
            raise InstallError("; ".join(missing))
        runner = runner or SubprocessRunner()
        sudo = ["sudo"] if plan.requires_root and hasattr(os, "geteuid") and os.geteuid() != 0 else []
        if sudo and not shutil.which("sudo"):
            raise InstallError("root privileges required but sudo is unavailable")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        for s in plan.steps:
            argv = sudo + s
            log.info("executing: %s", redact(" ".join(argv)))
            rc, out, err = runner.run(argv, timeout)
            result.steps.append(StepResult(s, rc, redact(out), redact(err)))
            if rc != 0:
                result.error = f"step failed with exit code {rc}: {' '.join(s)[:120]}"
                return result
        result.success = True
        return result
