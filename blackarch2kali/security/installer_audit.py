"""Audit install options/plans for risky patterns. Pure analysis; never executes anything."""

from __future__ import annotations

from ..models import InstallOption, Method, Risk, RiskDimension, RiskFinding
from .command_safety import is_unsafe_installer_text, quote_argv

_PRIV = ("--privileged", "--cap-add", "--pid=host", "docker.sock")


def audit_options(options: list[InstallOption]) -> list[RiskFinding]:
    out: list[RiskFinding] = []
    for o in options:
        scope = "all" if o.method is Method.APT else "upstream"
        for cmd in o.commands:
            text = quote_argv(cmd)
            if is_unsafe_installer_text(text):
                out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.CRITICAL, rule="remote-exec-installer", message=f"{o.method.value} command pipes remote content to a shell", evidence=text[:160], scope=scope))
            if any(p in text for p in _PRIV):
                out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule="privileged-execution", message=f"{o.method.value} command requests elevated container/host access", evidence=text[:160], scope=scope))
        if not o.verified:
            out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.MEDIUM, rule="unverified-install-source", message=f"{o.method.value} option lacks verified identity", evidence="; ".join(o.notes)[:160], scope=scope))
        if o.method is Method.SOURCE_BUILD:
            out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.LOW, rule="source-build-review", message="Source build requires manual review of build files before running", scope="upstream"))
    return out
