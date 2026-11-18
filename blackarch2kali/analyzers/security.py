"""Static, non-executing security heuristics over metadata and text. Findings carry evidence."""

from __future__ import annotations

import re

from ..models import Risk, RiskDimension, RiskFinding
from .language import python2_only
from .readme import ReadmeAnalysis

_SECRET = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}")
_PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]?|<.+>|xxxx|\*\*\*|placeholder|dummy|test)")
_POSTINSTALL = re.compile(r"(?im)(postinstall|post-install|preinstall)\s*[\"']?\s*[:=]\s*[\"']?[^\n]*(curl|wget|bash|sh|eval|powershell)")
_DOWNLOAD = re.compile(r"(?i)\b(curl|wget)\b[^\n]*https?://")
_PRIV = re.compile(r"--privileged|--cap-add\s*=?\s*(ALL|SYS_ADMIN)|-v\s+/:/|/var/run/docker\.sock")
_HOSTNET = re.compile(r"--net(work)?[= ]host")


def scan_text(text: str, source: str) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for m in _SECRET.finditer(text[:300_000]):
        snippet = m.group(0)
        if _PLACEHOLDER.search(snippet):
            continue
        findings.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.MEDIUM, rule="hardcoded-credential-pattern",
                                    message=f"Possible hardcoded credential in {source}", evidence=snippet[:6] + "...[redacted]"))
        break
    m2 = _POSTINSTALL.search(text)
    if m2:
        findings.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule="suspicious-post-install",
                                    message=f"Install hook performs network/shell execution in {source}", evidence=m2.group(0)[:120]))
    m3 = _PRIV.search(text)
    if m3:
        findings.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule="privileged-container",
                                    message=f"Privileged/host-level container option referenced in {source}", evidence=m3.group(0)))
    m4 = _HOSTNET.search(text)
    if m4:
        findings.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.MEDIUM, rule="host-network-container", message=f"Host networking referenced in {source}; the framework never uses it by default", evidence=m4.group(0)))
    return findings


def analyze_text_risks(readme_text: str | None, readme: ReadmeAnalysis | None) -> list[RiskFinding]:
    """Risk findings from README content. Keywords alone never produce a 'malicious' verdict."""
    if not readme_text:
        return []
    out = scan_text(readme_text, "README")
    if readme:
        for cmd in readme.unsafe_installers[:3]:
            out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule="unsafe-shell-installer",
                                   message="README suggests piping a download into a shell (never executed by this tool)", evidence=cmd[:160]))
    if python2_only(readme_text):
        out.append(RiskFinding(dimension=RiskDimension.COMPATIBILITY, level=Risk.MEDIUM, rule="python2-only",
                               message="README references Python 2 and not Python 3", evidence="python2 reference"))
    if _DOWNLOAD.search(readme_text) and not any(f.rule == "unsafe-shell-installer" for f in out):
        out.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.LOW, rule="network-download-documented",
                               message="README documents a network download step", evidence=None))
    return out
