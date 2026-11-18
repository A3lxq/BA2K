"""Upstream identity verification. A repository listed in BlackArch metadata is NOT trusted automatically."""

from __future__ import annotations

from typing import Any

from ..analyzers.license import license_mismatch
from ..collectors.upstream import classify
from ..compatibility.package_mapper import same_upstream
from ..models import BlackArchPackage, DebMatch, RepoInfo, Risk, RiskDimension, RiskFinding


def verify_upstream(pkg: BlackArchPackage, repo: RepoInfo | None, kali: DebMatch | None, debian: DebMatch | None, *, repo_missing: bool = False) -> tuple[dict[str, Any], list[RiskFinding]]:
    up = classify(pkg.url)
    findings: list[RiskFinding] = []
    v: dict[str, Any] = {"blackarch_url": pkg.url, "url_kind": up.kind, "repo_verified": False, "corroborated_by_distro": False, "checks": []}

    def add(level: Risk, rule: str, msg: str, evidence: str | None = None, dim: RiskDimension = RiskDimension.INSTALLATION) -> None:
        findings.append(RiskFinding(dimension=dim, level=level, rule=rule, message=msg, evidence=evidence, scope="upstream"))

    if up.kind == "invalid":
        scheme = str(pkg.url).split(":", 1)[0].lower()
        if scheme in {"javascript", "data", "file", "vbscript"}:
            add(Risk.HIGH, "unsafe-url-scheme", "Upstream URL uses a dangerous scheme", str(pkg.url)[:120])
        else:
            add(Risk.MEDIUM, "upstream-url-unusable", "Upstream URL is malformed or not an allowed host (raw IP/local); cannot be verified", str(pkg.url)[:120])
        return v, findings
    if up.kind != "github":
        v["checks"].append(f"upstream is {up.kind}; GitHub repository intelligence not applicable")
        return v, findings
    if repo is None and not repo_missing:
        v["checks"].append("GitHub repository not fetched yet (metadata pending)")
        return v, findings
    if repo is None:
        add(Risk.MEDIUM, "upstream-repo-missing", "GitHub repository could not be found (deleted, private or renamed without redirect)", pkg.url, RiskDimension.MAINTENANCE)
        v["checks"].append("repository not found")
        return v, findings
    v["repo_verified"] = True
    v["verified_repo"] = repo.full_name
    v["owner"] = repo.owner
    if repo.renamed_from:
        v["checks"].append(f"repository renamed/transferred: {repo.renamed_from} -> {repo.full_name}")
        add(Risk.LOW, "repository-renamed", "Repository was renamed or transferred; confirm the new owner is the legitimate maintainer", f"{repo.renamed_from} -> {repo.full_name}")
    if repo.fork:
        add(Risk.HIGH, "upstream-is-fork", "Referenced repository is a fork, not an original upstream; verify it is the intended maintained project", repo.full_name)
    if repo.archived:
        add(Risk.MEDIUM, "repository-archived", "Repository is archived (read-only, no security fixes)", repo.full_name, RiskDimension.MAINTENANCE)
    if repo.disabled:
        add(Risk.HIGH, "repository-disabled", "Repository is disabled by GitHub", repo.full_name)
    for m in (kali, debian):
        if m and same_upstream(m.homepage, repo.html_url):
            v["corroborated_by_distro"] = True
            v["checks"].append(f"{m.distribution} package homepage matches upstream")
    if (kali or debian) and not v["corroborated_by_distro"]:
        add(Risk.LOW, "distro-homepage-mismatch", "Distro package homepage does not match the BlackArch upstream", None)
    if license_mismatch(pkg.license, repo.license):
        add(Risk.LOW, "license-mismatch", "BlackArch and GitHub report different license classes", f"{pkg.license} vs {repo.license}", RiskDimension.COMPATIBILITY)
    if not v["corroborated_by_distro"]:
        v["checks"].append("no independent corroboration of upstream identity beyond BlackArch metadata")
    return v, findings
