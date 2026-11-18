"""Analysis engine: turns discovered metadata into a ToolRecord. Pure computation - no installs, no execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .analyzers.language import primary_language
from .analyzers.maintenance import classify_maintenance
from .analyzers.readme import analyze_readme
from .categories import research_categories
from .collectors.debian import DebIndex
from .collectors.upstream import classify
from .compatibility.dependency_resolver import DependencyResolver
from .compatibility.engine import evaluate
from .compatibility.install_strategy import StrategyContext
from .compatibility.package_mapper import map_package
from .compatibility.platform_detector import Platform
from .config import Settings
from .models import (
    UNKNOWN,
    BlackArchPackage,
    Compatibility,
    Maintenance,
    Method,
    RepoInfo,
    RiskFinding,
    ToolRecord,
)
from .security.installer_audit import audit_options
from .security.risk_engine import assess
from .security.source_validation import verify_upstream
from .validators.installation import VerificationProfile


@dataclass
class AnalysisContext:
    settings: Settings
    policy: dict[str, Any]
    platform: Platform
    packages: dict[str, BlackArchPackage]
    kali: DebIndex | None
    debian: DebIndex | None
    categories_cfg: dict[str, dict[str, Any]] = field(default_factory=dict)
    dep_aliases: dict[str, list[str]] = field(default_factory=dict)
    profiles: dict[str, VerificationProfile] = field(default_factory=dict)
    now: datetime | None = None
    missing_repos: set[str] = field(default_factory=set)  # slugs GitHub reported 404 for

    def __post_init__(self) -> None:
        self.resolver = DependencyResolver(self.packages, self.kali, self.debian, self.platform.deb_arch, self.dep_aliases)
        self.replaced_by: dict[str, list[str]] = {}
        for p in self.packages.values():
            for old in p.replaces:
                self.replaced_by.setdefault(old.split("<")[0].split(">")[0].split("=")[0], []).append(p.name)


def _prov(obj: Any) -> dict[str, Any]:
    return dict(obj.provenance.model_dump())


def analyze_package(pkg: BlackArchPackage, repo: RepoInfo | None, ctx: AnalysisContext) -> ToolRecord:
    th = ctx.settings.maintenance
    mapping = map_package(pkg, ctx.kali, ctx.debian)
    maint, maint_reasons = classify_maintenance(repo, th, ctx.now)
    readme = analyze_readme("\n".join(repo.readme_install_commands)) if repo else None
    sctx = StrategyContext(pkg=pkg, repo=repo, maintenance=maint, readme=readme, python2=bool(repo and repo.readme_python2_only),
                           host_arch=ctx.platform.deb_arch, host_is_kali=ctx.platform.is_kali, policy=ctx.policy)
    compat = evaluate(sctx, mapping)
    res = ctx.resolver.resolve(pkg.name)
    gh = classify(pkg.url).github
    repo_missing = repo is None and gh is not None and f"{gh[0]}/{gh[1]}".lower() in ctx.missing_repos
    verification, src_findings = verify_upstream(pkg, repo, mapping.kali, mapping.debian, repo_missing=repo_missing)
    findings: list[RiskFinding] = list(src_findings) + audit_options(compat.options)
    if repo:
        findings += [RiskFinding.model_validate(f) for f in repo.readme_findings]
    py2_deps = [d for d in pkg.depends if d.split(">")[0].split("=")[0].split("<")[0].startswith(("python2", "python2-"))]
    unverified_native = any(m is not None and m.confidence != "exact-name+homepage" for m in (mapping.kali, mapping.debian))
    risk = assess(findings, maintenance=maint, compat=compat.primary, repo_known=repo is not None, missing_deps=len(res.missing), python2_deps=py2_deps, unverified_native=unverified_native)
    blocked_levels = [str(x) for x in ctx.policy.get("blocked_risk_levels", ["HIGH", "CRITICAL"])]
    options = []
    for o in compat.options:
        lvl = risk.level_for(o.method)
        o = o.model_copy(update={"blocked_reason": f"risk {lvl.value} requires manual review"} if lvl.value in blocked_levels else {})
        options.append(o)
    usable = [o for o in options if not o.blocked_reason]
    preferred = usable[0] if usable else None
    official, derived = research_categories(pkg, ctx.categories_cfg)
    lang = primary_language(repo)
    profile = ctx.profiles.get(pkg.name)
    dep_names = sorted({*res.apt_packages, *res.blackarch_deps})
    notes = list(compat.notes) + [f"maintenance: {r}" for r in maint_reasons]
    if res.missing:
        notes.append(f"unresolved dependencies: {', '.join(res.missing[:10])}")
    if res.cycles:
        notes.append("dependency cycle detected")
    if res.version_conflicts:
        notes.append(f"version conflicts: {len(res.version_conflicts)}")
    if preferred is None and options:
        notes.append("all install options blocked pending manual review")
    repro: dict[str, Any] = {
        "blackarch_version": pkg.version, "blackarch_sha256": pkg.sha256, "blackarch_filename": pkg.filename,
        "upstream_head_sha": repo.head_sha if repo else None, "upstream_latest_release": repo.latest_release if repo else None,
    }
    for label, m in (("kali", mapping.kali), ("debian", mapping.debian)):
        if m:
            repro[f"{label}_version"] = m.version
            repro[f"{label}_sha256"] = m.sha256
            repro[f"{label}_filename"] = m.filename
    return ToolRecord(
        tool_name=pkg.name, blackarch_package=pkg.name, category=pkg.categories, research_categories=official, derived_categories=derived, description=pkg.description or None,
        github_repo=repo.html_url if repo else None, official_website=pkg.url, language=lang, stars=repo.stars if repo else None,
        forks=repo.forks if repo else None, open_issues=repo.open_issues if repo else None, last_commit=repo.last_commit if repo else None,
        latest_release=repo.latest_release if repo else None, license=(repo.license if repo and repo.license else (", ".join(pkg.license) or None)),
        maintained=True if maint in {Maintenance.ACTIVE, Maintenance.MAINTAINED} else (None if maint is Maintenance.UNKNOWN else False),
        maintenance_status=maint.value, kali_compatibility=compat.primary.value if compat.primary is not Compatibility.UNKNOWN else UNKNOWN,
        installation_methods=[o.method.value for o in options], preferred_install_method=preferred.method.value if preferred else None,
        dependencies=dep_names, install_commands=preferred.commands if preferred else [],
        install_options=[o.model_dump(mode="json") for o in options],
        verification_command=[profile.binary, *profile.version_args] if profile else None,
        docker_support=True if any(o.method is Method.DOCKER for o in options) else None,
        security_risk=risk.overall.value, risk_findings=[f.model_dump(mode="json") for f in risk.findings],
        source_provenance=[_prov(pkg)] + ([_prov(repo)] if repo else []) + [_prov(m) for m in (mapping.kali, mapping.debian) if m],
        last_checked=(ctx.now or datetime.now().astimezone()).isoformat(timespec="seconds"), notes=notes,
        replacement_if_dead=", ".join(sorted(ctx.replaced_by.get(pkg.name, []))) or None,
        upstream_verification=verification, reproducibility=repro,
        dependency_resolution={k: v for k, v in res.to_dict().items() if k not in {"root"} and v},
    )

