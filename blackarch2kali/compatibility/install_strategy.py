"""Build and rank installation options from *verified evidence only*.

Every option is bound to a verified upstream repo and pinned to a commit/tag where one is known, so
plans are reproducible. Nothing is derived from unverified README text except identifiers that are
re-validated against the verified repository (e.g. a `go install` path must live under the same repo).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..analyzers.readme import ReadmeAnalysis
from ..models import BlackArchPackage, DebMatch, InstallOption, Maintenance, Method, RepoInfo
from ..security.command_safety import validate_package_name

_MAINT_SCORE = {Maintenance.ACTIVE: 10, Maintenance.MAINTAINED: 8, Maintenance.LOW_ACTIVITY: 5, Maintenance.UNKNOWN: 4, Maintenance.STALE: 2, Maintenance.ARCHIVED: 1}
_GO_INSTALL = re.compile(r"^go\s+install\s+(?:-\w+\s+)*(github\.com/[\w.-]+/[\w.-]+(?:/[\w./-]+)?)@([\w.\-+]+)$")
_DOCKER_IMAGE = re.compile(r"^docker\s+(?:pull|run)\s+(?:-[\w-]+(?:=\S+)?\s+)*([\w./-]+(?::[\w.-]+)?)\s*$")
_DOCKER_ELEVATED = re.compile(r"--privileged|--cap-add|--net(work)?[= ]host|--pid|--ipc|--device|\s-v\s|--volume|docker\.sock")
DEFAULT_WEIGHTS = {"reliability": 0.25, "security": 0.25, "reproducibility": 0.20, "isolation": 0.15, "maintenance": 0.15}


@dataclass
class StrategyContext:
    pkg: BlackArchPackage
    repo: RepoInfo | None
    maintenance: Maintenance
    readme: ReadmeAnalysis | None = None
    python2: bool = False
    kali: DebMatch | None = None
    debian: DebMatch | None = None
    host_arch: str = "amd64"
    host_is_kali: bool = True
    policy: dict[str, Any] = field(default_factory=dict)


def _ref(repo: RepoInfo) -> tuple[str, str] | None:
    """(kind, value) pin: prefer commit SHA, fall back to release tag."""
    if repo.head_sha:
        return "rev", repo.head_sha
    if repo.latest_release:
        return "tag", repo.latest_release
    return None


def _arch_ok(m: DebMatch, host: str) -> bool:
    return m.architecture in {"all", host}


def build_options(ctx: StrategyContext) -> list[InstallOption]:
    opts: list[InstallOption] = []
    repo = ctx.repo
    usable_repo = repo is not None and not repo.archived and not repo.disabled
    for m, label in ((ctx.kali, "kali"), (ctx.debian, "debian")):
        if m is None or not _arch_ok(m, ctx.host_arch):
            continue
        if label == "debian" and ctx.kali is not None:
            continue
        verified = m.confidence == "exact-name+homepage"
        notes = [f"{label} package {m.package} {m.version} ({m.architecture})"]
        if m.sha256:
            notes.append(f"index sha256={m.sha256}")
        if not verified:
            notes.append("package identity matched by name only (homepage mismatch/absent)")
        if label == "debian":
            notes.append("Debian-only package: requires Debian suites in apt sources; this tool never edits repositories")
        opts.append(InstallOption(method=Method.APT, commands=[["apt-get", "install", "--no-install-recommends", "--", m.package]], requires_root=True, verified=verified, notes=notes))
    if repo and usable_repo:
        pin = _ref(repo)
        root = {f.lower() for f in repo.root_files}
        url = repo.html_url
        py2 = ctx.python2
        if pin and ({"pyproject.toml", "setup.py", "setup.cfg"} & root) and not py2:
            spec = f"git+{url}@{pin[1]}"
            n = ["builds upstream Python code at install time; pinned to " + pin[1][:12], "console entry points not verified before install"]
            opts.append(InstallOption(method=Method.PIPX, commands=[["pipx", "install", "--", spec]], verified=True, notes=n))
            opts.append(InstallOption(method=Method.PYTHON_VENV, commands=[["python3", "-m", "venv", "@VENV@"], ["@VENV@/bin/pip", "install", "--", spec]], verified=True, notes=[*n, "isolated virtualenv under the state directory"]))
        if pin and "cargo.toml" in root:
            flag = "--rev" if pin[0] == "rev" else "--tag"
            opts.append(InstallOption(method=Method.CARGO, commands=[["cargo", "install", "--locked", "--git", url, flag, pin[1]]], verified=True, notes=["installed from the verified git repository, not a registry name"]))
        if pin and ctx.readme and "go.mod" in root:
            target = _go_target(ctx.readme, repo)
            if target:
                module, readme_ver = target
                opts.append(InstallOption(method=Method.GO, commands=[["go", "install", f"{module}@{pin[1]}"]], verified=True, notes=[f"module path from README, re-validated under {repo.full_name}; pinned to {pin[1][:12]} (README version {readme_ver} ignored)"]))
        if pin and "package.json" in root:
            opts.append(InstallOption(method=Method.NPM, commands=[["npm", "install", "--global", "--ignore-scripts", "--prefix", "@HOME@/.local", f"github:{repo.full_name}#{pin[1]}"]], verified=True, notes=["lifecycle scripts disabled (--ignore-scripts); may need a manual build step"]))
        if any(f.endswith(".gemspec") for f in root):
            opts.append(InstallOption(method=Method.GEM, commands=[["gem", "install", "--user-install", "--no-document", "--", ctx.pkg.name]], verified=False, notes=["RubyGems name is not proven to belong to the upstream repository; review before approving"]))
        if ctx.readme:
            trusted = [str(t) for t in ctx.policy.get("trusted_docker_registries", [])]
            for line in ctx.readme.install_commands:
                if _DOCKER_ELEVATED.search(line):
                    continue  # documented usage needs privileged/host access: not offered as a Docker option
                dm = _DOCKER_IMAGE.match(line.strip())
                if dm and _trusted_image(dm.group(1), repo, trusted):
                    opts.append(InstallOption(method=Method.DOCKER, commands=[["docker", "pull", dm.group(1)]], verified=True, notes=["image is in a trusted registry namespace owned by the upstream; runs unprivileged by default"]))
                    break
        if pin and root & {"makefile", "cmakelists.txt", "configure", "meson.build", "configure.ac"}:
            opts.append(InstallOption(method=Method.SOURCE_BUILD, commands=[["git", "clone", "--no-checkout", url, "@SRC@"], ["git", "-C", "@SRC@", "checkout", "--detach", pin[1]]], verified=True, notes=["fetches pinned source only; build steps are NOT run - review the build files, then build manually or with --allow-source-build"]))
    return opts


def _go_target(readme: ReadmeAnalysis, repo: RepoInfo) -> tuple[str, str] | None:
    allowed = {f"github.com/{repo.full_name.lower()}"}
    if repo.renamed_from:
        allowed.add(f"github.com/{repo.renamed_from.lower()}")
    for line in readme.install_commands:
        gm = _GO_INSTALL.match(line.strip())
        if gm and any(gm.group(1).lower() == a or gm.group(1).lower().startswith(a + "/") for a in allowed):
            return gm.group(1), gm.group(2)
    return None


def _trusted_image(image: str, repo: RepoInfo, trusted: list[str]) -> bool:
    name = image.split(":")[0].lower()
    parts = name.split("/")
    owner = repo.owner.lower()
    if parts[0] in {"ghcr.io", "quay.io"}:
        return f"{parts[0]}" in {t.lower().split("/")[0] for t in trusted} and len(parts) >= 3 and parts[1] == owner
    if "." in parts[0]:
        return False  # unknown registry
    if len(parts) == 1:
        return "docker.io/library" in {t.lower() for t in trusted}
    return len(parts) >= 2 and parts[0] == owner and any(t.lower().startswith("docker.io") for t in trusted)


def score_option(opt: InstallOption, maintenance: Maintenance, policy: dict[str, Any]) -> float:
    s = policy.get("method_scores", {}).get(opt.method.value)
    if not s:
        return 0.0
    w = DEFAULT_WEIGHTS
    total = sum(w[k] * float(s.get(k, 0)) for k in ("reliability", "security", "reproducibility", "isolation")) + w["maintenance"] * _MAINT_SCORE.get(maintenance, 4)
    if not opt.verified:
        total -= 3
    return round(total, 3)


def rank_options(options: list[InstallOption], maintenance: Maintenance, policy: dict[str, Any]) -> list[InstallOption]:
    """Deterministic ranking: score desc, then policy method order, then method name."""
    order = {m: i for i, m in enumerate(policy.get("method_preference", []))}
    scored = [o.model_copy(update={"score": score_option(o, maintenance, policy)}) for o in options]
    return sorted(scored, key=lambda o: (-o.score, order.get(o.method.value, 99), o.method.value))


def validate_option_names(options: list[InstallOption]) -> None:
    for o in options:
        for cmd in o.commands:
            if o.method is Method.APT:
                validate_package_name(cmd[-1])
