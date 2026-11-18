"""Regression tests. Each 'BUG-n' test pins a defect found while building the project."""

import httpx
import pytest
import yaml

from blackarch2kali.analysis import AnalysisContext, analyze_package
from blackarch2kali.collectors.blackarch import parse_db
from blackarch2kali.collectors.debian import parse_packages
from blackarch2kali.collectors.github import GitHubCollector
from blackarch2kali.compatibility.platform_detector import Platform
from blackarch2kali.config import Settings
from blackarch2kali.errors import CollectorError, RateLimitError
from blackarch2kali.models import BlackArchPackage, Provenance, RepoInfo
from tests.conftest import FIX, make_client

POLICY = yaml.safe_load(open("config/installation_policies.yaml"))
P = Provenance(source="t")


def gh(handler):
    return GitHubCollector(make_client(handler, max_retries=1), Settings())


# ---- error-handling matrix -------------------------------------------------------------------
def test_github_404_means_no_repo():
    assert gh(lambda r: httpx.Response(404)).fetch_repo("o", "r") is None
    assert gh(lambda r: httpx.Response(410)).fetch_repo("o", "r") is None


def test_github_403_forbidden_is_error_not_silent_empty():
    with pytest.raises(CollectorError):
        gh(lambda r: httpx.Response(403, json={"message": "Resource not accessible"})).fetch_repo("o", "r")


def test_github_rate_limit_surfaces_as_ratelimit_error():
    with pytest.raises(RateLimitError):
        gh(lambda r: httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "99999999999"})).fetch_repo("o", "r")


def test_github_500_and_timeout_are_collector_errors():
    with pytest.raises(CollectorError):
        gh(lambda r: httpx.Response(500)).fetch_repo("o", "r")

    def boom(req):
        raise httpx.ReadTimeout("t")

    with pytest.raises(CollectorError):
        gh(boom).fetch_repo("o", "r")


def test_partial_enrichment_failure_keeps_core_data():
    def h(req):
        p = req.url.path
        if p == "/repos/o/r":
            return httpx.Response(200, json={"full_name": "o/r", "name": "r", "owner": {"login": "o"}, "html_url": "https://github.com/o/r", "default_branch": "main", "stargazers_count": 5})
        return httpx.Response(500)

    info = gh(h).fetch_repo("o", "r")
    assert info and info.stars == 5 and info.latest_release is None and info.head_sha is None


def test_github_response_with_wrong_types_does_not_crash():
    def h(req):
        if req.url.path == "/repos/o/r":
            return httpx.Response(200, json={"full_name": "o/r", "name": "r", "owner": {"login": "o"}, "html_url": "https://github.com/o/r", "license": None, "topics": None})
        if req.url.path.endswith("/commits"):
            return httpx.Response(200, json=[{"sha": "nothex", "commit": {}}])
        return httpx.Response(200, json={"unexpected": True})

    info = gh(h).fetch_repo("o", "r")
    assert info and info.head_sha is None and info.languages == {} and info.license is None


# ---- BUG-1: GitHub 'Other'/NOASSERTION license was reported as a real license ---------------------
def test_bug1_noassertion_license_is_unknown():
    def h(req):
        if req.url.path == "/repos/o/r":
            return httpx.Response(200, json={"full_name": "o/r", "name": "r", "owner": {"login": "o"}, "html_url": "https://github.com/o/r",
                                             "license": {"key": "other", "name": "Other", "spdx_id": "NOASSERTION"}})
        return httpx.Response(404)

    assert gh(h).fetch_repo("o", "r").license is None


# ---- BUG-2: renamed repositories (HTTP 301) must be followed and recorded -------------------------
def test_bug2_renamed_repo_followed_and_recorded():
    def h(req):
        if req.url.path == "/repos/old/name":
            return httpx.Response(301, headers={"location": "https://api.github.com/repos/new/name"})
        if req.url.path == "/repos/new/name":
            return httpx.Response(200, json={"full_name": "new/name", "name": "name", "owner": {"login": "new"}, "html_url": "https://github.com/new/name"})
        return httpx.Response(404)

    info = gh(h).fetch_repo("old", "name")
    assert info and info.full_name == "new/name" and info.renamed_from == "old/name"


# ---- BUG-3: unfetched repos were flagged as 'missing' (false MEDIUM finding) ----------------------
def test_bug3_unfetched_repo_not_reported_missing(ba_db_bytes, kali_text):
    pk = parse_db(ba_db_bytes, "u").packages
    ctx = AnalysisContext(Settings(), POLICY, Platform("kali"), pk, parse_packages(kali_text, "kali", "u"), None)
    rec = analyze_package(pk["amass"], None, ctx)
    assert "upstream-repo-missing" not in {f["rule"] for f in rec.risk_findings}
    ctx.missing_repos = {"owasp/amass"}
    assert "upstream-repo-missing" in {f["rule"] for f in analyze_package(pk["amass"], None, ctx).risk_findings}


# ---- BUG-4: sync path imported installers through validators (violated discovery/execution split) ----
def test_bug4_validators_commands_has_no_installer_import():
    import blackarch2kali.validators.commands as m

    assert "installers" not in open(m.__file__).read()


# ---- BUG-5: `docker run --privileged` README lines were reduced to a plain pull option --------------
def test_bug5_privileged_docker_usage_not_offered():
    from blackarch2kali.analyzers.readme import analyze_readme
    from blackarch2kali.compatibility.install_strategy import StrategyContext, build_options
    from blackarch2kali.models import Maintenance, Method

    repo = RepoInfo(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", head_sha="a" * 40, provenance=P)
    for line in ("docker run --privileged o/r", "docker run --net=host o/r", "docker run -v /:/host o/r"):
        ctx = StrategyContext(pkg=BlackArchPackage(name="r", version="1", provenance=P), repo=repo, maintenance=Maintenance.ACTIVE, readme=analyze_readme(line), policy=POLICY)
        assert all(o.method is not Method.DOCKER for o in build_options(ctx)), line


# ---- BUG-6: a redirect from the API host to a plain-http/internal address was followed ---------------
def test_bug6_redirect_to_internal_address_blocked():
    from blackarch2kali.errors import UnsafeInputError

    c = make_client(lambda r: httpx.Response(302, headers={"location": "https://169.254.169.254/x"}), max_retries=0)
    with pytest.raises(UnsafeInputError):
        c.get("https://x.example/a")


# ---- BUG-7: dependency graph rebuilt per package (analysis took minutes) ---------------------------------
def test_bug7_graph_is_cached():
    from blackarch2kali.compatibility.dependency_resolver import DependencyResolver

    r = DependencyResolver({"a": BlackArchPackage(name="a", version="1", depends=["b"], provenance=P), "b": BlackArchPackage(name="b", version="1", provenance=P)}, None, None)
    assert r.resolve_graph() is r.resolve_graph()


# ---- malformed / edge metadata -------------------------------------------------------------------------
def test_malformed_kali_index_blocks_tolerated():
    idx = parse_packages("garbage line\n\nPackage: ok\nVersion: 1\nArchitecture: amd64\n\nPackage: noversion\n\n: :\n", "kali", "u")
    assert list(idx.by_name) == ["ok"]


def test_python2_only_dependency_and_unsupported_arch_end_to_end(kali_text):
    pkg = BlackArchPackage(name="oldtool", version="1", arch="x86_64", depends=["python2", "python2-requests"], url="https://github.com/o/oldtool", provenance=P)
    ctx = AnalysisContext(Settings(), POLICY, Platform("kali", deb_arch="arm64"), {"oldtool": pkg}, parse_packages(kali_text, "kali", "u"), None)
    rec = analyze_package(pkg, None, ctx)
    assert "python2-dependency" in {f["rule"] for f in rec.risk_findings}
    arm = analyze_package(BlackArchPackage(name="amass", version="1", url="https://github.com/OWASP/Amass", provenance=P), None,
                          AnalysisContext(Settings(), POLICY, Platform("kali", deb_arch="s390x"), {}, parse_packages(kali_text, "kali", "u"), None))
    assert arm.kali_compatibility == "INCOMPATIBLE" and arm.preferred_install_method is None


def test_archived_repo_blocks_upstream_methods_and_marks_legacy(ba_db_bytes):
    pk = parse_db(ba_db_bytes, "u").packages
    repo = RepoInfo(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", archived=True, head_sha="a" * 40, root_files=["pyproject.toml"], provenance=P)
    ctx = AnalysisContext(Settings(), POLICY, Platform("kali"), pk, None, None)
    rec = analyze_package(pk["0d1n"], repo, ctx)
    assert rec.maintenance_status == "ARCHIVED" and rec.kali_compatibility == "LEGACY" and "PIPX" not in rec.installation_methods
    assert FIX.exists()
