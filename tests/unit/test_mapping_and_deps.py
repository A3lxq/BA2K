import pytest

from blackarch2kali.collectors.blackarch import parse_db
from blackarch2kali.collectors.debian import parse_packages
from blackarch2kali.compatibility.dependency_resolver import (
    DependencyResolver,
    compare_versions,
    find_cycles,
    parse_relation,
    satisfies,
)
from blackarch2kali.compatibility.package_mapper import map_package, normalize_url, same_upstream
from blackarch2kali.models import BlackArchPackage, Provenance


@pytest.fixture
def pkgs(ba_db_bytes):
    return parse_db(ba_db_bytes, "u").packages


@pytest.fixture
def kali(kali_text):
    return parse_packages(kali_text, "kali", "u")


def mk(name, url=None, depends=(), version="1.0-1", provides=()):
    return BlackArchPackage(name=name, version=version, url=url, depends=list(depends), provides=list(provides), provenance=Provenance(source="t"))


def test_exact_match_with_homepage_verified(pkgs, kali):
    m = map_package(pkgs["amass"], kali, None)
    assert m.kali and m.kali.package == "amass" and m.kali.confidence == "exact-name+homepage"
    assert m.kali.sha256 and m.kali.filename.endswith(".deb")


def test_name_collision_flagged_unverified(pkgs, kali):
    m = map_package(pkgs["ace"], kali, None)  # BlackArch 'ace' is not the Kali 'ace'
    assert m.kali and m.kali.confidence == "exact-name" and any("unverified" in n for n in m.notes)


def test_no_substring_matching(pkgs, kali):
    assert map_package(mk("amas"), kali, None).kali is None
    assert map_package(mk("amass-extra"), kali, None).kali is None


def test_transformed_name_needs_homepage(kali):
    # python3-pip exists in the index; a BlackArch 'python-pip' with a different homepage must NOT map.
    assert map_package(mk("python-pip", "https://example.org/other"), kali, None).kali is None


def test_url_normalisation():
    assert normalize_url("https://www.GitHub.com/A/B.git/") == "github.com/a/b"
    assert same_upstream("https://github.com/o/r", "http://github.com/o/r/releases")
    assert not same_upstream("https://github.com/o/r", "https://github.com/o/other")
    assert not same_upstream(None, "https://github.com/o/r")


def test_parse_relation():
    assert parse_relation("foo>=1.2") == ("foo", ">=", "1.2")
    assert parse_relation("foo: optional reason") == ("foo", None, None)
    assert parse_relation("lib++") == ("lib++", None, None)
    with pytest.raises(ValueError):
        parse_relation("bad name; rm -rf /")


def test_version_compare_and_constraints():
    assert compare_versions("1.10", "1.9") > 0
    assert compare_versions("1:2.0-1", "2.0-3") == 0  # epoch/revision stripped by design
    assert compare_versions("1.0~rc1", "1.0") < 0
    assert satisfies("2.0", ">=", "1.5") and not satisfies("1.0", ">", "1.0") and satisfies("1.0", None, None)


def test_cycles_detected():
    g = {"a": ["b"], "b": ["c"], "c": ["a"], "d": ["d"], "e": ["a"]}
    cyc = find_cycles(g)
    assert ["a", "b", "c"] in cyc and ["d"] in cyc and len(cyc) == 2
    assert find_cycles({"a": ["b"], "b": []}) == []


def test_resolution_missing_alias_conflicts_and_order(kali):
    packages = {
        "root": mk("root", depends=["libxslt", "mid", "ghost-lib", "python>=99.0", "bash"]),
        "mid": mk("mid", depends=["leaf"]),
        "leaf": mk("leaf", depends=["mid"]),  # cycle mid<->leaf
    }
    r = DependencyResolver(packages, kali, None, aliases={"libxslt": ["libxslt1.1"], "python": ["python3"]}).resolve("root")
    assert "libxslt1.1" in r.apt_packages and "bash" in r.apt_packages
    assert "ghost-lib" in r.missing and "libxslt" not in r.missing
    assert any(c["dependency"] == "python" for c in r.version_conflicts)
    assert r.cycles and sorted(r.cycles[0]) == ["leaf", "mid"]
    assert r.install_order[-1] == "root" and set(r.blackarch_deps) == {"mid", "leaf"}


def test_architecture_conflict(kali):
    arm_only = kali.by_name["bash"].model_copy(update={"architecture": "s390x"})
    kali.by_name["bash"] = arm_only
    r = DependencyResolver({"x": mk("x", depends=["bash"])}, kali, None, host_arch="amd64").resolve("x")
    assert r.arch_conflicts


def test_unknown_root_and_python_prefix_fallback(kali):
    assert DependencyResolver({}, kali, None).resolve("nope").missing == ["nope"]
    r = DependencyResolver({"x": mk("x", depends=["python-pip"])}, kali, None).resolve("x")
    assert r.apt_packages == ["python3-pip"] and not r.missing
