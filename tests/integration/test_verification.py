import os
import stat

import pytest

from blackarch2kali.compatibility.platform_detector import detect, parse_os_release
from blackarch2kali.config import Settings
from blackarch2kali.errors import UnsafeInputError
from blackarch2kali.validators.commands import diagnose, find_binary, probe
from blackarch2kali.validators.dependencies import package_installed
from blackarch2kali.validators.health import run_health
from blackarch2kali.validators.installation import (
    VerificationProfile,
    load_profiles,
    package_owner,
    verify_tool,
)


def script(dir, name, body):
    p = dir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


@pytest.fixture
def bindir(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    return d


def test_passing_tool(bindir):
    script(bindir, "goodtool", 'case "$1" in --version) echo "goodtool 1.2";; --help) echo usage;; esac')
    rep = verify_tool("goodtool", VerificationProfile(binary="goodtool", version_args=["--version"], help_args=["--help"]))
    assert rep.ok and rep.executed and rep.checks["version"]["passed"] and rep.checks["version_output"] == ["goodtool 1.2"]


def test_failing_tool_has_diagnostics(bindir):
    script(bindir, "badtool", 'echo "error while loading shared libraries: libfoo.so.1: cannot open" >&2; exit 127')
    rep = verify_tool("badtool", VerificationProfile(binary="badtool", version_args=["--version"]))
    assert not rep.ok and rep.checks["version"]["exit_code"] == 127
    assert any("libfoo.so.1" in d for d in rep.diagnostics) and "libfoo" in rep.stderr and rep.remediation


def test_missing_binary_and_passive_mode(bindir):
    rep = verify_tool("nonexistent-xyz")
    assert not rep.ok and not rep.checks["binary_exists"] and rep.remediation
    script(bindir, "passive", 'touch "$0.executed"; exit 0')
    rep = verify_tool("passive")  # no profile -> must NOT execute the tool
    assert rep.ok and not rep.executed and not (bindir / "passive.executed").exists()


def test_timeout_handled(bindir):
    script(bindir, "slow", "sleep 5")
    res = probe(find_binary("slow"), [], timeout=0.3)
    assert res.timed_out and res.returncode is None


def test_env_is_scrubbed_for_probes(bindir, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "q" * 36)
    script(bindir, "envtool", 'echo "tok=${GITHUB_TOKEN:-none}"')
    assert "tok=none" in probe(find_binary("envtool"), []).stdout


def test_invalid_tool_name_rejected():
    with pytest.raises(UnsafeInputError):
        verify_tool("../../bin/sh")


def test_diagnose_patterns():
    assert any("Python module" in d for d in diagnose("ModuleNotFoundError: No module named 'requests'"))
    assert any("Python 2" in d for d in diagnose('  File "x.py", line 3\n    print "hi"\nSyntaxError'))


def test_profiles_loaded_and_dependency_checks(tmp_path):
    assert set(load_profiles(__import__("pathlib").Path("config/verification_profiles.yaml"))) >= {"nmap", "sqlmap"}
    assert load_profiles(tmp_path / "missing.yaml") == {}
    assert package_installed("definitely-not-a-package-xyz") in (False, None)
    with pytest.raises(UnsafeInputError):
        package_installed("bad;name")
    assert package_owner(tmp_path / "x") is None


def test_platform_and_health(tmp_path):
    assert parse_os_release('ID=kali\nID_LIKE=debian\nVERSION_ID="2026.1"\n#c')["ID"] == "kali"
    f = tmp_path / "os-release"
    f.write_text("ID=kali\nID_LIKE=debian\n")
    pl = detect(f, which=lambda t: "/x/" + t if t in {"git"} else None)
    assert pl.is_kali and pl.is_debian_family and pl.has("git") and not pl.has("cargo")
    s = Settings(state_dir=tmp_path / "state")
    s.state_dir.mkdir()
    checks = {c.name: c for c in run_health(s, pl)}
    assert checks["database"].ok and checks["kali-host"].ok and checks["state-dir-writable"].ok
