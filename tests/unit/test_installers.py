import hashlib

import httpx
import pytest

from blackarch2kali.errors import InstallError, UnsafeInputError
from blackarch2kali.installers import get_installer
from blackarch2kali.installers.binary import install_binary
from blackarch2kali.models import InstallOption, Method
from tests.conftest import make_client

SHA = "a" * 40


class FakeRunner:
    def __init__(self, codes=None):
        self.calls = []
        self.codes = codes or {}

    def run(self, argv, timeout):
        self.calls.append(argv)
        return self.codes.get(len(self.calls), 0), "out ghp_" + "x" * 36, "err"


def opt(method, cmds, **kw):
    kw.setdefault("verified", True)
    return InstallOption(method=method, commands=cmds, **kw)


@pytest.fixture
def work(tmp_path):
    return tmp_path / "state"


def test_dry_run_default_executes_nothing(work):
    inst = get_installer(Method.APT, work)
    plan = inst.make_plan("amass", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "amass"]], requires_root=True))
    r = FakeRunner()
    res = inst.execute(plan, r)
    assert res.dry_run and res.success and r.calls == [] and res.steps[0].skipped


def test_execution_requires_matching_digest(work):
    inst = get_installer(Method.APT, work)
    plan = inst.make_plan("amass", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "amass"]]))
    for bad in (None, "0" * 64):
        with pytest.raises(InstallError):
            inst.execute(plan, FakeRunner(), dry_run=False, approved_digest=bad)


def test_execute_runs_argv_and_redacts_output(work, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    inst = get_installer(Method.APT, work)
    plan = inst.make_plan("amass", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "amass"]], requires_root=True))
    r = FakeRunner()
    res = inst.execute(plan, r, dry_run=False, approved_digest=plan.digest)
    assert res.success and r.calls == [plan.steps[0]]
    assert "ghp_" not in res.steps[0].stdout


def test_sudo_prefix_when_not_root(work, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    inst = get_installer(Method.APT, work)
    plan = inst.make_plan("amass", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "amass"]], requires_root=True))
    r = FakeRunner()
    inst.execute(plan, r, dry_run=False, approved_digest=plan.digest)
    assert r.calls[0][0] == "sudo"


def test_failure_stops_and_reports_exit_code(work, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    inst = get_installer(Method.PYTHON_VENV, work)
    plan = inst.make_plan("t", opt(Method.PYTHON_VENV, [["python3", "-m", "venv", "@VENV@"], ["@VENV@/bin/pip", "install", "--", f"git+https://github.com/o/r@{SHA}"]]))
    r = FakeRunner({1: 3})
    res = inst.execute(plan, r, dry_run=False, approved_digest=plan.digest)
    assert not res.success and "exit code 3" in (res.error or "") and len(r.calls) == 1
    assert plan.rollback


def test_unverified_plan_needs_flag(work, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/" + x)
    inst = get_installer(Method.GEM, work)
    plan = inst.make_plan("t", opt(Method.GEM, [["gem", "install", "--user-install", "--no-document", "--", "t"]], verified=False))
    with pytest.raises(InstallError):
        inst.execute(plan, FakeRunner(), dry_run=False, approved_digest=plan.digest)
    assert inst.execute(plan, FakeRunner(), dry_run=False, approved_digest=plan.digest, allow_unverified=True).success


def test_missing_prerequisite(work, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    inst = get_installer(Method.CARGO, work)
    plan = inst.make_plan("t", opt(Method.CARGO, [["cargo", "install", "--locked", "--git", "https://github.com/o/r", "--rev", SHA]]))
    with pytest.raises(InstallError, match="cargo"):
        inst.execute(plan, FakeRunner(), dry_run=False, approved_digest=plan.digest)


def test_blocked_option_and_wrong_method_rejected(work):
    inst = get_installer(Method.APT, work)
    with pytest.raises(InstallError):
        inst.make_plan("x", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "x"]], blocked_reason="risk HIGH"))
    with pytest.raises(InstallError):
        inst.make_plan("x", opt(Method.PIPX, [["pipx", "install", "--", "x"]]))


def test_digest_changes_with_steps(work):
    inst = get_installer(Method.APT, work)
    a = inst.make_plan("x", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "x"]]))
    b = inst.make_plan("x", opt(Method.APT, [["apt-get", "install", "--no-install-recommends", "--", "y"]]))
    assert a.digest != b.digest and a.digest == a.model_copy(update={"notes": ["changed"]}).digest


def test_generic_installer_missing_for_binary():
    with pytest.raises(KeyError):
        get_installer(Method.OFFICIAL_BINARY_RELEASE, __import__("pathlib").Path("."))


def test_binary_release_checksum_enforced(tmp_path):
    data = b"\x7fELF-fake"
    c = make_client(lambda r: httpx.Response(200, content=data))
    sha = hashlib.sha256(data).hexdigest()
    p = install_binary(c, "mytool", "https://example.org/mytool", sha, tmp_path, confirmed=True)
    assert p.read_bytes() == data and p.stat().st_mode & 0o111
    with pytest.raises(InstallError, match="checksum"):
        install_binary(c, "mytool", "https://example.org/mytool", "0" * 64, tmp_path, confirmed=True)
    with pytest.raises(InstallError):
        install_binary(c, "mytool", "https://example.org/mytool", "nothex", tmp_path, confirmed=True)
    with pytest.raises(InstallError, match="confirmation"):
        install_binary(c, "mytool", "https://example.org/mytool", sha, tmp_path)
    with pytest.raises(UnsafeInputError):
        install_binary(c, "../x", "https://example.org/x", sha, tmp_path, confirmed=True)
