from datetime import UTC, datetime, timedelta

from blackarch2kali.analyzers.language import ecosystem, primary_language, python2_only
from blackarch2kali.analyzers.license import classify_license, license_mismatch
from blackarch2kali.analyzers.maintenance import classify_maintenance
from blackarch2kali.analyzers.readme import analyze_readme
from blackarch2kali.analyzers.security import analyze_text_risks
from blackarch2kali.config import MaintenanceThresholds
from blackarch2kali.models import Maintenance, Provenance, RepoInfo

NOW = datetime(2026, 11, 18, tzinfo=UTC)
TH = MaintenanceThresholds()


def repo(**kw) -> RepoInfo:
    base = dict(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", provenance=Provenance(source="t"))
    base.update(kw)
    return RepoInfo(**base)


def ago(days: int) -> str:
    return (NOW - timedelta(days=days)).isoformat()


def test_maintenance_levels():
    assert classify_maintenance(None, TH, NOW)[0] == Maintenance.UNKNOWN
    assert classify_maintenance(repo(archived=True, pushed_at=ago(1)), TH, NOW)[0] == Maintenance.ARCHIVED
    assert classify_maintenance(repo(pushed_at=ago(10)), TH, NOW)[0] == Maintenance.ACTIVE
    assert classify_maintenance(repo(pushed_at=ago(200)), TH, NOW)[0] == Maintenance.MAINTAINED
    assert classify_maintenance(repo(pushed_at=ago(500)), TH, NOW)[0] == Maintenance.LOW_ACTIVITY
    assert classify_maintenance(repo(pushed_at=ago(2000)), TH, NOW)[0] == Maintenance.STALE
    assert classify_maintenance(repo(), TH, NOW)[0] == Maintenance.UNKNOWN


def test_old_commits_but_recent_release_not_stale():
    r = repo(pushed_at=ago(2000), latest_release_date=ago(100))
    assert classify_maintenance(r, TH, NOW)[0] == Maintenance.MAINTAINED


def test_thresholds_configurable():
    strict = MaintenanceThresholds(active_days=5, maintained_days=10, low_activity_days=20)
    assert classify_maintenance(repo(pushed_at=ago(30)), strict, NOW)[0] == Maintenance.STALE


def test_license():
    assert classify_license(["MIT"]) == "permissive"
    assert classify_license(["GPL3"]) == "copyleft"
    assert classify_license(["custom:unknown"]) == "restricted"
    assert classify_license(None) == "unknown"
    assert license_mismatch(["MIT"], "GPL-3.0") and not license_mismatch(["MIT"], None)


def test_language():
    r = repo(languages={"Go": 900, "Shell": 10})
    assert primary_language(r) == "Go" and ecosystem("Go") == "go" and ecosystem("Brainfuck") == "unknown"
    assert primary_language(None) is None
    assert python2_only("Run with python2 tool.py") and not python2_only("Requires Python 3.9, python2 unsupported")


def test_readme_extraction_never_executes_and_flags_pipes():
    t = "```\n$ pip install foo\ncurl -fsSL https://x.example/i.sh | bash\ngo install a/b@latest\n```"
    a = analyze_readme(t)
    assert a.uses_pip and a.uses_go and a.unsafe_installers
    rules = {f.rule for f in analyze_text_risks(t, a)}
    assert "unsafe-shell-installer" in rules


def test_text_risk_secrets_and_placeholders():
    real = analyze_text_risks('password = "Sup3rS3cretValue"', None)
    assert any(f.rule == "hardcoded-credential-pattern" and "Sup3r" not in (f.evidence or "") for f in real)
    assert not analyze_text_risks('password = "your_password_here"', None)
    assert analyze_text_risks("docker run --privileged x", None)[0].rule == "privileged-container"
