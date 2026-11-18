import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from blackarch2kali import cli
from blackarch2kali.services import Services
from tests.conftest import make_client, world_handler

runner = CliRunner()


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    shutil.copytree("config", cfg)
    s = (cfg / "settings.yaml").read_text().replace("generated_dir: ./generated", f"generated_dir: {tmp_path / 'gen'}").replace("data_dir: ./data", f"data_dir: {tmp_path / 'data'}")
    (cfg / "settings.yaml").write_text(s)
    monkeypatch.setattr(Services, "http", lambda self: make_client(world_handler()))
    monkeypatch.setattr("blackarch2kali.installers.base.Installer.missing_prerequisites", lambda self: [])
    base = ["--config-dir", str(cfg), "--home", str(tmp_path / "state")]

    def run(*args, input=None):
        return runner.invoke(cli.app, [*base, *args], input=input)

    return run, tmp_path


@pytest.fixture
def synced(env):
    run, tmp = env
    r = run("sync")
    assert r.exit_code == 0, r.output
    return run, tmp


def test_help_lists_all_commands(env):
    run, _ = env
    r = run("--help")
    for c in ("init", "sync", "inventory", "search", "categories", "analyze", "compatibility", "plan", "install", "verify", "update", "report", "security-audit", "health"):
        assert c in r.output


def test_init_and_empty_state(env):
    run, tmp = env
    assert run("init").exit_code == 0 and (tmp / "state" / "blackarch2kali.sqlite").exists()
    r = run("report")
    assert r.exit_code == 2 and "sync" in r.output


def test_sync_generates_reports_and_json(env):
    run, tmp = env
    r = run("--json", "sync") if False else runner.invoke(cli.app, ["--json", "--config-dir", str(tmp / "config"), "--home", str(tmp / "state"), "sync"])
    assert r.exit_code == 0, r.output
    assert (tmp / "gen/reports/full_inventory.json").exists() and (tmp / "gen/categories/wireless.json").exists()
    import yaml

    assert yaml.safe_load((tmp / "data/tools.yaml").read_text())["tools"] and (tmp / "data/compatibility.json").exists() and (tmp / "data/dependency_graph.json").exists()


def test_inventory_search_categories(synced):
    run, _ = synced
    r = run("--json", "inventory", "--limit", "0")
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert len(data) == 27
    s = run("search", "amass")
    assert s.exit_code == 0 and "amass" in s.output
    assert run("search", "zzz-nothing").exit_code == 2
    c = run("--json", "categories")
    assert "blackarch-recon" in json.loads(c.output)["official_groups"]


def test_analyze_compat_plan_dry_run_install(synced):
    run, _ = synced
    assert "NATIVE_KALI" in run("analyze", "amass").output
    comp = run("--json", "compatibility", "amass")
    assert json.loads(comp.output)["options"][0]["method"] == "APT"
    p = json.loads(run("--json", "plan", "amass").output)
    assert p["method"] == "APT" and len(p["digest"]) == 64
    d = run("install", "amass")
    assert d.exit_code == 0 and "DRY RUN" in d.output
    assert run("install", "amass", "--dry-run", "--confirm").exit_code == 2


def test_confirm_requires_approval_and_matching_digest(synced, monkeypatch):
    run, _ = synced
    calls = []
    monkeypatch.setattr("blackarch2kali.installers.base.SubprocessRunner.run", lambda self, argv, timeout=0: (calls.append(argv), (0, "", ""))[1])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert run("install", "amass", "--confirm", input="n\n").exit_code == 4 and calls == []
    bad = run("install", "amass", "--confirm", "--plan-digest", "f" * 64)
    assert bad.exit_code == 4 and calls == []
    digest = json.loads(run("--json", "plan", "amass").output)["digest"]
    ok = run("install", "amass", "--confirm", "--plan-digest", digest)
    assert calls == [["apt-get", "install", "--no-install-recommends", "--", "amass"]]
    assert ok.exit_code == 3 and "verification FAILED" in ok.output  # binary isn't really installed here


def test_unverified_native_needs_flag(synced, monkeypatch):
    run, _ = synced
    monkeypatch.setattr("blackarch2kali.installers.base.SubprocessRunner.run", lambda self, argv, timeout=0: (0, "", ""))
    digest = json.loads(run("--json", "plan", "ace").output)["digest"]  # name-only Kali match
    r = run("install", "ace", "--confirm", "--plan-digest", digest)
    assert r.exit_code == 3 and "unverified" in r.output


def test_bad_inputs_rejected(synced):
    run, _ = synced
    assert run("analyze", "../../etc/passwd").exit_code == 2
    assert run("install", "nonexistent-tool").exit_code == 2
    assert run("install").exit_code == 2 and run("install", "amass", "--category", "Wireless").exit_code == 2
    assert run("plan", "amass", "--method", "bogus").exit_code == 2
    assert run("report", "--format", "xml").exit_code == 2
    assert run("install", "--category", "Not A Category").exit_code == 2


def test_category_and_all_are_dry_run_by_default(synced, monkeypatch):
    run, _ = synced
    monkeypatch.setattr("blackarch2kali.installers.base.SubprocessRunner.run", lambda *a, **k: pytest.fail("must not execute"))
    r = run("install", "--all")
    assert r.exit_code == 0 and "DRY RUN" in r.output
    assert run("install", "--category", "Reconnaissance").exit_code == 0


def test_report_formats_security_audit_health_verify(synced, tmp_path):
    run, tmp = synced
    for fmt in ("json", "csv", "markdown", "html"):
        r = run("report", "--format", fmt)
        assert r.exit_code == 0
    assert run("security-audit").exit_code == 0
    assert run("security-audit", "--fail-on", "MEDIUM").exit_code == 3
    assert run("health").exit_code == 0
    v = run("verify", "nmap-parse-output")
    assert v.exit_code == 3 and "not found" in v.output
    assert run("--json", "verify", "amass").exit_code in (0, 3)


def test_update_command_does_not_install(env, monkeypatch):
    run, _ = env
    monkeypatch.setattr("blackarch2kali.installers.base.SubprocessRunner.run", lambda *a, **k: pytest.fail("must not execute"))
    assert run("update").exit_code == 0


def test_sync_failure_exit_code(env, monkeypatch):
    run, _ = env
    import httpx

    monkeypatch.setattr(Services, "http", lambda self: make_client(lambda r: httpx.Response(500), max_retries=0))
    r = run("sync")
    assert r.exit_code == 1 and "error" in r.output.lower()
    assert Path.cwd()
