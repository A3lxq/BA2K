import io
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from blackarch2kali.analysis import AnalysisContext
from blackarch2kali.compatibility.platform_detector import Platform
from blackarch2kali.config import Settings
from blackarch2kali.database.repository import Database
from blackarch2kali.errors import CollectorError
from blackarch2kali.synchronization.engine import SyncEngine
from blackarch2kali.synchronization.scheduler import is_due, run_loop
from tests.conftest import FIX, make_client, world_handler

POLICY = yaml.safe_load(open("config/installation_policies.yaml"))


def build(tmp_path, handler, **kw):
    settings = Settings()
    db = Database(tmp_path / "db.sqlite")
    http = make_client(handler)
    factory = lambda pk, k, d: AnalysisContext(settings, POLICY, Platform("kali", deb_arch="amd64"), pk, k, d)  # noqa: E731
    return SyncEngine(db, http, settings, factory, **kw), db, http


def mutate_db(drop=(), rename=None):
    src = tarfile.open(FIX / "blackarch.db")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as out:
        for m in src.getmembers():
            if not m.isfile():
                continue
            data = src.extractfile(m).read()
            name = data.split(b"%NAME%\n")[1].split(b"\n")[0].decode()
            if name in drop:
                continue
            if rename and name == rename[0]:
                data = data.replace(f"%NAME%\n{name}\n".encode(), f"%NAME%\n{rename[1]}\n".encode())
                m.name = f"{rename[1]}-1/desc"
            m.size = len(data)
            out.addfile(m, io.BytesIO(data))
    return buf.getvalue()


def test_full_sync_persists_and_analyzes(tmp_path):
    eng, db, _ = build(tmp_path, world_handler())
    res = eng.run("full")
    assert res.status == "success" and res.inventory["total"] == 27 and res.tools_analyzed == 27
    assert res.repos_fetched >= 1
    amass = db.load_tools()["amass"]
    assert amass.kali_compatibility == "NATIVE_KALI" and amass.preferred_install_method == "APT"
    assert amass.stars is not None and amass.github_repo.lower().endswith("owasp-amass/amass")  # canonical repo after GitHub rename
    assert amass.reproducibility["kali_sha256"] and amass.reproducibility["blackarch_sha256"] and amass.reproducibility["upstream_head_sha"] == "b" * 40
    assert {p["source"] for p in amass.source_provenance} >= {"blackarch.db", "github-api", "kali-Packages"}
    assert db.last_successful_run()["mode"] == "full"


def test_incremental_does_not_refetch_fresh_repos(tmp_path):
    h = world_handler()
    eng, db, _ = build(tmp_path, h, interval_hours=24)
    eng.run("full")
    first = len([c for c in h.calls if "api.github.com" in c])
    res = eng.run("incremental")
    assert len([c for c in h.calls if "api.github.com" in c]) == first and res.inventory["added"] == 0
    eng.run("full")
    assert len([c for c in h.calls if "api.github.com" in c]) > first


def test_removed_and_renamed_detected(tmp_path):
    state = {"db": None}
    base = world_handler()

    def handler(req):
        if req.url.path.endswith("blackarch.db") and state["db"]:
            return __import__("httpx").Response(200, content=state["db"])
        return base(req)

    eng, db, _ = build(tmp_path, handler)
    eng.run("full")
    state["db"] = mutate_db(drop={"arjun"} if False else {"3proxy"}, rename=("altdns", "altdns-ng"))
    res = eng.run("incremental")
    assert res.inventory["removed"] == 1 and res.inventory["renamed"] == 1
    kinds = {(c["kind"], c["subject"]) for c in db.list_changes(res.run_id)}
    assert ("package-removed", "3proxy") in kinds and ("package-renamed", "altdns") in kinds
    assert "3proxy" not in db.load_tools() and "3proxy" in db.removed_packages()
    assert db.package_history("3proxy") == [] and "3proxy" in db.load_packages(include_removed=True)


def test_github_rate_limit_is_partial_not_fatal(tmp_path):
    eng, db, _ = build(tmp_path, world_handler(github_status={"owasp/amass": 403}))
    res = eng.run("full")
    assert res.status == "partial" and any("rate limit" in w for w in res.warnings)
    assert res.tools_analyzed == 27 and db.last_successful_run() is None  # partial isn't a clean success


def test_missing_repo_vs_unfetched(tmp_path):
    eng, db, _ = build(tmp_path, world_handler(github_status={"owasp/amass": 404}))
    res = eng.run("full")
    assert res.repos_missing >= 1
    rules = {f["rule"] for f in db.load_tools()["amass"].risk_findings}
    assert "upstream-repo-missing" in rules
    eng2, db2, _ = build(tmp_path / "b", world_handler(), max_repos=0)
    eng2.max_repos = 1
    eng2.run("full")
    missing = db2.missing_repos()
    unfetched = [t for t in db2.load_tools().values() if t.github_repo is None and t.official_website and "github.com" in t.official_website
                 and "/".join(t.official_website.split("/")[3:5]).lower().removesuffix(".git") not in missing]
    assert unfetched and all("upstream-repo-missing" not in {f["rule"] for f in t.risk_findings} for t in unfetched)


def test_empty_inventory_never_wipes_existing_data(tmp_path):
    state = {"empty": False}
    base = world_handler()

    def handler(req):
        if req.url.path.endswith("blackarch.db") and state["empty"]:
            buf = io.BytesIO()
            tarfile.open(fileobj=buf, mode="w:gz").close()
            return __import__("httpx").Response(200, content=buf.getvalue())
        return base(req)

    eng, db, _ = build(tmp_path, handler)
    eng.run("full")
    state["empty"] = True
    with pytest.raises(CollectorError):
        eng.run("incremental")
    assert len(db.load_packages()) == 27 and db.list_runs(1)[0]["status"] == "failed"


def test_kali_index_outage_degrades_gracefully(tmp_path):
    base = world_handler()
    eng, db, _ = build(tmp_path, lambda req: __import__("httpx").Response(500) if "kali" in req.url.host else base(req))
    res = eng.run("full")
    assert res.status == "partial" and any("kali index unavailable" in w for w in res.warnings)
    assert db.load_tools()["amass"].kali_compatibility != "NATIVE_KALI"


def test_sync_never_installs_or_executes(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("subprocess used during sync")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    eng, db, _ = build(tmp_path, world_handler())
    assert eng.run("full").tools_analyzed == 27


def test_sync_package_has_no_installer_dependency():
    code = "import blackarch2kali.synchronization.engine, blackarch2kali.synchronization.scheduler, sys;" \
           "bad=[m for m in sys.modules if m.startswith('blackarch2kali.installers')];" \
           "sys.exit(1 if bad else 0)"
    assert subprocess.run([sys.executable, "-I", "-c", code], check=False).returncode == 0


def test_scheduler_due_and_loop(tmp_path):
    db = Database(tmp_path / "s.sqlite")
    now = datetime.now(UTC)
    assert is_due(db, 24, now)
    rid = db.start_run("full")
    db.finish_run(rid, "success", {})
    assert not is_due(db, 24, now) and is_due(db, 24, now + timedelta(hours=25))
    calls, sleeps = [], []

    def job():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient")

    assert run_loop(job, 2, max_iterations=3, sleep=sleeps.append) == 3 and sleeps == [7200, 7200]
