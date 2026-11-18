from blackarch2kali.database.repository import Database
from blackarch2kali.models import BlackArchPackage, DebMatch, Provenance, RepoInfo, Risk
from blackarch2kali.security.source_validation import verify_upstream
from blackarch2kali.synchronization.history import recent_runs

P = Provenance(source="t")


def pkg(url, lic=None):
    return BlackArchPackage(name="t", version="1", url=url, license=lic or [], provenance=P)


def repo(**kw):
    b = {"full_name": "o/r", "owner": "o", "name": "r", "html_url": "https://github.com/o/r", "provenance": P}
    b.update(kw)
    return RepoInfo(**b)


def rules(fs):
    return {f.rule: f.level for f in fs}


def test_unusable_and_dangerous_urls():
    assert rules(verify_upstream(pkg("http://10.1.2.3/x"), None, None, None)[1]) == {"upstream-url-unusable": Risk.MEDIUM}
    assert rules(verify_upstream(pkg("javascript:alert(1)"), None, None, None)[1]) == {"unsafe-url-scheme": Risk.HIGH}


def test_non_github_upstream_not_flagged():
    v, f = verify_upstream(pkg("https://gitlab.com/o/r"), None, None, None)
    assert f == [] and v["url_kind"] == "gitlab" and not v["repo_verified"]


def test_fork_disabled_archived_renamed_and_license():
    v, f = verify_upstream(pkg("https://github.com/old/r", ["MIT"]), repo(fork=True, disabled=True, archived=True, renamed_from="old/r", license="GPL-3.0"), None, None, repo_missing=False)
    r = rules(f)
    assert r["upstream-is-fork"] is Risk.HIGH and r["repository-disabled"] is Risk.HIGH and r["repository-archived"] is Risk.MEDIUM
    assert "repository-renamed" in r and "license-mismatch" in r and v["repo_verified"]


def test_missing_vs_pending_repo():
    assert rules(verify_upstream(pkg("https://github.com/o/r"), None, None, None, repo_missing=True)[1]) == {"upstream-repo-missing": Risk.MEDIUM}
    v, f = verify_upstream(pkg("https://github.com/o/r"), None, None, None)
    assert f == [] and "pending" in v["checks"][0]


def test_distro_corroboration_and_mismatch():
    ok = DebMatch(package="t", version="1", architecture="amd64", homepage="https://github.com/o/r", distribution="kali", provenance=P)
    bad = ok.model_copy(update={"homepage": "https://github.com/someone/else"})
    v, f = verify_upstream(pkg("https://github.com/o/r"), repo(), ok, None)
    assert v["corroborated_by_distro"] and "distro-homepage-mismatch" not in rules(f)
    v2, f2 = verify_upstream(pkg("https://github.com/o/r"), repo(), bad, None)
    assert not v2["corroborated_by_distro"] and "distro-homepage-mismatch" in rules(f2)


def test_history_summary(tmp_path):
    db = Database(tmp_path / "h.sqlite")
    rid = db.start_run("full")
    db.finish_run(rid, "success", {"total": 3})
    runs = recent_runs(db)
    assert runs[0]["summary"] == {"total": 3} and runs[0]["mode"] == "full"
