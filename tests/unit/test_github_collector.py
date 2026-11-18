import json

import httpx

from blackarch2kali.collectors.github import GitHubCollector
from blackarch2kali.config import Settings
from tests.conftest import FIX, make_client


def _handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/repos/OWASP/Amass":
        return httpx.Response(200, content=(FIX / "gh_amass.json").read_bytes())
    if p.endswith("/languages"):
        return httpx.Response(200, content=(FIX / "gh_amass_languages.json").read_bytes())
    if p.endswith("/releases/latest"):
        return httpx.Response(200, json={"tag_name": "v5.0.0", "published_at": "2026-01-01T00:00:00Z"})
    if "/releases" in p:
        return httpx.Response(200, json=[{}, {}])
    if "/commits" in p:
        return httpx.Response(200, json=[{"sha": "a" * 40, "commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}}])
    if p.endswith("/readme"):
        return httpx.Response(200, json={"download_url": "https://raw.githubusercontent.com/o/r/HEAD/README.md"})
    if p.startswith("/o/r"):
        return httpx.Response(200, content=b"# Install\n\ngo install foo@latest\n")
    return httpx.Response(404)


def test_fetch_repo_renamed_and_enriched():
    gh = GitHubCollector(make_client(_handler), Settings())
    info = gh.fetch_repo("OWASP", "Amass")
    assert info and info.full_name == "owasp-amass/amass"
    assert info.renamed_from == "OWASP/Amass"
    assert info.latest_release == "v5.0.0" and info.release_count == 2
    assert info.head_sha == "a" * 40 and info.last_commit == "2026-10-01T00:00:00Z"
    assert info.languages and info.has_readme and info.has_build_instructions
    assert info.license is None  # NOASSERTION is not fabricated into a license
    assert info.provenance.source == "github-api"


def test_missing_repo_returns_none():
    gh = GitHubCollector(make_client(lambda r: httpx.Response(404)), Settings())
    assert gh.fetch_repo("no", "such") is None


def test_malformed_json_is_collector_error():
    import pytest

    from blackarch2kali.errors import CollectorError

    gh = GitHubCollector(make_client(lambda r: httpx.Response(200, content=b"<html>")), Settings())
    with pytest.raises(CollectorError):
        gh.fetch_repo("a", "b")
    assert json  # silence unused
