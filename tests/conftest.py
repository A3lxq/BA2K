from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from blackarch2kali.config import HttpSettings
from blackarch2kali.http import HttpClient

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIX


@pytest.fixture
def ba_db_bytes() -> bytes:
    return (FIX / "blackarch.db").read_bytes()


@pytest.fixture
def kali_text() -> str:
    return (FIX / "kali_Packages").read_text()


def make_client(handler, tmp_path: Path | None = None, **kw) -> HttpClient:
    sleeps: list[float] = []
    c = HttpClient(HttpSettings(max_retries=kw.pop("max_retries", 3), backoff_base_seconds=0.01), cache_dir=tmp_path,
                   transport=httpx.MockTransport(handler), sleep=sleeps.append, **kw)
    c.sleeps = sleeps  # type: ignore[attr-defined]
    return c


@pytest.fixture
def gh_fixture():
    return json.loads((FIX / "gh_amass.json").read_text()), json.loads((FIX / "gh_amass_languages.json").read_text())


# ---- a fake "internet": BlackArch db, Kali/Debian indexes, GitHub API -----------------------------
import gzip  # noqa: E402


def world_handler(*, ba_db: bytes | None = None, github_status: dict[str, int] | None = None, extra_github=None):
    """Return an httpx handler serving fixtures. `github_status` maps 'owner/repo' -> forced HTTP status."""
    ba = ba_db if ba_db is not None else (FIX / "blackarch.db").read_bytes()
    kali = gzip.compress((FIX / "kali_Packages").read_bytes())
    amass = (FIX / "gh_amass.json").read_bytes()
    langs = (FIX / "gh_amass_languages.json").read_bytes()
    forced = github_status or {}
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        calls.append(url)
        host, path = req.url.host, req.url.path
        if path.endswith("blackarch.db"):
            return httpx.Response(200, content=ba)
        if "kali" in host and path.endswith("Packages.gz"):
            return httpx.Response(200, content=kali)
        if "debian" in host and path.endswith("Packages.gz"):
            return httpx.Response(200, content=gzip.compress(b"Package: bash\nVersion: 5.2\nArchitecture: amd64\n\n"))
        if host == "api.github.com":
            parts = path.strip("/").split("/")
            slug = "/".join(parts[1:3]).lower() if len(parts) >= 3 else ""
            if slug in forced:
                return httpx.Response(forced[slug], headers={"x-ratelimit-remaining": "0", "retry-after": "99999"} if forced[slug] == 403 else {})
            if extra_github:
                r = extra_github(req)
                if r is not None:
                    return r
            if slug in {"owasp/amass", "owasp-amass/amass"}:
                if path.endswith("/languages"):
                    return httpx.Response(200, content=langs)
                if len(parts) == 3:
                    return httpx.Response(200, content=amass)
                if path.endswith("/releases/latest"):
                    return httpx.Response(200, json={"tag_name": "v5.0.0", "published_at": "2026-10-01T00:00:00Z"})
                if "/commits" in path:
                    return httpx.Response(200, json=[{"sha": "b" * 40, "commit": {"committer": {"date": "2026-11-01T00:00:00Z"}}}])
                if path.endswith("/contents"):
                    return httpx.Response(200, json=[{"name": "go.mod"}, {"name": "Makefile"}])
                if path.endswith("/readme"):
                    return httpx.Response(404)
                return httpx.Response(200, json=[])
            return httpx.Response(404)
        return httpx.Response(404)

    handler.calls = calls  # type: ignore[attr-defined]
    return handler
