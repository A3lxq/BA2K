"""GitHub repository intelligence via the official REST API."""

from __future__ import annotations

import logging
import re
from typing import Any

from ..analyzers.language import python2_only
from ..analyzers.readme import analyze_readme
from ..analyzers.security import analyze_text_risks
from ..config import Settings
from ..errors import CollectorError, RateLimitError
from ..http import HttpClient
from ..models import Provenance, RepoInfo

log = logging.getLogger(__name__)

_BUILD_HINTS = re.compile(r"(?im)^#{1,4}\s*(install(ation)?|build(ing)?|getting started|setup|usage|requirements)\b|\b(pip3? install|go install|cargo install|npm install|make( install)?|cmake|docker (run|build|pull)|apt(-get)? install|gem install)\b")


class GitHubCollector:
    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.api = settings.sources.github_api.rstrip("/")

    def _get_json(self, path: str, *, ok: tuple[int, ...] = (200,)) -> tuple[int, Any]:
        resp = self.http.get(f"{self.api}{path}", headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, ok_statuses=ok)
        if resp.status != 200:
            return resp.status, None  # 404/409/410...: no body is parsed
        try:
            return resp.status, resp.json()
        except ValueError as exc:
            raise CollectorError(f"Malformed JSON from GitHub for {path}") from exc

    def fetch_repo(self, owner: str, repo: str) -> RepoInfo | None:
        """Return RepoInfo, or None if the repository does not exist (404/410). Raises on rate limit/hard errors."""
        status, data = self._get_json(f"/repos/{owner}/{repo}", ok=(200, 404, 410))
        if data is None or not isinstance(data, dict) or status != 200 or "full_name" not in data:
            return None
        prov = Provenance(source="github-api", url=f"{self.api}/repos/{owner}/{repo}")
        lic = data.get("license") or {}
        spdx = lic.get("spdx_id") if isinstance(lic, dict) else None
        license_ = spdx if isinstance(spdx, str) and spdx not in {"NOASSERTION", "OTHER"} else None  # unrecognised -> UNKNOWN, never guessed
        full = str(data["full_name"])
        info = RepoInfo(
            full_name=full, owner=str(data.get("owner", {}).get("login", owner)), name=str(data.get("name", repo)),
            html_url=str(data.get("html_url", f"https://github.com/{full}")), description=data.get("description"),
            stars=data.get("stargazers_count"), forks=data.get("forks_count"), open_issues=data.get("open_issues_count"),
            default_branch=data.get("default_branch"), created_at=data.get("created_at"), pushed_at=data.get("pushed_at"),
            archived=bool(data.get("archived")), disabled=bool(data.get("disabled")), fork=bool(data.get("fork")),
            license=license_, primary_language=data.get("language"), topics=list(data.get("topics") or []),
            homepage=data.get("homepage") or None, provenance=prov,
        )
        if full.lower() != f"{owner}/{repo}".lower():
            info.renamed_from = f"{owner}/{repo}"
        self._enrich(info)
        return info

    def _enrich(self, info: RepoInfo) -> None:
        """Best-effort extra calls; failures leave fields as None (UNKNOWN) rather than guessing."""
        slug = info.full_name
        try:
            _, langs = self._get_json(f"/repos/{slug}/languages", ok=(200, 404))
            if isinstance(langs, dict):
                info.languages = {str(k): v for k, v in langs.items() if isinstance(v, int) and not isinstance(v, bool)}
            _, rel = self._get_json(f"/repos/{slug}/releases/latest", ok=(200, 404))
            if isinstance(rel, dict) and rel.get("tag_name"):
                info.latest_release = str(rel["tag_name"])
                info.latest_release_date = rel.get("published_at")
            _, rels = self._get_json(f"/repos/{slug}/releases?per_page=100", ok=(200, 404))
            if isinstance(rels, list):
                info.release_count = len(rels)  # capped at one page (100); noted in docs
            if info.default_branch:
                _, commits = self._get_json(f"/repos/{slug}/commits?per_page=1&sha={info.default_branch}", ok=(200, 404, 409))
                if isinstance(commits, list) and commits:
                    info.last_commit = commits[0].get("commit", {}).get("committer", {}).get("date")
                    sha = commits[0].get("sha")
                    info.head_sha = sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) else None
            _, root = self._get_json(f"/repos/{slug}/contents", ok=(200, 404))
            if isinstance(root, list):
                info.root_files = sorted(str(e["name"]) for e in root if isinstance(e, dict) and "name" in e)
            status, readme = self._get_json(f"/repos/{slug}/readme", ok=(200, 404))
            info.has_readme = status == 200
            if isinstance(readme, dict) and readme.get("download_url"):
                self._analyze_readme(info, str(readme["download_url"]))
        except RateLimitError:
            raise
        except CollectorError as exc:
            log.warning("partial GitHub data for %s: %s", slug, exc)

    def _analyze_readme(self, info: RepoInfo, url: str) -> None:
        """Fetch README as inert text and extract install hints/risk findings. Nothing is executed."""
        try:
            body = self.http.get(url).content[:300_000].decode("utf-8", errors="replace")
        except (CollectorError, ValueError):
            return
        ra = analyze_readme(body)
        info.has_build_instructions = bool(_BUILD_HINTS.search(body)) or ra.has_build_instructions
        info.readme_install_commands = [c[:300] for c in ra.install_commands[:40]]
        info.readme_python2_only = python2_only(body)
        info.readme_findings = [f.model_dump(mode="json") | {"scope": "upstream"} for f in analyze_text_risks(body, ra)]
