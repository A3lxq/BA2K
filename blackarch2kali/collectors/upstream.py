"""Upstream URL classification. Only github.com repositories are treated as verified GitHub sources."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..errors import UnsafeInputError
from ..security.command_safety import parse_github_url, validate_url

_KNOWN_FORGES = {"gitlab.com": "gitlab", "codeberg.org": "codeberg", "bitbucket.org": "bitbucket", "sourceforge.net": "sourceforge"}


@dataclass(frozen=True)
class Upstream:
    url: str | None
    kind: str  # github | gitlab | codeberg | bitbucket | sourceforge | website | invalid | none
    github: tuple[str, str] | None = None


def classify(url: str | None) -> Upstream:
    if not url:
        return Upstream(None, "none")
    gh = parse_github_url(url)
    if gh:
        return Upstream(url, "github", gh)
    try:
        validate_url(url, allowed_schemes={"https", "http"})
    except UnsafeInputError:
        return Upstream(None, "invalid")
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    if host == "github.com" or host.endswith(".github.com"):
        return Upstream(url, "website")  # e.g. github.io pages or org pages, not a repo
    return Upstream(url, _KNOWN_FORGES.get(host, "website"))
