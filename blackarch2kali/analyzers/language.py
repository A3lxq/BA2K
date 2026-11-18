"""Language analysis and install-ecosystem hints."""

from __future__ import annotations

import re

from ..models import RepoInfo

_ECOSYSTEM = {
    "python": "python", "go": "go", "rust": "rust", "javascript": "node", "typescript": "node", "ruby": "ruby",
    "c": "native", "c++": "native", "java": "java", "shell": "shell", "perl": "perl", "php": "php",
}
_PY2 = re.compile(r"(?i)\bpython\s*2(\.\d+)?\b(?!\s*(and|/|or)\s*3)|#!\s*/usr/bin/(env\s+)?python2\b|\bpython2\s+\S+\.py\b|print\s+[\"'][^\"']*[\"']\s*$")
_PY3 = re.compile(r"(?i)\bpython\s*3\b|python_requires\s*=\s*[\"']>=?\s*3|Programming Language :: Python :: 3")


def primary_language(repo: RepoInfo | None) -> str | None:
    if repo is None:
        return None
    if repo.languages:
        return max(repo.languages, key=lambda k: repo.languages[k])
    return repo.primary_language


def ecosystem(language: str | None) -> str:
    return _ECOSYSTEM.get((language or "").lower(), "unknown")


def python2_only(text: str) -> bool:
    """Heuristic: text positively references Python 2 and never references Python 3."""
    return bool(_PY2.search(text)) and not _PY3.search(text)
