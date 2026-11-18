"""Input validation primitives. All external text must pass through these before reaching a
filesystem path, a command line, or a generated script."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

from ..errors import UnsafeInputError

# Debian policy package names + Arch names (arch allows '+', '_', '@', '.', digits). Must start alnum.
_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._@-]{0,127}$")
_SHELL_META = set(";&|`$<>\\\n\r\"'(){}*?!~#")
_ALLOWED_SCHEMES = {"https"}
_GH_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_GH_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def validate_package_name(name: str) -> str:
    if not isinstance(name, str) or not _PKG_RE.fullmatch(name) or ".." in name:
        raise UnsafeInputError(f"Invalid package name: {name!r}")
    return name


def validate_tool_name(name: str) -> str:
    """Tool names end up in filenames and CLI args: allow only the package charset, no traversal."""
    validate_package_name(name)
    if name.startswith("-"):
        raise UnsafeInputError(f"Tool name may not start with '-': {name!r}")
    return name


def validate_url(url: str, *, allowed_schemes: set[str] | None = None) -> str:
    schemes = allowed_schemes or _ALLOWED_SCHEMES
    if not isinstance(url, str) or any(c in url for c in " \t\r\n\x00'\"<>`\\") or len(url) > 2048:
        raise UnsafeInputError(f"Invalid URL: {url[:80]!r}")
    parsed = urlparse(url)
    if parsed.scheme not in schemes:
        raise UnsafeInputError(f"URL scheme not allowed ({parsed.scheme or 'none'}): {url[:80]!r}")
    if not parsed.hostname:
        raise UnsafeInputError(f"URL has no host: {url[:80]!r}")
    if parsed.username or parsed.password:
        raise UnsafeInputError("URLs with embedded credentials are rejected")
    host = parsed.hostname.lower()
    if host in {"localhost"} or host.endswith(".local") or re.fullmatch(r"[0-9.]+", host) or ":" in host:
        raise UnsafeInputError(f"URL host not allowed (local or raw IP): {host}")
    return url


def parse_github_url(url: str) -> tuple[str, str] | None:
    """Return (owner, repo) for a verified github.com repo URL, else None. Never raises on odd input."""
    try:
        validate_url(url, allowed_schemes={"https", "http"})
    except UnsafeInputError:
        return None
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    repo = repo.removesuffix(".git")
    if not _GH_SLUG.fullmatch(owner) or not _GH_REPO.fullmatch(repo) or repo in {".", ".."}:
        return None
    return owner, repo


def assert_no_shell_meta(arg: str) -> str:
    if any(c in _SHELL_META for c in arg):
        raise UnsafeInputError(f"Shell metacharacters rejected in argument: {arg!r}")
    return arg


def safe_argv(argv: list[str]) -> list[str]:
    """Validate an argv list for generated commands: strings only, no NULs/newlines."""
    if not argv or not all(isinstance(a, str) and a and "\x00" not in a and "\n" not in a for a in argv):
        raise UnsafeInputError("Malformed command argv")
    return argv


def quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in safe_argv(argv))


_REMOTE_EXEC = re.compile(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(ba|z)?sh\b|eval\s+\$\(|base64\s+-d[^|\n]*\|\s*(ba)?sh", re.I)


def is_unsafe_installer_text(text: str) -> bool:
    """True for curl|bash style remote execution patterns."""
    return bool(_REMOTE_EXEC.search(text))


def safe_child_path(base: Path, name: str) -> Path:
    """Join `name` under `base`, refusing traversal and symlink escapes."""
    validate_tool_name(name)
    base_r = base.resolve()
    target = (base_r / name).resolve()
    if base_r != target and base_r not in target.parents:
        raise UnsafeInputError(f"Path escapes base directory: {name!r}")
    return base_r / name


def safe_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    """Write atomically; refuse to follow a symlink at the destination or in the parent."""
    if path.is_symlink():
        raise UnsafeInputError(f"Refusing to write through symlink: {path}")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise UnsafeInputError(f"Refusing to write inside symlinked directory: {parent}")
    tmp = parent / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
