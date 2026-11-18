"""Official binary release installer: requires an https URL AND a pinned SHA-256; verifies before install."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from ..errors import InstallError
from ..http import HttpClient
from ..security.command_safety import validate_tool_name, validate_url


def install_binary(client: HttpClient, tool: str, url: str, sha256: str, dest_dir: Path, *, confirmed: bool = False) -> Path:
    """Download a single-file binary, verify its SHA-256, then place it (mode 0755). No extraction/execution."""
    validate_tool_name(tool)
    validate_url(url)
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256.lower()):
        raise InstallError("a pinned lowercase hex SHA-256 is required for binary releases")
    if not confirmed:
        raise InstallError("binary installation requires explicit confirmation")
    data = client.get(url, use_cache=False).content
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256.lower():
        raise InstallError(f"checksum mismatch for {tool}: expected {sha256}, got {actual}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / tool
    if target.is_symlink():
        raise InstallError(f"refusing to overwrite symlink {target}")
    tmp = dest_dir / f".{tool}.tmp"
    tmp.write_bytes(data)
    tmp.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    os.replace(tmp, target)
    return target
