"""Check whether Debian package dependencies are installed (dpkg-query; read-only)."""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404  # nosec B404

from ..security.command_safety import validate_package_name


def package_installed(pkg: str) -> bool | None:
    """True/False, or None when dpkg-query is unavailable (non-Debian host)."""
    validate_package_name(pkg)
    exe = shutil.which("dpkg-query")
    if not exe:
        return None
    p = subprocess.run([exe, "-W", "-f=${Status}", "--", pkg], capture_output=True, text=True, timeout=15, check=False)  # noqa: S603  # nosec B603
    return p.returncode == 0 and "install ok installed" in p.stdout


def check_dependencies(pkgs: list[str]) -> dict[str, bool | None]:
    return {p: package_installed(p) for p in pkgs}
