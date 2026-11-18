"""Safe command probing for verification (version/help only, scrubbed env, timeouts, stdin closed)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass
from pathlib import Path

from ..security.command_safety import SAFE_ENV_KEYS, safe_argv, validate_tool_name

_DIAGNOSTICS = [
    (re.compile(r"error while loading shared libraries: (\S+):"), "missing shared library {0}; find the owning package with `apt-file search {0}`"),
    (re.compile(r"No module named '?([\w.]+)'?"), "missing Python module {0}; reinstall the tool in its isolated environment"),
    (re.compile(r"cannot find module '([^']+)'", re.I), "missing Node module {0}"),
    (re.compile(r"(?i)command not found|No such file or directory"), "interpreter or file missing; check the install method's prerequisites"),
    (re.compile(r"(?i)permission denied"), "permission problem; check file modes and ownership"),
    (re.compile(r"(?i)python2|print\s+\"|SyntaxError"), "likely Python 2 code under Python 3; tool may need patching"),
]


@dataclass
class ProbeResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def find_binary(name: str, extra_dirs: list[Path] | None = None) -> Path | None:
    validate_tool_name(name)
    extra = os.pathsep.join(str(d) for d in (extra_dirs or []))
    found = shutil.which(name, path=os.environ.get("PATH", "") + (os.pathsep + extra if extra else ""))
    return Path(found) if found else None


def probe(binary: Path, args: list[str], timeout: float = 15.0) -> ProbeResult:
    argv = safe_argv([str(binary), *args])
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_KEYS}
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL, shell=False, check=False)  # noqa: S603  # nosec B603
    except subprocess.TimeoutExpired:
        return ProbeResult(argv, None, "", f"timed out after {timeout}s", True)
    except OSError as exc:
        return ProbeResult(argv, None, "", str(exc))
    return ProbeResult(argv, p.returncode, p.stdout[:4000], p.stderr[:4000])


def diagnose(stderr: str) -> list[str]:
    out = []
    for pat, tmpl in _DIAGNOSTICS:
        m = pat.search(stderr)
        if m:
            out.append(tmpl.format(*m.groups()))
    return out
