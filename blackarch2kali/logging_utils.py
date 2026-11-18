"""Structured logging with credential redaction."""

from __future__ import annotations

import json
import logging
import re
import sys

_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)(authorization|token|password|secret|api[_-]?key)(\s*[:=]\s*|\s+)(bearer\s+|token\s+)?[^\s,;'\"]+"),
]


def redact(text: str) -> str:
    """Mask anything resembling a credential."""
    out = text
    out = _PATTERNS[0].sub("[REDACTED]", out)
    out = _PATTERNS[1].sub("[REDACTED]", out)
    out = _PATTERNS[2].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", out)
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(verbose: bool = False, json_logs: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JsonFormatter() if json_logs else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("blackarch2kali")
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.propagate = False
    logging.getLogger("httpx").setLevel(logging.WARNING)
