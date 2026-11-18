"""BlackArch package inventory collector.

Source: the official pacman sync database (`blackarch.db`), a gzip'd tar of `<name>-<ver>/desc` files.
This is structured repository metadata, not scraped HTML. Archive members are read in memory and never
extracted to disk, so hostile member names cannot touch the filesystem.
"""

from __future__ import annotations

import io
import logging
import re
import tarfile
from dataclasses import dataclass, field

from ..errors import BA2KError, CollectorError
from ..http import HttpClient
from ..models import BlackArchPackage, Provenance
from ..security.command_safety import validate_package_name

log = logging.getLogger(__name__)
MAX_DESC_BYTES = 256 * 1024
MAX_MEMBERS = 100_000

_FIELDS = {
    "NAME": "name", "BASE": "base", "VERSION": "version", "DESC": "description", "GROUPS": "groups",
    "URL": "url", "LICENSE": "license", "ARCH": "arch", "DEPENDS": "depends", "MAKEDEPENDS": "makedepends",
    "OPTDEPENDS": "optdepends", "PROVIDES": "provides", "REPLACES": "replaces", "CONFLICTS": "conflicts",
    "BUILDDATE": "build_date", "FILENAME": "filename", "SHA256SUM": "sha256", "CSIZE": "compressed_size",
}
_LIST_FIELDS = {"groups", "license", "depends", "makedepends", "optdepends", "provides", "replaces", "conflicts"}


@dataclass
class ParseResult:
    packages: dict[str, BlackArchPackage] = field(default_factory=dict)
    duplicates: list[tuple[str, str, str]] = field(default_factory=list)  # (name, kept_version, dropped_version)
    errors: list[str] = field(default_factory=list)


def parse_desc(text: str) -> dict[str, list[str]]:
    """Parse a pacman `desc` file into {%FIELD%: [lines]}."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = re.fullmatch(r"%([A-Z0-9]+)%", line.strip())
        if m:
            current = m.group(1)
            sections[current] = []
        elif line.strip() and current:
            sections[current].append(line.strip())
    return sections


def _vercmp_key(version: str) -> list[tuple[int, int | str]]:
    """Approximate pacman version ordering; only used to choose between duplicate entries."""
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    return [(0, int(p)) if p.isdigit() else (-1, p) for p in parts]


def build_package(sections: dict[str, list[str]], prov: Provenance) -> BlackArchPackage:
    raw: dict[str, object] = {}
    for key, attr in _FIELDS.items():
        values = sections.get(key)
        if not values:
            continue
        if attr in _LIST_FIELDS:
            raw[attr] = values
        elif attr in {"build_date", "compressed_size"}:
            raw[attr] = int(values[0]) if values[0].isdigit() else None
        else:
            raw[attr] = " ".join(values) if attr == "description" else values[0]
    if "name" not in raw or "version" not in raw:
        raise ValueError("desc missing %NAME% or %VERSION%")
    validate_package_name(str(raw["name"]))
    return BlackArchPackage(provenance=prov, **raw)


def parse_db(data: bytes, source_url: str) -> ParseResult:
    prov = Provenance(source="blackarch.db", url=source_url)
    result = ParseResult()
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")  # noqa: SIM115
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise CollectorError(f"blackarch.db is not a valid archive: {exc}") from exc
    with tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise CollectorError("blackarch.db has an implausible number of entries")
        for m in members:
            if not m.isfile() or not m.name.endswith("/desc"):
                continue
            if m.size > MAX_DESC_BYTES:
                result.errors.append(f"{m.name}: desc too large")
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            try:
                pkg = build_package(parse_desc(fh.read().decode("utf-8", errors="replace")), prov)
            except (ValueError, BA2KError) as exc:  # a malformed entry must not abort the whole inventory
                result.errors.append(f"{m.name}: {exc}")
                continue
            prev = result.packages.get(pkg.name)
            if prev is not None:
                if _vercmp_key(pkg.version) > _vercmp_key(prev.version):
                    result.duplicates.append((pkg.name, pkg.version, prev.version))
                    result.packages[pkg.name] = pkg
                else:
                    result.duplicates.append((pkg.name, prev.version, pkg.version))
                continue
            result.packages[pkg.name] = pkg
    return result


class BlackArchCollector:
    def __init__(self, http: HttpClient, urls: list[str]) -> None:
        self.http = http
        self.urls = urls

    def collect(self) -> ParseResult:
        errors: list[str] = []
        for url in self.urls:
            try:
                resp = self.http.get(url)
                result = parse_db(resp.content, url)
            except CollectorError as exc:
                errors.append(f"{url}: {exc}")
                log.warning("mirror failed: %s", exc)
                continue
            if not result.packages:
                errors.append(f"{url}: inventory is empty")
                continue
            return result
        raise CollectorError("No BlackArch mirror produced a usable inventory: " + "; ".join(errors))
