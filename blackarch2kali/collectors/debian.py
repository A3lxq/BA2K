"""Debian-format `Packages` index parsing (shared by Debian and Kali collectors)."""

from __future__ import annotations

import gzip
import logging
import lzma
import re
from dataclasses import dataclass, field

from ..errors import CollectorError
from ..http import HttpClient
from ..models import DebMatch, Provenance

log = logging.getLogger(__name__)
MAX_DECOMPRESSED = 512 * 1024 * 1024


@dataclass
class DebIndex:
    distribution: str
    url: str
    by_name: dict[str, DebMatch] = field(default_factory=dict)
    provides: dict[str, list[str]] = field(default_factory=dict)  # virtual name -> real packages

    def get(self, name: str) -> DebMatch | None:
        """Exact package-name lookup only."""
        return self.by_name.get(name)

    def __len__(self) -> int:
        return len(self.by_name)


def _split_relations(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def decompress(data: bytes, url: str) -> str:
    try:
        if url.endswith(".xz"):
            raw = lzma.LZMADecompressor().decompress(data, max_length=MAX_DECOMPRESSED)
        elif url.endswith(".gz"):
            with gzip.GzipFile(fileobj=__import__("io").BytesIO(data)) as gz:
                raw = gz.read(MAX_DECOMPRESSED + 1)
            if len(raw) > MAX_DECOMPRESSED:
                raise CollectorError("Packages index exceeds size limit")
        else:
            raw = data
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise CollectorError(f"Cannot decompress {url}: {exc}") from exc
    return raw.decode("utf-8", errors="replace")


def parse_packages(text: str, distribution: str, url: str) -> DebIndex:
    prov = Provenance(source=f"{distribution}-Packages", url=url)
    index = DebIndex(distribution=distribution, url=url)
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip()] = val.strip()
        name = fields.get("Package")
        version = fields.get("Version")
        if not name or not version:
            continue
        match = DebMatch(
            package=name, version=version, architecture=fields.get("Architecture", "UNKNOWN"),
            homepage=fields.get("Homepage"), depends=_split_relations(fields.get("Depends", "")),
            conflicts=_split_relations(fields.get("Conflicts", "")), distribution=distribution, provenance=prov,
            sha256=fields.get("SHA256"), filename=fields.get("Filename"),
        )
        prev = index.by_name.get(name)
        if prev is None or _newer(version, prev.version):
            index.by_name[name] = match
        for virt in _split_relations(fields.get("Provides", "")):
            index.provides.setdefault(virt.split(" ")[0], []).append(name)
    return index


def _newer(a: str, b: str) -> bool:
    ka = [int(x) if x.isdigit() else x for x in re.findall(r"\d+|[A-Za-z]+", a)]
    kb = [int(x) if x.isdigit() else x for x in re.findall(r"\d+|[A-Za-z]+", b)]
    try:
        return ka > kb
    except TypeError:
        return a > b


class DebianCollector:
    distribution = "debian"

    def __init__(self, http: HttpClient, url: str) -> None:
        self.http = http
        self.url = url

    def collect(self) -> DebIndex:
        resp = self.http.get(self.url)
        index = parse_packages(decompress(resp.content, self.url), self.distribution, self.url)
        if not len(index):
            raise CollectorError(f"{self.distribution} package index at {self.url} is empty")
        return index
