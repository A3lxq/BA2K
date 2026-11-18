"""HTTP client with retries, rate-limit handling, and conditional-request disk caching."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .config import HttpSettings
from .errors import CollectorError, RateLimitError
from .security.command_safety import validate_url

log = logging.getLogger(__name__)
MAX_RATELIMIT_WAIT = 120.0
MAX_BODY_BYTES = 256 * 1024 * 1024
MAX_REDIRECTS = 5


@dataclass
class HttpResponse:
    status: int
    content: bytes
    headers: dict[str, str]
    url: str
    from_cache: bool = False
    retrieved_at: float = field(default_factory=time.time)

    def json(self) -> object:
        return json.loads(self.content)


class HttpClient:
    def __init__(
        self,
        settings: HttpSettings | None = None,
        *,
        cache_dir: Path | None = None,
        token: str | None = None,
        token_host: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings or HttpSettings()
        self.cache_dir = cache_dir
        self._token = token
        self._token_host = token_host
        self._sleep = sleep
        self._clock = clock
        self._client = httpx.Client(
            transport=transport,
            timeout=self.settings.timeout_seconds,
            follow_redirects=False,  # redirects are followed manually so every hop is re-validated
            headers={"User-Agent": "blackarch2kali/0.1 (+https://github.com/A3lxq/BA2K)"},
        )

    def close(self) -> None:
        self._client.close()

    # ---- cache ----------------------------------------------------------------------------
    def _cache_paths(self, url: str) -> tuple[Path, Path] | None:
        if not self.cache_dir:
            return None
        key = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"{key}.body", self.cache_dir / f"{key}.meta"

    def _cache_read(self, url: str) -> tuple[bytes, dict[str, object]] | None:
        paths = self._cache_paths(url)
        if not paths or not paths[0].exists() or not paths[1].exists():
            return None
        try:
            return paths[0].read_bytes(), json.loads(paths[1].read_text())
        except (OSError, ValueError):
            return None

    def _cache_write(self, url: str, resp: HttpResponse) -> None:
        paths = self._cache_paths(url)
        if not paths:
            return
        try:
            paths[0].parent.mkdir(parents=True, exist_ok=True)
            paths[0].write_bytes(resp.content)
            meta = {"etag": resp.headers.get("etag"), "last_modified": resp.headers.get("last-modified"), "fetched_at": self._clock()}
            paths[1].write_text(json.dumps(meta))
        except OSError as exc:
            log.warning("cache write failed: %s", exc)

    # ---- request --------------------------------------------------------------------------
    def _headers_for(self, url: str, extra: dict[str, str] | None) -> dict[str, str]:
        headers = dict(extra or {})
        if self._token and self._token_host and (urlparse(url).hostname or "") == self._token_host:
            headers["Authorization"] = f"Bearer {self._token}"  # sent ONLY to the configured API host
        return headers

    def get(self, url: str, *, headers: dict[str, str] | None = None, use_cache: bool = True, ok_statuses: tuple[int, ...] = (200,)) -> HttpResponse:
        validate_url(url)
        cached = self._cache_read(url) if use_cache else None
        req_headers = self._headers_for(url, headers)
        if cached:
            body, meta = cached
            age = self._clock() - float(str(meta.get("fetched_at", 0)))
            if age < self.settings.cache_ttl_seconds:
                return HttpResponse(200, body, {}, url, from_cache=True)
            if meta.get("etag"):
                req_headers["If-None-Match"] = str(meta["etag"])
            elif meta.get("last_modified"):
                req_headers["If-Modified-Since"] = str(meta["last_modified"])

        last_exc: Exception | None = None
        for attempt in range(self.settings.max_retries + 1):
            try:
                r = self._follow(url, req_headers)
            except httpx.HTTPError as exc:
                last_exc = exc
                log.warning("request error (%s) attempt %d: %s", type(exc).__name__, attempt + 1, url)
                self._backoff(attempt)
                continue
            if len(r.content) > MAX_BODY_BYTES:
                raise CollectorError(f"Response too large from {url}")
            resp = HttpResponse(r.status_code, r.content, {k.lower(): v for k, v in r.headers.items()}, str(r.url))
            if resp.status == 304 and cached:
                self._touch_cache(url)
                return HttpResponse(200, cached[0], resp.headers, url, from_cache=True)
            if self._is_rate_limited(resp):
                wait = self._rate_limit_wait(resp)
                if wait > MAX_RATELIMIT_WAIT or attempt >= self.settings.max_retries:
                    raise RateLimitError(f"Rate limited by {urlparse(url).hostname}; retry in {wait:.0f}s", reset_at=self._clock() + wait)
                log.warning("rate limited; sleeping %.1fs", wait)
                self._sleep(wait)
                continue
            if resp.status >= 500 or resp.status == 429:
                last_exc = CollectorError(f"HTTP {resp.status} from {url}")
                self._backoff(attempt)
                continue
            if resp.status in ok_statuses:
                if resp.status == 200:
                    self._cache_write(url, resp)
                return resp
            raise CollectorError(f"HTTP {resp.status} from {url}")
        raise CollectorError(f"Giving up on {url} after {self.settings.max_retries + 1} attempts: {last_exc}")

    def _follow(self, url: str, headers: dict[str, str]) -> httpx.Response:
        """GET with manual redirect handling: each hop must pass URL validation (https, no IPs/localhost);
        the Authorization header is recomputed per host so a token never follows a redirect elsewhere."""
        current = url
        base_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        for _ in range(MAX_REDIRECTS + 1):
            hop_headers = self._headers_for(current, base_headers)
            r = self._client.get(current, headers=hop_headers)
            if r.status_code not in (301, 302, 303, 307, 308):
                return r
            location = r.headers.get("location")
            if not location:
                return r
            nxt = str(httpx.URL(current).join(location))
            validate_url(nxt)  # raises UnsafeInputError for http://, raw IPs, localhost, credentials...
            current = nxt
        raise CollectorError(f"Too many redirects fetching {url}")

    def _touch_cache(self, url: str) -> None:
        paths = self._cache_paths(url)
        if paths and paths[1].exists():
            try:
                meta = json.loads(paths[1].read_text())
                meta["fetched_at"] = self._clock()
                paths[1].write_text(json.dumps(meta))
            except (OSError, ValueError):
                pass

    def _backoff(self, attempt: int) -> None:
        if attempt < self.settings.max_retries:
            self._sleep(self.settings.backoff_base_seconds * (2**attempt))

    @staticmethod
    def _is_rate_limited(resp: HttpResponse) -> bool:
        if resp.status == 429:
            return True
        if resp.status in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
            return True
        return resp.status == 403 and "retry-after" in resp.headers

    def _rate_limit_wait(self, resp: HttpResponse) -> float:
        if "retry-after" in resp.headers:
            try:
                return max(float(resp.headers["retry-after"]), 0.0) + 1
            except ValueError:
                pass
        reset = resp.headers.get("x-ratelimit-reset")
        if reset and reset.isdigit():
            return max(float(reset) - self._clock(), 0.0) + 1
        return 60.0
