import httpx
import pytest

from blackarch2kali.errors import CollectorError, RateLimitError, UnsafeInputError
from tests.conftest import make_client


def test_retry_on_500_then_success():
    calls = []

    def h(req):
        calls.append(1)
        return httpx.Response(500) if len(calls) < 3 else httpx.Response(200, content=b"ok")

    c = make_client(h)
    assert c.get("https://x.example/a").content == b"ok"
    assert len(calls) == 3 and len(c.sleeps) == 2


def test_gives_up_after_retries():
    c = make_client(lambda r: httpx.Response(503), max_retries=2)
    with pytest.raises(CollectorError):
        c.get("https://x.example/a")


def test_404_raises_unless_allowed():
    c = make_client(lambda r: httpx.Response(404))
    with pytest.raises(CollectorError):
        c.get("https://x.example/a")
    assert c.get("https://x.example/a", ok_statuses=(200, 404)).status == 404


def test_timeout_retries_and_fails():
    def h(req):
        raise httpx.ConnectTimeout("t")

    c = make_client(h, max_retries=1)
    with pytest.raises(CollectorError):
        c.get("https://x.example/a")


def test_rate_limit_short_wait_then_ok():
    state = {"n": 0}

    def h(req):
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(403, headers={"x-ratelimit-remaining": "0", "retry-after": "2"})
        return httpx.Response(200, content=b"ok")

    c = make_client(h)
    assert c.get("https://x.example/a").content == b"ok"
    assert c.sleeps[0] == 3


def test_rate_limit_long_wait_raises():
    c = make_client(lambda r: httpx.Response(429, headers={"retry-after": "9999"}))
    with pytest.raises(RateLimitError):
        c.get("https://x.example/a")


def test_plain_403_is_error_not_rate_limit():
    c = make_client(lambda r: httpx.Response(403))
    with pytest.raises(CollectorError) as ei:
        c.get("https://x.example/a")
    assert not isinstance(ei.value, RateLimitError)


def test_cache_and_etag(tmp_path):
    seen = []

    def h(req):
        seen.append(req.headers.get("if-none-match"))
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=b"body", headers={"etag": '"v1"'})

    now = [1000.0]
    c = make_client(h, tmp_path, clock=lambda: now[0])
    assert not c.get("https://x.example/a").from_cache
    assert c.get("https://x.example/a").from_cache and len(seen) == 1  # within TTL: no request
    now[0] += 10**6
    r = c.get("https://x.example/a")
    assert r.from_cache and r.content == b"body" and seen[-1] == '"v1"'


def test_token_only_sent_to_token_host():
    auth = {}

    def h(req):
        auth[req.url.host] = req.headers.get("authorization")
        return httpx.Response(200, content=b"x")

    c = make_client(h, token="ghp_" + "a" * 36, token_host="api.github.com")
    c.get("https://api.github.com/x")
    c.get("https://evil.example/x")
    assert auth["api.github.com"].startswith("Bearer ") and auth["evil.example"] is None


def test_rejects_unsafe_urls():
    c = make_client(lambda r: httpx.Response(200))
    for u in ("http://x.example/a", "file:///etc/passwd", "https://127.0.0.1/a", "https://user:pw@x.example/"):
        with pytest.raises(UnsafeInputError):
            c.get(u)
