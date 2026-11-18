import io
import tarfile

import httpx
import pytest

from blackarch2kali.collectors.blackarch import BlackArchCollector, parse_db, parse_desc
from blackarch2kali.errors import CollectorError
from tests.conftest import make_client


def test_parse_fixture(ba_db_bytes):
    r = parse_db(ba_db_bytes, "https://example/blackarch.db")
    assert len(r.packages) == 27 and not r.errors
    amass = r.packages["amass"]
    assert amass.url == "https://github.com/OWASP/Amass"
    assert "blackarch-recon" in amass.categories and "blackarch" not in amass.categories
    assert amass.sha256 and len(amass.sha256) == 64
    assert amass.provenance.source == "blackarch.db" and amass.provenance.retrieved_at


def test_parse_desc_sections():
    s = parse_desc("%NAME%\nfoo\n\n%DEPENDS%\na\nb>=1\n")
    assert s == {"NAME": ["foo"], "DEPENDS": ["a", "b>=1"]}


def _tar(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in entries.items():
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_duplicates_keep_newest():
    d = _tar({"foo-1.0-1/desc": "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n", "foo-2.0-1/desc": "%NAME%\nfoo\n\n%VERSION%\n2.0-1\n"})
    r = parse_db(d, "u")
    assert r.packages["foo"].version == "2.0-1"
    assert r.duplicates == [("foo", "2.0-1", "1.0-1")]


def test_malformed_and_malicious_entries_isolated():
    d = _tar({
        "ok-1-1/desc": "%NAME%\nok\n\n%VERSION%\n1-1\n",
        "bad-1-1/desc": "%NAME%\nbad\n",  # no version
        "evil-1-1/desc": "%NAME%\n../../etc/passwd\n\n%VERSION%\n1\n",
        "../../escape/desc": "%NAME%\nescape\n\n%VERSION%\n1\n",
    })
    r = parse_db(d, "u")
    assert "ok" in r.packages and "bad" not in r.packages and "../../etc/passwd" not in r.packages
    assert len(r.errors) >= 2


def test_not_an_archive():
    with pytest.raises(CollectorError):
        parse_db(b"garbage", "u")


def test_empty_inventory_falls_back_to_next_mirror(ba_db_bytes):
    empty = _tar({})

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=empty if "bad" in str(req.url) else ba_db_bytes)

    c = make_client(handler)
    res = BlackArchCollector(c, ["https://bad.example/blackarch.db", "https://good.example/blackarch.db"]).collect()
    assert len(res.packages) == 27


def test_all_mirrors_fail():
    c = make_client(lambda r: httpx.Response(404), max_retries=0)
    with pytest.raises(CollectorError):
        BlackArchCollector(c, ["https://a.example/x.db"]).collect()
