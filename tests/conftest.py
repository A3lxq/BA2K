from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from blackarch2kali.config import HttpSettings
from blackarch2kali.http import HttpClient

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIX


@pytest.fixture
def ba_db_bytes() -> bytes:
    return (FIX / "blackarch.db").read_bytes()


@pytest.fixture
def kali_text() -> str:
    return (FIX / "kali_Packages").read_text()


def make_client(handler, tmp_path: Path | None = None, **kw) -> HttpClient:
    sleeps: list[float] = []
    c = HttpClient(HttpSettings(max_retries=kw.pop("max_retries", 3), backoff_base_seconds=0.01), cache_dir=tmp_path,
                   transport=httpx.MockTransport(handler), sleep=sleeps.append, **kw)
    c.sleeps = sleeps  # type: ignore[attr-defined]
    return c


@pytest.fixture
def gh_fixture():
    return json.loads((FIX / "gh_amass.json").read_text()), json.loads((FIX / "gh_amass_languages.json").read_text())
