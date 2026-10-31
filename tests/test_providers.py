import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
import requests

from asnban.providers import USER_AGENT, bgptools, cymru

CYMRU_TEXT = """AS | IP | Name
13335 | 1.1.1.1 | CLOUDFLARENET
"""

CYMRU_MULTI_TEXT = """<PRE>AS      | IP               | AS Name
138421  | 1.1.8.1          | CU-CN-AS - China Unicom, CN
149511  | 1.1.8.1          | YNCL-AS-AP - Yamu Technologies Co., Ltd., CN
</PRE>
"""

TABLE_TEXT = """192.0.2.0/24 64496
2001:db8::/32 64496
198.51.100.0/24 64500
"""


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_cymru_query(monkeypatch):
    def fake_post(url, *, files, headers, timeout):
        assert headers == {"User-Agent": USER_AGENT}
        assert timeout[0] > 0 and timeout[1] > 0
        return FakeResponse(CYMRU_TEXT)

    monkeypatch.setattr(cymru.requests, "post", fake_post)
    assert cymru.query("1.1.1.1") == ("13335", "1.1.1.1", "CLOUDFLARENET")


def test_cymru_multiple_origins(monkeypatch):
    monkeypatch.setattr(
        cymru.requests, "post", lambda *args, **kwargs: FakeResponse(CYMRU_MULTI_TEXT)
    )
    assert cymru.query("1.1.8.1") == (
        "138421 149511",
        "1.1.8.1",
        "CU-CN-AS - China Unicom, CN; YNCL-AS-AP - Yamu Technologies Co., Ltd., CN",
    )


def test_cymru_unexpected_response(monkeypatch):
    monkeypatch.setattr(
        cymru.requests, "post", lambda *args, **kwargs: FakeResponse("nope")
    )
    with pytest.raises(ValueError, match="response"):
        cymru.query("1.1.1.1")


def test_cymru_rejects_results_for_another_ip(monkeypatch):
    monkeypatch.setattr(
        cymru.requests, "post", lambda *args, **kwargs: FakeResponse(CYMRU_TEXT)
    )
    with pytest.raises(ValueError, match="unexpected IP"):
        cymru.query("1.0.0.1")


def test_cymru_unannounced_ip(monkeypatch):
    monkeypatch.setattr(
        cymru.requests,
        "post",
        lambda *args, **kwargs: FakeResponse("AS | IP | Name\nNA | 192.0.2.1 | NA\n"),
    )
    assert cymru.query("192.0.2.1") == ("NA", "192.0.2.1", "NA")


def test_bgptools_cache_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert bgptools._cache_path() == tmp_path / "asnban" / "table.txt"


def test_bgptools_query(monkeypatch, tmp_path):
    calls = []

    def fake_get(url, headers, timeout):
        assert timeout[0] > 0 and timeout[1] > 0
        calls.append((url, headers))
        return FakeResponse(TABLE_TEXT)

    monkeypatch.setattr(bgptools.requests, "get", fake_get)
    monkeypatch.setattr(bgptools, "_cache_path", lambda: tmp_path / "table.txt")

    assert bgptools.query_prefixes("AS64496") == [
        "192.0.2.0/24",
        "2001:db8::/32",
    ]
    assert calls == [("https://bgp.tools/table.txt", {"User-Agent": USER_AGENT})]


def test_bgptools_uses_cache(monkeypatch, tmp_path):
    calls = []

    def fake_get(url, headers, timeout):
        calls.append(url)
        return FakeResponse(TABLE_TEXT)

    cache = tmp_path / "table.txt"
    monkeypatch.setattr(bgptools.requests, "get", fake_get)
    monkeypatch.setattr(bgptools, "_cache_path", lambda: cache)

    expected = ["192.0.2.0/24", "2001:db8::/32"]
    assert bgptools.query_prefixes("64496") == expected
    assert bgptools.query_prefixes("64496") == expected
    assert calls == ["https://bgp.tools/table.txt"]
    assert cache.is_file()


def test_bgptools_simultaneous_downloads(monkeypatch, tmp_path):
    cache = tmp_path / "table.txt"
    barrier = Barrier(2)
    replace = Path.replace

    def simultaneous_replace(self, target):
        barrier.wait(timeout=5)
        return replace(self, target)

    monkeypatch.setattr(bgptools, "_cache_path", lambda: cache)
    monkeypatch.setattr(
        bgptools.requests, "get", lambda *args, **kwargs: FakeResponse(TABLE_TEXT)
    )
    monkeypatch.setattr(Path, "replace", simultaneous_replace)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bgptools.query_prefixes, ["64496", "64496"]))
    assert results == [["192.0.2.0/24", "2001:db8::/32"]] * 2
    assert cache.read_text() == TABLE_TEXT
    assert list(tmp_path.iterdir()) == [cache]


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html>temporary maintenance</html>",
        "192.0.2.1/24 64496\n",
        "192.0.2.0/24 not-an-asn\n",
        "192.0.2.0/24 4294967296\n",
        "192.0.2.0/24 064496\n",
        "fe80::%eth0/64 64496\n",
        TABLE_TEXT + "broken row\n",
    ],
)
def test_bgptools_rejects_invalid_download(monkeypatch, tmp_path, body):
    cache = tmp_path / "table.txt"
    cache.write_text(TABLE_TEXT)
    os.utime(cache, (0, 0))
    monkeypatch.setattr(bgptools, "_cache_path", lambda: cache)
    monkeypatch.setattr(
        bgptools.requests, "get", lambda *args, **kwargs: FakeResponse(body)
    )
    with pytest.raises(ValueError, match="table"):
        bgptools.query_prefixes("64496")
    assert cache.read_text() == TABLE_TEXT
    assert cache.stat().st_mtime == 0
    assert list(tmp_path.iterdir()) == [cache]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.HTTPError])
def test_bgptools_preserves_cache_on_request_failure(monkeypatch, tmp_path, failure):
    cache = tmp_path / "table.txt"
    cache.write_text(TABLE_TEXT)
    os.utime(cache, (0, 0))

    def fail(*args, **kwargs):
        raise failure("upstream request failed")

    monkeypatch.setattr(bgptools, "_cache_path", lambda: cache)
    monkeypatch.setattr(bgptools.requests, "get", fail)
    with pytest.raises(failure):
        bgptools.query_prefixes("64496")
    assert cache.read_text() == TABLE_TEXT


def test_bgptools_cleans_up_after_failed_replace(monkeypatch, tmp_path):
    cache = tmp_path / "table.txt"
    cache.write_text(TABLE_TEXT)
    os.utime(cache, (0, 0))

    def fail(self, target):
        raise OSError("cache replace failed")

    monkeypatch.setattr(bgptools, "_cache_path", lambda: cache)
    monkeypatch.setattr(
        bgptools.requests, "get", lambda *args, **kwargs: FakeResponse(TABLE_TEXT)
    )
    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError, match="cache replace failed"):
        bgptools.query_prefixes("64496")
    assert cache.read_text() == TABLE_TEXT
    assert list(tmp_path.iterdir()) == [cache]


@pytest.mark.parametrize("asn", ["AS064496", "  as64496  "])
def test_bgptools_normalizes_asn(monkeypatch, asn):
    monkeypatch.setattr(bgptools, "_table_text", lambda: TABLE_TEXT)
    assert bgptools.query_prefixes(asn) == ["192.0.2.0/24", "2001:db8::/32"]


@pytest.mark.parametrize(
    "asn", ["", "AS", "not-an-asn", "-1", "1.5", "4294967296", "１２"]
)
def test_bgptools_rejects_invalid_asn_before_io(monkeypatch, asn):
    monkeypatch.setattr(
        bgptools, "_table_text", lambda: pytest.fail("unexpected table lookup")
    )
    with pytest.raises(ValueError, match="invalid ASN"):
        bgptools.query_prefixes(asn)
