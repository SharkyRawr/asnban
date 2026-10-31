import pytest

from asnban.providers import USER_AGENT, bgptools, cymru

CYMRU_TEXT = """AS | IP | Name
13335 | 1.1.1.1 | CLOUDFLARENET
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
    monkeypatch.setattr(
        cymru.requests, "post", lambda *args, **kwargs: FakeResponse(CYMRU_TEXT)
    )
    assert cymru.query("1.1.1.1") == ("13335", "1.1.1.1", "CLOUDFLARENET")


def test_cymru_unexpected_response(monkeypatch):
    monkeypatch.setattr(
        cymru.requests, "post", lambda *args, **kwargs: FakeResponse("nope")
    )
    with pytest.raises(Exception, match="expected number"):
        cymru.query("1.1.1.1")


def test_bgptools_cache_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert bgptools._cache_path() == tmp_path / "asnban" / "table.txt"


def test_bgptools_query(monkeypatch, tmp_path):
    calls = []

    def fake_get(url, headers):
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

    def fake_get(url, headers):
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
