import pytest

from asnban.providers import USER_AGENT, bgptools, cymru

PREFIXES = ["192.0.2.0/24", "2001:db8::/32"]

CYMRU_TEXT = """AS | IP | Name
13335 | 1.1.1.1 | CLOUDFLARENET
"""

BGPLIST_HTML = """
<table><tbody id="prefixlist-tbody">
<tr><td>Prefix</td><td>AS</td></tr>
<tr><td>1</td><td>192.0.2.0/24</td></tr>
<tr><td>2</td><td>2001:db8::/32</td></tr>
</tbody></table>
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


def test_bgptools_query(monkeypatch):
    calls = []

    def fake_get(url, headers):
        calls.append((url, headers))
        return FakeResponse(BGPLIST_HTML)

    monkeypatch.setattr(bgptools.requests, "get", fake_get)
    assert bgptools.query_prefixes("AS64496") == PREFIXES
    assert calls == [("https://bgp.tools/as/64496", {"User-Agent": USER_AGENT})]
