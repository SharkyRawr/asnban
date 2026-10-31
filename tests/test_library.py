import pytest

from asnban import (
    Prefix,
    PrefixList,
    iptables_commands,
    lookup_ip,
    prefixes_for_asn,
    prefixes_for_ip,
    ufw_commands,
)

STRINGS = ["192.0.2.0/24", "2001:db8::/32"]
PREFIXES = PrefixList(STRINGS)


def test_prefix_validates_and_normalizes():
    assert str(Prefix("2001:DB8::/32")) == "2001:db8::/32"
    assert str(Prefix.from_str("192.0.2.0/24")) == "192.0.2.0/24"


def test_prefix_repr():
    assert repr(Prefix("192.0.2.0/24")) == "Prefix('192.0.2.0/24')"


def test_prefix_rejects_type():
    with pytest.raises(TypeError):
        Prefix(123)


def test_prefix_rejects_invalid():
    with pytest.raises(ValueError, match="invalid prefix"):
        Prefix("not-a-prefix")


def test_prefix_list_converts():
    assert PREFIXES.to_list() == STRINGS
    assert PrefixList.from_iterable(STRINGS).to_list() == STRINGS
    assert PrefixList.from_iterable(p for p in STRINGS).to_list() == STRINGS
    assert PrefixList([Prefix("192.0.2.0/24")]).to_list() == ["192.0.2.0/24"]
    assert len(PREFIXES) == 2
    assert [str(prefix) for prefix in PREFIXES] == STRINGS


def test_prefix_list_repr():
    assert repr(PREFIXES) == "PrefixList(['192.0.2.0/24', '2001:db8::/32'])"


def test_prefix_list_rejects_single_string():
    with pytest.raises(TypeError):
        PrefixList("192.0.2.0/24")


def test_prefix_list_from_iterable_rejects_string():
    with pytest.raises(TypeError):
        PrefixList.from_iterable("192.0.2.0/24")


def test_prefix_list_rejects_bad_item():
    with pytest.raises(TypeError):
        PrefixList([1])


def test_prefix_list_validates_strings():
    with pytest.raises(ValueError):
        PrefixList(["not-a-prefix"])


def test_lookup_ip(monkeypatch):
    monkeypatch.setattr(
        "asnban.cymru.query", lambda ip: ("13335", "1.1.1.1", "CLOUDFLARENET")
    )
    assert lookup_ip("1.1.1.1") == ("13335", "1.1.1.1", "CLOUDFLARENET")


def test_prefixes_for_asn(monkeypatch):
    monkeypatch.setattr("asnban.bgptools.query_prefixes", lambda asn: STRINGS)
    assert prefixes_for_asn("64496").to_list() == STRINGS


def test_prefixes_for_ip(monkeypatch):
    monkeypatch.setattr(
        "asnban.cymru.query", lambda ip: ("64496", "192.0.2.1", "EXAMPLE")
    )
    monkeypatch.setattr("asnban.bgptools.query_prefixes", lambda asn: STRINGS)
    assert prefixes_for_ip("192.0.2.1").to_list() == STRINGS


def test_iptables_commands():
    assert iptables_commands(PREFIXES) == [
        "iptables -A INPUT -s 192.0.2.0/24 -j DROP",
        "ip6tables -A INPUT -s 2001:db8::/32 -j DROP",
    ]


def test_iptables_commands_options():
    assert iptables_commands(
        PREFIXES, insert=True, chain="FORWARD", action="REJECT"
    ) == [
        "iptables -I FORWARD -s 192.0.2.0/24 -j REJECT",
        "ip6tables -I FORWARD -s 2001:db8::/32 -j REJECT",
    ]


def test_iptables_commands_rejects_list():
    with pytest.raises(TypeError):
        iptables_commands(STRINGS)


def test_ufw_commands():
    assert ufw_commands(PREFIXES) == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]


def test_ufw_commands_rejects_list():
    with pytest.raises(TypeError):
        ufw_commands(STRINGS)
