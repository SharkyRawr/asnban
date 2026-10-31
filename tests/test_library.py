from asnban import (
    iptables_commands,
    lookup_ip,
    prefixes_for_asn,
    prefixes_for_ip,
    ufw_commands,
)

PREFIXES = ["192.0.2.0/24", "2001:db8::/32"]


def test_lookup_ip(monkeypatch):
    monkeypatch.setattr(
        "asnban.cymru.query", lambda ip: ("13335", "1.1.1.1", "CLOUDFLARENET")
    )
    assert lookup_ip("1.1.1.1") == ("13335", "1.1.1.1", "CLOUDFLARENET")


def test_prefixes_for_asn(monkeypatch):
    monkeypatch.setattr("asnban.bgptools.query_prefixes", lambda asn: PREFIXES)
    assert prefixes_for_asn("64496") == PREFIXES


def test_prefixes_for_ip(monkeypatch):
    monkeypatch.setattr(
        "asnban.cymru.query", lambda ip: ("64496", "192.0.2.1", "EXAMPLE")
    )
    monkeypatch.setattr("asnban.bgptools.query_prefixes", lambda asn: PREFIXES)
    assert prefixes_for_ip("192.0.2.1") == PREFIXES


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


def test_ufw_commands():
    assert ufw_commands(PREFIXES) == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]
