import builtins
import json
import runpy
import sys
from pathlib import Path

import pytest

import asnban

PREFIXES = ["192.0.2.0/24", "2001:db8::/32"]


def parse(*argv):
    return asnban.ap.parse_args(list(argv))


def test_plain(capsys):
    asnban.print_prefixes(PREFIXES, parse())
    assert capsys.readouterr().out.split() == PREFIXES


def test_json(capsys):
    asnban.print_prefixes(PREFIXES, parse("--json"))
    assert json.loads(capsys.readouterr().out) == PREFIXES


def test_yaml(capsys):
    asnban.print_prefixes(PREFIXES, parse("--yaml"))
    out = capsys.readouterr().out
    assert "prefixes:" in out
    assert "192.0.2.0/24" in out


def test_yaml_missing(capsys, monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    asnban.print_prefixes(PREFIXES, parse("--yaml"))
    assert "Could not import PyYAML" in capsys.readouterr().out


def test_iptables(capsys):
    asnban.print_prefixes(PREFIXES, parse("--iptables"))
    assert capsys.readouterr().out.splitlines() == [
        "iptables -A INPUT -s 192.0.2.0/24 -j DROP",
        "ip6tables -A INPUT -s 2001:db8::/32 -j DROP",
    ]


def test_iptables_options(capsys):
    args = parse(
        "--iptables",
        "--iptables-insert",
        "--iptables-chain",
        "FORWARD",
        "--iptables-action",
        "REJECT",
    )
    asnban.print_prefixes(PREFIXES, args)
    assert capsys.readouterr().out.splitlines() == [
        "iptables -I FORWARD -s 192.0.2.0/24 -j REJECT",
        "ip6tables -I FORWARD -s 2001:db8::/32 -j REJECT",
    ]


def test_ufw(capsys):
    asnban.print_prefixes(PREFIXES, parse("--ufw"))
    assert capsys.readouterr().out.splitlines() == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]


def run_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["asnban.py", *argv])
    return runpy.run_path(str(Path(asnban.__file__)), run_name="__main__")


def test_cli_requires_an_argument(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch)
    assert exc.value.code == 1
    assert "usage:" in capsys.readouterr().out


def test_cli_ip(monkeypatch, capsys):
    monkeypatch.setattr(
        "providers.cymru.query", lambda ip: ("13335", "1.1.1.1", "CLOUDFLARENET")
    )
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "--ip", "1.1.1.1")
    assert exc.value.code == 0
    assert capsys.readouterr().out == "1.1.1.1 - AS13335 - CLOUDFLARENET\n"


def test_cli_asn(monkeypatch, capsys):
    monkeypatch.setattr("providers.bgptools.query_prefixes", lambda asn: PREFIXES)
    run_cli(monkeypatch, "--asn", "64496")
    assert capsys.readouterr().out.splitlines() == PREFIXES


def test_cli_ban(monkeypatch, capsys):
    monkeypatch.setattr(
        "providers.cymru.query", lambda ip: ("64496", "192.0.2.1", "EXAMPLE")
    )
    monkeypatch.setattr("providers.bgptools.query_prefixes", lambda asn: PREFIXES)
    run_cli(monkeypatch, "--ban", "192.0.2.1", "--ufw")
    assert capsys.readouterr().out.splitlines() == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]
