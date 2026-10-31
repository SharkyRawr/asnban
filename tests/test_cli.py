import builtins
import json
import runpy
import sys

import pytest

from asnban import PrefixList, cli

PREFIXES = PrefixList(["192.0.2.0/24", "2001:db8::/32"])


def parse(*argv):
    return cli.build_parser().parse_args(list(argv))


def run(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["asnban", *argv])
    cli.main()


def test_render_default():
    assert cli.render(PREFIXES, parse()) == PREFIXES.to_list()


def test_render_json():
    lines = cli.render(PREFIXES, parse("--json"))
    assert len(lines) == 1
    assert json.loads(lines[0]) == PREFIXES.to_list()


def test_render_yaml():
    lines = cli.render(PREFIXES, parse("--yaml"))
    assert len(lines) == 1
    assert "prefixes:" in lines[0]
    assert "192.0.2.0/24" in lines[0]


def test_render_yaml_missing(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    lines = cli.render(PREFIXES, parse("--yaml"))
    assert "Could not import PyYAML" in lines[0]


def test_render_iptables():
    assert cli.render(PREFIXES, parse("--iptables")) == [
        "iptables -A INPUT -s 192.0.2.0/24 -j DROP",
        "ip6tables -A INPUT -s 2001:db8::/32 -j DROP",
    ]


def test_render_iptables_options():
    args = parse(
        "--iptables",
        "--iptables-insert",
        "--iptables-chain",
        "FORWARD",
        "--iptables-action",
        "REJECT",
    )
    assert cli.render(PREFIXES, args) == [
        "iptables -I FORWARD -s 192.0.2.0/24 -j REJECT",
        "ip6tables -I FORWARD -s 2001:db8::/32 -j REJECT",
    ]


def test_render_ufw():
    assert cli.render(PREFIXES, parse("--ufw")) == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]


def test_main_requires_an_argument(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch)
    assert exc.value.code == 1
    assert "usage:" in capsys.readouterr().out


def test_main_ip(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "lookup_ip", lambda ip: ("13335", "1.1.1.1", "CLOUDFLARENET")
    )
    run(monkeypatch, "--ip", "1.1.1.1")
    assert capsys.readouterr().out == "1.1.1.1 - AS13335 - CLOUDFLARENET\n"


def test_main_asn(monkeypatch, capsys):
    monkeypatch.setattr(cli, "prefixes_for_asn", lambda asn: PREFIXES)
    run(monkeypatch, "--asn", "64496")
    assert capsys.readouterr().out.splitlines() == PREFIXES.to_list()


def test_main_ban(monkeypatch, capsys):
    monkeypatch.setattr(cli, "prefixes_for_ip", lambda ip: PREFIXES)
    run(monkeypatch, "--ban", "192.0.2.1", "--ufw")
    assert capsys.readouterr().out.splitlines() == [
        "ufw insert 1 deny from 192.0.2.0/24",
        "ufw insert 1 deny from 2001:db8::/32",
    ]


def test_main_module(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["asnban"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("asnban", run_name="__main__")
    assert exc.value.code == 1
