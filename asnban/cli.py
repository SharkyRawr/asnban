"""Command-line frontend for the asnban library."""

import json
import sys
from argparse import ArgumentParser, Namespace

from . import (
    DEFAULT_ACTION,
    DEFAULT_CHAIN,
    PrefixList,
    iptables_commands,
    lookup_ip,
    prefixes_for_asn,
    prefixes_for_ip,
    ufw_commands,
)


def build_parser() -> ArgumentParser:
    ap = ArgumentParser()
    ap.add_argument("--ip", nargs="?", help="IP-to-ASN lookup using asn.cymru.com")
    ap.add_argument("--asn", nargs="?", help="ASN-to-prefixes lookup using bgp.tools")
    ap.add_argument(
        "--ban", nargs="?", help="ban all prefixes owned by the AS that also owns IP"
    )

    ap.add_argument(
        "--iptables", action="store_true", help="output as iptables invocations"
    )
    ap.add_argument(
        "--iptables-insert",
        action="store_true",
        default=False,
        help="use 'iptables -I' (combine with --iptables)",
    )
    ap.add_argument(
        "--iptables-chain",
        default=DEFAULT_CHAIN,
        help="which chain to insert into, defaults to INPUT (combine with --iptables)",
    )
    ap.add_argument(
        "--iptables-action",
        default=DEFAULT_ACTION,
        help="which action to use, defaults to DROP (combine with --iptables)",
    )

    ap.add_argument("--json", action="store_true", help="output as JSON")

    ap.add_argument("--yaml", action="store_true", help="output as YAML")

    ap.add_argument(
        "--ufw", action="store_true", help="output as 'ufw deny' invocations"
    )
    return ap


def render(prefixes: PrefixList, args: Namespace) -> list[str]:
    """Turn a prefix list into the output lines requested by the CLI flags."""
    if args.iptables:
        return iptables_commands(
            prefixes,
            insert=args.iptables_insert,
            chain=args.iptables_chain,
            action=args.iptables_action,
        )

    if args.json:
        return [json.dumps(prefixes.to_list(), indent=2, separators=(",", ": "))]

    if args.yaml:
        try:
            from yaml import dump as yaml_dump
        except ImportError:
            return [
                "Could not import PyYAML, YAML output not supported.\n"
                "You may try to fix this with: 'pip install PyYAML' and then retrying your last commad."
            ]
        return [yaml_dump({"prefixes": prefixes.to_list()})]

    if args.ufw:
        return ufw_commands(prefixes)

    return prefixes.to_list()


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()

    if not args.ip and not args.asn and not args.ban:
        ap.print_help()
        sys.exit(1)

    try:
        if args.ip:
            asns, ip, name = lookup_ip(args.ip)
            owners = ", ".join(f"AS{asn}" for asn in asns.split())
            print(f"{ip} - {owners} - {name}")
            return

        prefixes = prefixes_for_asn(args.asn) if args.asn else prefixes_for_ip(args.ban)
        for line in render(prefixes, args):
            print(line)
    except ValueError as exc:
        ap.error(str(exc))
