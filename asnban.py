import json
import sys
import typing
from argparse import ArgumentParser

ap = ArgumentParser()
ap.add_argument("--ip", nargs='?', help="IP-to-ASN lookup using asn.cymru.com")
ap.add_argument("--asn", nargs='?',
                help="ASN-to-prefixes lookup using bgp.tools")
ap.add_argument('--ban', nargs='?',
                help='ban all prefixes owned by the AS that also owns IP')

ap.add_argument("--iptables", action='store_true',
                help="output as iptables invocations")
ap.add_argument("--iptables-insert", action='store_true',
                default=False, help="use 'iptables -I'")
ap.add_argument("--iptables-chain", nargs='?', default="INPUT",
                help="which chain to insert into, defaults to INPUT")
ap.add_argument("--iptables-action", nargs='?', default="DROP",
                help="which action to use, defaults to DROP")

ap.add_argument('--json',  action='store_true', help="output as JSON")

ap.add_argument("--ufw", action='store_true',
                help="output as 'ufw deny' invocations")


def print_prefixes(prefixes: typing.List[str], args):
    if args.iptables:
        for p in prefixes:
            print("iptables -{aori} {chain} -s {prefix} -j DROP".format(
                aori='I' if args.iptables_insert else 'A',
                chain=args.iptables_chain or 'INPUT',
                prefix=p
            ))
        return

    if args.json:
        print(json.dumps(prefixes, indent=2, separators=(',', ': ')))
        return

    if args.ufw:
        for p in prefixes:
            print("ufw insert 1 deny from {prefix}".format(prefix=p))
        return

    for p in prefixes:
        print(p)
    return


if __name__ == "__main__":
    from providers import bgptools, cymru

    args = ap.parse_args()

    if not args.ip and not args.asn and not args.ban:
        ap.print_help()
        sys.exit(1)

    if args.ip:
        asn, ip, name = cymru.query(args.ip)
        print("{} - AS{} - {}".format(ip, asn, name))
        sys.exit(0)
    elif args.asn:
        prefixes = bgptools.query_prefixes(args.asn)
        print_prefixes(prefixes, args)
    elif args.ban:
        asn, ip, name = cymru.query(args.ban)
        prefixes = bgptools.query_prefixes(asn)
        print_prefixes(prefixes, args)
