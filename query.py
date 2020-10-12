import sys
from argparse import ArgumentParser
import json

ap = ArgumentParser()
ap.add_argument("--ip", nargs='?', help="IP-to-ASN lookup using asn.cymru.com")
ap.add_argument("--asn", nargs='?',
                help="ASN-to-prefixes lookup using bgp.tools")

ap.add_argument("--iptables", action='store_true', help="output as iptables invocations")
ap.add_argument("--iptables-insert", action='store_true', default=False, help="use 'iptables -I'")
ap.add_argument("--iptables-chain", nargs='?', default="INPUT", help="which chain to insert into, defaults to INPUT")
ap.add_argument("--iptables-action", nargs='?', default="DROP", help="which action to use, defaults to DROP")

ap.add_argument('--json',  action='store_true', help="output as JSON")

if __name__ == "__main__":
    from providers import cymru, bgptools

    args = ap.parse_args()

    if not args.ip and not args.asn:
        ap.print_help()
        sys.exit(1)

    if args.ip:
        asn, ip, name = cymru.query(args.ip)
        print("{} - AS{} - {}".format(ip, asn, name))
        sys.exit(0)

    if args.asn:
        prefixes = bgptools.query_prefixes(args.asn)

        if args.iptables:
            for p in prefixes:
                print("iptables -{aori} {chain} -s {prefix} -j DROP".format(
                    aori='I' if args.iptables_insert else 'A',
                    chain=args.iptables_chain or 'INPUT',
                    prefix=p
                ))
            sys.exit(0)

        if args.json:
            print(json.dumps(prefixes, indent=2, separators=(',', ': ')))#
            sys.exit(0)

        
        for p in prefixes:
            print(p)
        sys.exit(0)
