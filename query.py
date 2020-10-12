from argparse import ArgumentParser

ap = ArgumentParser()
ap.add_argument("ip", help="IP address to lookup")


if __name__ == "__main__":
    from providers import cymru
    
    args = ap.parse_args()
    asn, ip, name = cymru.query(args.ip)
    print("{} - AS{} - {}".format(ip, asn, name))
