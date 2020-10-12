import re
import typing

import requests

__ENDPOINT = 'https://asn.cymru.com/cgi-bin/whois.cgi'
CYMRU_RESULT_RE = re.compile(r'(.+)\s*\|\s*(.+)\s?\|\s*(.+)\s?')


def query(qry: str) -> typing.Tuple[str, str, str]:
    args = {
        'action': (None, 'do_whois'),
        'family': (None, 'ipv4'),
        'method_whois': (None, 'whois'),
        'bulk_paste': (None, qry),
        'submit_paste': (None, ''),
    }
    r = requests.post(__ENDPOINT, files=args)
    r.raise_for_status()
    #print(r.text)

    finds = CYMRU_RESULT_RE.findall(r.text)
    if len(finds) != 2:
        raise Exception("Didn't get the expected number of results from API")

    rm = finds[1]
    if len(rm) != 3:
        raise Exception("API response has unfamiliar format")

    asn, ip, name = rm
    asn = asn.strip()
    ip = ip.strip()
    name = name.strip()
    return (asn, ip, name)
