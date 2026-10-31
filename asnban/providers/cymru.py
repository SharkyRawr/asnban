import re
import typing
from html import unescape

import requests

from . import HTTP_TIMEOUT, USER_AGENT, normalize_asn

__ENDPOINT = "https://asn.cymru.com/cgi-bin/whois.cgi"
CYMRU_RESULT_RE = re.compile(r"([^|\r\n]+)\|([^|\r\n]+)\|([^<\r\n]+)")


def query(qry: str) -> typing.Tuple[str, str, str]:
    """Look up an IPv4 address with Team Cymru's whois service.

    :param qry: IPv4 address to look up.
    :returns: Tuple of ``(asn, ip, name)``, with space-separated ASNs and
        semicolon-separated names when there are multiple origins.
    :raises requests.HTTPError: If the HTTP request fails.
    :raises ValueError: If the response has an unexpected format.
    """
    args = {
        "action": (None, "do_whois"),
        "family": (None, "ipv4"),
        "method_whois": (None, "whois"),
        "bulk_paste": (None, qry),
        "submit_paste": (None, "Submit"),
    }
    r = requests.post(
        __ENDPOINT,
        files=args,
        headers={"User-Agent": USER_AGENT},
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()

    finds = CYMRU_RESULT_RE.findall(r.text)
    if len(finds) < 2:
        raise ValueError("Cymru response has no lookup results")

    rows = [tuple(unescape(field.strip()) for field in row) for row in finds[1:]]
    if any(ip != qry.strip() for _, ip, _ in rows):
        raise ValueError("Cymru response contains an unexpected IP address")
    asns = dict.fromkeys(
        normalize_asn(asn) if asn != "NA" else asn
        for origins, _, _ in rows
        for asn in origins.split()
    )
    return (
        " ".join(asns),
        rows[0][1],
        "; ".join(dict.fromkeys(name for _, _, name in rows)),
    )
