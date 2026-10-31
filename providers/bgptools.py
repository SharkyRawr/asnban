import typing

import requests
from bs4 import BeautifulSoup

from . import USER_AGENT

__ENDPOIT = 'https://bgp.tools/as/'
__STATIC_HEADERS = {'User-Agent': USER_AGENT}


def query_prefixes(asn: str) -> typing.List[str]:
    if 'as' in asn.lower():
        asn = asn[2:]
    r = requests.get(__ENDPOIT + asn, headers=__STATIC_HEADERS)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, 'html.parser')
    tbody = soup.find('tbody', id='prefixlist-tbody')
    rows = tbody.find_all('tr')
    # print(rows)
    prefixes = []
    for row in rows:
        if 'Prefix' in row.get_text():
            continue
        # print(row)
        tds = row.find_all('td')
        prefix = tds[1].get_text()
        if prefix:
            prefixes.append(prefix)
    return prefixes
