import typing

import requests
from bs4 import BeautifulSoup

__ENDPOIT = 'https://bgp.tools/as/'
__STATIC_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/jxl,image/webp,*/*;q=0.8'
    'Accept-Language' 'en,de;q=0.7,en-US;q=0.3',
    'DNT': '1',
}


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
