import typing

import requests
from bs4 import BeautifulSoup, NavigableString, Tag

__ENDPOIT = 'https://www.enjen.net/asn-blocklist/index.php?asn='
__TYPE = '&type=iplist'
__STATIC_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/jxl,image/webp,*/*;q=0.8'
    'Accept-Language' 'en,de;q=0.7,en-US;q=0.3',
    'DNT': '1',
}


def query_prefixes(asn: str) -> typing.List[str]:
    if 'as' in asn.lower():
        asn = asn[2:]
    r = requests.get(__ENDPOIT + asn + __TYPE, headers=__STATIC_HEADERS)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, 'html.parser')
    tbody = soup.find('div', id='data')
    rows = tbody.find_all('br')
    prefixes = []
    for br in rows:
        next_s = br.nextSibling
        if not (next_s and isinstance(next_s,NavigableString)):
            continue
        next2_s = next_s.nextSibling
        if next2_s and isinstance(next2_s,Tag) and next2_s.name == 'br':
            prefix = str(next_s).strip()
            if prefix:
                prefixes.append(prefix)
    return prefixes
