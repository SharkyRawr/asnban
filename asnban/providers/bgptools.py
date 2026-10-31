import os
import time
from pathlib import Path

import requests

from . import USER_AGENT

__ENDPOINT = "https://bgp.tools/table.txt"
__CACHE_TTL = 2 * 60 * 60
__STATIC_HEADERS = {"User-Agent": USER_AGENT}


def _cache_path() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "asnban" / "table.txt"


def _table_text() -> str:
    cache = _cache_path()
    if cache.is_file() and time.time() - cache.stat().st_mtime < __CACHE_TTL:
        return cache.read_text()

    response = requests.get(__ENDPOINT, headers=__STATIC_HEADERS)
    response.raise_for_status()

    cache.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache.with_name(cache.name + ".tmp")
    tmp.write_text(response.text)
    tmp.replace(cache)
    return response.text


def query_prefixes(asn: str) -> list[str]:
    asn = asn.strip()
    if asn.lower().startswith("as"):
        asn = asn[2:]

    prefixes = []
    for line in _table_text().splitlines():
        prefix, _, origin = line.rpartition(" ")
        if origin == asn:
            prefixes.append(prefix)
    return prefixes
