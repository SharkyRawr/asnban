import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import requests

from ..prefixes import Prefix
from . import HTTP_TIMEOUT, USER_AGENT, normalize_asn

__ENDPOINT = "https://bgp.tools/table.txt"
__CACHE_TTL = 2 * 60 * 60
__STATIC_HEADERS = {"User-Agent": USER_AGENT}


def _cache_path() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "asnban" / "table.txt"


def _validate_table(text: str) -> None:
    if not text.strip():
        raise ValueError("bgp.tools returned an empty table")
    try:
        for line in text.splitlines():
            prefix, origin = line.split()
            Prefix(prefix)
            if origin != normalize_asn(origin):
                raise ValueError("non-canonical ASN")
    except ValueError as exc:
        raise ValueError("bgp.tools returned an invalid table") from exc


def _table_text() -> str:
    cache = _cache_path()
    if cache.is_file() and time.time() - cache.stat().st_mtime < __CACHE_TTL:
        return cache.read_text(encoding="utf-8")

    response = requests.get(__ENDPOINT, headers=__STATIC_HEADERS, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    text = response.text
    _validate_table(text)

    cache.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=cache.parent, prefix="table-") as directory:
        tmp = Path(directory) / cache.name
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(cache)
    return text


def query_prefixes(asn: str) -> list[str]:
    """Return prefixes originated by an ASN according to bgp.tools.

    Reads the cached bgp.tools ``table.txt`` export, downloading it again
    when the local copy is older than two hours.

    :param asn: ASN, with or without a leading ``AS``.
    :returns: List of prefix strings originated by the ASN.
    :raises requests.HTTPError: If the table export cannot be downloaded.
    :raises ValueError: If the ASN or downloaded table is invalid.
    """
    asn = normalize_asn(asn)

    prefixes = []
    for line in _table_text().splitlines():
        prefix, _, origin = line.rpartition(" ")
        if origin == asn:
            prefixes.append(prefix)
    return prefixes
