"""Query ASNs and turn their prefixes into suggested firewall actions.

This module is the library entry point: it performs no printing or argument
parsing and returns validated prefix lists or ready-to-run command strings.
"""

import ipaddress

from .prefixes import Prefix, PrefixList
from .providers import bgptools, cymru

__all__ = [
    "DEFAULT_ACTION",
    "DEFAULT_CHAIN",
    "Prefix",
    "PrefixList",
    "iptables_commands",
    "lookup_ip",
    "prefixes_for_asn",
    "prefixes_for_ip",
    "ufw_commands",
]

DEFAULT_CHAIN = "INPUT"
DEFAULT_ACTION = "DROP"


def lookup_ip(ip: str) -> tuple[str, str, str]:
    """Look up the AS that owns an IP address.

    :param ip: IPv4 address to look up.
    :returns: Tuple of ``(asn, ip, name)``, where ``asn`` has no ``AS`` prefix.
    :raises requests.HTTPError: If the lookup request fails.
    """
    return cymru.query(ip)


def prefixes_for_asn(asn: str) -> PrefixList:
    """Return the prefixes originated by an ASN.

    Prefix data comes from bgp.tools' table export, which is cached locally
    and may lag by roughly 30 minutes.

    :param asn: ASN, with or without a leading ``AS``.
    :returns: Validated prefixes originated by the ASN.
    :raises requests.HTTPError: If the table export cannot be downloaded.
    :raises ValueError: If bgp.tools returns an invalid prefix.
    """
    return PrefixList(bgptools.query_prefixes(asn))


def prefixes_for_ip(ip: str) -> PrefixList:
    """Return the prefixes originated by the AS that owns an IP address.

    :param ip: IPv4 address to look up.
    :returns: Validated prefixes originated by the AS.
    :raises requests.HTTPError: If a lookup or table download fails.
    """
    asn, _, _ = lookup_ip(ip)
    return prefixes_for_asn(asn)


def iptables_commands(
    prefixes: PrefixList,
    insert: bool = False,
    chain: str = DEFAULT_CHAIN,
    action: str = DEFAULT_ACTION,
) -> list[str]:
    """Build iptables commands for the given prefixes.

    IPv4 prefixes produce ``iptables`` commands and IPv6 prefixes produce
    ``ip6tables`` commands.

    :param prefixes: Validated prefixes to build commands for.
    :param insert: Use ``-I`` instead of ``-A``.
    :param chain: Chain to append or insert into.
    :param action: iptables target, for example ``DROP`` or ``REJECT``.
    :returns: One command string per prefix.
    :raises TypeError: If ``prefixes`` is not a :class:`PrefixList`.
    """
    if not isinstance(prefixes, PrefixList):
        raise TypeError("prefixes must be a PrefixList")

    commands = []
    for prefix in prefixes:
        network = ipaddress.ip_network(str(prefix))
        binary = (
            "ip6tables" if isinstance(network, ipaddress.IPv6Network) else "iptables"
        )
        mode = "I" if insert else "A"
        commands.append(f"{binary} -{mode} {chain} -s {prefix} -j {action}")
    return commands


def ufw_commands(prefixes: PrefixList) -> list[str]:
    """Build ``ufw deny`` commands for the given prefixes.

    :param prefixes: Validated prefixes to build commands for.
    :returns: One command string per prefix.
    :raises TypeError: If ``prefixes`` is not a :class:`PrefixList`.
    """
    if not isinstance(prefixes, PrefixList):
        raise TypeError("prefixes must be a PrefixList")
    return [f"ufw insert 1 deny from {prefix}" for prefix in prefixes]
