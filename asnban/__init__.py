"""Query ASNs and turn their prefixes into suggested firewall actions.

This module is the library entry point: it performs no printing or argument
parsing and returns prefix strings or ready-to-run command strings.
"""

import ipaddress

from .providers import bgptools, cymru

DEFAULT_CHAIN = "INPUT"
DEFAULT_ACTION = "DROP"


def lookup_ip(ip: str) -> tuple[str, str, str]:
    """Look up the AS that owns an IP address.

    :param ip: IPv4 address to look up.
    :returns: Tuple of ``(asn, ip, name)``, where ``asn`` has no ``AS`` prefix.
    :raises requests.HTTPError: If the lookup request fails.
    """
    return cymru.query(ip)


def prefixes_for_asn(asn: str) -> list[str]:
    """Return the prefixes originated by an ASN.

    Prefix data comes from bgp.tools' table export, which is cached locally
    and may lag by roughly 30 minutes.

    :param asn: ASN, with or without a leading ``AS``.
    :returns: Prefix strings such as ``["192.0.2.0/24"]``.
    :raises requests.HTTPError: If the table export cannot be downloaded.
    """
    return bgptools.query_prefixes(asn)


def prefixes_for_ip(ip: str) -> list[str]:
    """Return the prefixes originated by the AS that owns an IP address.

    :param ip: IPv4 address to look up.
    :returns: Prefix strings originated by the AS.
    :raises requests.HTTPError: If a lookup or table download fails.
    """
    asn, _, _ = lookup_ip(ip)
    return prefixes_for_asn(asn)


def iptables_commands(
    prefixes: list[str],
    insert: bool = False,
    chain: str = DEFAULT_CHAIN,
    action: str = DEFAULT_ACTION,
) -> list[str]:
    """Build iptables commands for the given prefixes.

    IPv4 prefixes produce ``iptables`` commands and IPv6 prefixes produce
    ``ip6tables`` commands.

    :param prefixes: Prefix strings to build commands for.
    :param insert: Use ``-I`` instead of ``-A``.
    :param chain: Chain to append or insert into.
    :param action: iptables target, for example ``DROP`` or ``REJECT``.
    :returns: One command string per prefix.
    :raises ValueError: If a prefix is not a valid network.
    """
    commands = []
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix)
        binary = (
            "ip6tables" if isinstance(network, ipaddress.IPv6Network) else "iptables"
        )
        mode = "I" if insert else "A"
        commands.append(f"{binary} -{mode} {chain} -s {prefix} -j {action}")
    return commands


def ufw_commands(prefixes: list[str]) -> list[str]:
    """Build ``ufw deny`` commands for the given prefixes.

    :param prefixes: Prefix strings to build commands for.
    :returns: One command string per prefix.
    """
    return [f"ufw insert 1 deny from {prefix}" for prefix in prefixes]
