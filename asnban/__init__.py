"""Query ASNs and turn their prefixes into suggested firewall actions."""

import ipaddress

from .providers import bgptools, cymru

DEFAULT_CHAIN = "INPUT"
DEFAULT_ACTION = "DROP"


def lookup_ip(ip: str) -> tuple[str, str, str]:
    """Return ``(asn, ip, name)`` for an IP address."""
    return cymru.query(ip)


def prefixes_for_asn(asn: str) -> list[str]:
    """Return the prefixes announced by an ASN."""
    return bgptools.query_prefixes(asn)


def prefixes_for_ip(ip: str) -> list[str]:
    """Return the prefixes announced by the AS that owns an IP address."""
    asn, _, _ = lookup_ip(ip)
    return prefixes_for_asn(asn)


def iptables_commands(
    prefixes: list[str],
    insert: bool = False,
    chain: str = DEFAULT_CHAIN,
    action: str = DEFAULT_ACTION,
) -> list[str]:
    """Return iptables/ip6tables commands for the prefixes."""
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
    """Return ufw deny commands for the prefixes."""
    return [f"ufw insert 1 deny from {prefix}" for prefix in prefixes]
