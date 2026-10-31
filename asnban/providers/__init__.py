USER_AGENT = "asnban/1.0.0 (+https://github.com/SharkyRawr/asnban)"
HTTP_TIMEOUT = (5, 30)


def normalize_asn(asn: str) -> str:
    """Validate and normalize a decimal 32-bit ASN, optionally prefixed by AS."""
    value = asn.strip()
    if value.lower().startswith("as"):
        value = value[2:]
    if not value.isascii() or not value.isdecimal() or int(value) > 2**32 - 1:
        raise ValueError(f"invalid ASN: {asn!r}")
    return str(int(value))
