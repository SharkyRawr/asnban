"""Validated prefix types used by the asnban library."""

import ipaddress
from collections.abc import Iterable, Iterator


class Prefix:
    """A validated IPv4 or IPv6 network prefix.

    :param value: Prefix in CIDR notation, for example ``192.0.2.0/24``.
    :raises TypeError: If ``value`` is not a string.
    :raises ValueError: If ``value`` is not a valid network prefix.
    """

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError(f"prefix must be a string, got {type(value).__name__}")
        try:
            self._value = str(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"invalid prefix: {value!r}") from exc

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Prefix({self._value!r})"

    @classmethod
    def from_str(cls, value: str) -> "Prefix":
        """Build a :class:`Prefix` from a CIDR string.

        :param value: Prefix in CIDR notation.
        :returns: The validated prefix.
        """
        return cls(value)


class PrefixList:
    """An ordered collection of validated :class:`Prefix` objects.

    :param prefixes: Prefix strings or :class:`Prefix` objects.
    :raises TypeError: If a single string or an unsupported item is given.
    :raises ValueError: If a prefix string is invalid.
    """

    def __init__(self, prefixes: Iterable[str | Prefix] = ()):
        if isinstance(prefixes, (str, bytes)):
            raise TypeError(
                "PrefixList expects an iterable of prefixes, not a single string"
            )
        self._prefixes: list[Prefix] = []
        for prefix in prefixes:
            if isinstance(prefix, Prefix):
                self._prefixes.append(prefix)
            elif isinstance(prefix, str):
                self._prefixes.append(Prefix(prefix))
            else:
                raise TypeError(
                    f"prefix must be str or Prefix, got {type(prefix).__name__}"
                )

    def __iter__(self) -> Iterator[Prefix]:
        return iter(self._prefixes)

    def __len__(self) -> int:
        return len(self._prefixes)

    def __repr__(self) -> str:
        return f"PrefixList({self.to_list()!r})"

    def to_list(self) -> list[str]:
        """Return the prefixes as a list of CIDR strings."""
        return [str(prefix) for prefix in self._prefixes]

    @classmethod
    def from_iterable(cls, prefixes: Iterable[str]) -> "PrefixList":
        """Build a :class:`PrefixList` from any iterable of CIDR strings.

        :param prefixes: Iterable of prefix strings in CIDR notation.
        :returns: The validated prefix list.
        :raises TypeError: If a single string or an unsupported item is given.
        :raises ValueError: If any prefix is invalid.
        """
        return cls(prefixes)
