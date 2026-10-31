# asnban

A python script to query and quickly ban whole prefixes for any given autonomous system.

API documentation: <https://sharkyrawr.github.io/asnban/>

## How to use

- Lookup the owner of an IP address:

    ```
    $ python -m asnban --ip 192.0.2.1
    192.0.2.1 - ASNA - NA
    ```

- List all the prefixes for an ASN:
    ```
    $ python -m asnban --asn 64496
    24.92.187.0/24
    ```

- List all the prefixes for an ASN and generate `iptables -j DROP` commands:
    ```
    $ python -m asnban --asn 64496 --iptables
    iptables -A INPUT -s 24.92.187.0/24 -j DROP
    ```

- List all the prefixes for an ASN and generate `ufw deny from` commands:
    ```
    $ python -m asnban --asn 64496 --ufw
    ufw insert 1 deny from 24.92.187.0/24
    ```

- Combine both steps and generate commands to block all the prefixes of the AS who owns the given IP address:
    ```
    $ python -m asnban --ban 192.0.2.1 --iptables
    iptables -A INPUT -s 192.0.2.0/24 -j DROP
    iptables -A INPUT -s 192.0.3.0/24 -j DROP
    [... etc ...]
    ```

## Library

```python
import asnban

prefixes = asnban.prefixes_for_asn("64496")
print(prefixes.to_list())  # ['24.92.187.0/24', ...]
commands = asnban.iptables_commands(prefixes)
```

The library returns `PrefixList` objects (validated prefixes, convertible to `list[str]`) or suggested command strings; the CLI is only a frontend.

When an IP has multiple AS origins, `lookup_ip()` keeps its `(asn, ip, name)` tuple
and returns space-separated ASNs with semicolon-separated names. `prefixes_for_ip()`
and `--ban` include prefixes from every origin, removing duplicates. Unannounced IPs
return `NA` ownership and an empty prefix list.

ASNs may have a leading `AS` and leading zeros; malformed or out-of-range values
are rejected. Prefixes cannot contain IPv6 scope identifiers. Generated commands
quote shell arguments and are never executed by the library or CLI.

The bgp.tools export is cached for two hours in `$XDG_CACHE_HOME/asnban/table.txt`
(default: `~/.cache/asnban/table.txt`). Downloads are validated before replacing the
cache. Provider requests use a 5-second connection timeout and a 30-second read timeout.
