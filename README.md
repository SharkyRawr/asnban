# asnban

A python script to query and quickly ban whole prefixes for any given autonomous system.

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
commands = asnban.iptables_commands(prefixes)
```

The library returns lists of prefix strings or suggested command strings; the CLI is only a frontend.
