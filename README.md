# asnban

A python script to query and quickly ban whole prefixes for any given autonomous system.

## How to use

- Lookup the owner of an IP address:

    ```
    $ python asnban.py --ip 192.0.2.1
    192.0.2.1 - ASNA - NA
    ```

- List all the prefixes for an ASN:
    ```
    $ python asnban.py --asn 64496
    24.92.187.0/24
    ```

- List all the prefixes for an ASN and generate `iptables -j DROP` commands:
    ```
    $ python asnban.py --asn 64496 --iptables
    iptables -A INPUT -s 24.92.187.0/24 -j DROP
    ```

- List all the prefixes for an ASN and generate `ufw deny from` commands:
    ```
    $ python asnban.py --asn 64496 --ufw
    ufw insert 1 deny from 24.92.187.0/24
    ```

- Combine both steps and generate commands to block all the prefixes of the AS who owns the given IP address:
    ```
    $ python asnban.py --ban 192.0.2.1 --iptables
    iptables -A INPUT -s 192.0.2.0/24 -j DROP
    iptables -A INPUT -s 192.0.3.0/24 -j DROP
    [... etc ...]
    ```
