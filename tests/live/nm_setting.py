#!/usr/bin/env python3
"""Pull one field out of a NetworkManager settings dictionary.

    busctl --json=short call ... GetSettings | nm_setting.py ipv4 address

A separate file rather than a heredoc inside the shell script, and that is not
tidiness: the first version was inline, and quoting an f-string containing
double quotes inside a shell function inside a `$(...)` produced a program that
ran, printed nothing, and made five checks agree with an empty string.

Fields:
    method    the addressing method
    address   every static address, as CIDR
    gateway   the default route's next hop
    routes    every route in the table, as CIDR
"""

import json
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    group_name, field = sys.argv[1], sys.argv[2]

    document = json.load(sys.stdin)
    group = document["data"][0].get(group_name, {})

    def scalar(key):
        return group.get(key, {}).get("data", "")

    def entries(key):
        return group.get(key, {}).get("data", [])

    def cidr(entry, address_key):
        address = entry[address_key]["data"]
        prefix = entry["prefix"]["data"]
        return str(address) + "/" + str(prefix)

    if field == "method":
        print(scalar("method"))
    elif field == "gateway":
        print(scalar("gateway"))
    elif field == "address":
        print(" ".join(cidr(e, "address") for e in entries("address-data")))
    elif field == "routes":
        print(" ".join(cidr(e, "dest") for e in entries("route-data")))
    else:
        print("unknown field " + field, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
