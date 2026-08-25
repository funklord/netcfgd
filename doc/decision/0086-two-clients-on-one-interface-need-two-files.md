# 0086: two clients on one interface need two files

Status: accepted
Date: 2026-08-04
Milestone: the gap [0072](0072-dhcpcds-own-hooks-are-replaced-or-silenced.md) named and did not close

## Context

[0072](0072-dhcpcds-own-hooks-are-replaced-or-silenced.md) found a `DHCPv6` lease
rewriting `/etc/resolv.conf` behind netcfgd -- 0066's contention, alive on the
family nobody had run -- and silenced dhcpcd's `resolv.conf` and `hostname` hooks
on the v6 client with `-C`. The `DHCPv4` client instead gets `-c`, a script of
netcfgd's that reports the lease's nameservers into
`/run/netcfgd/reported/<interface>`.

The asymmetry had a reason, and 0072 wrote it down:

> the interface report is one file per interface, and a second client writing it
> would clobber the first client's nameservers on every renewal.

True, and it left this, which 0072 also wrote down:

> What a v6 lease says about names therefore still reaches nothing, which is now
> a stated gap with a shape (a fragment directory) rather than an accident.

A stated gap with a shape is still a gap. On a dual-stack interface the machine
resolved by v4 and quietly ignored what the v6 server said. **On a v6-only
network it resolved nothing at all** -- dnsmasq sends `option6:dns-server`,
dhcpcd receives it, netcfgd silences the hook that would have used it, and no
other path carries it.

## Decision

**The single file stays the contract; netcfgd's own writers get a directory.**

```
/run/netcfgd/reported/<interface>          one file, one writer, documented
/run/netcfgd/reported.d/<interface>/<src>  one file per writer
```

`read_reports` merges them: the single file first, then the fragments in name
order. `dhcpcd4`'s report is the single file and `dhcpcd6`'s is a fragment, so a
v4 lease's nameservers precede a v6 lease's -- and the order is the same on every
machine and every boot, rather than whatever `read_dir` hands over.

The single file is untouched on purpose. It is what
[doc/interface-report.md](../interface-report.md) documents, what a modem helper
and a `pppd` script and an `openvpn --route-up` write, and it has exactly one
writer by construction: the thing writing it is the thing that brought the
interface up. The problem was never that file. It was netcfgd starting a *second*
client on an interface that already had one, which is a situation only netcfgd
creates.

**A separate tree rather than `reported/<interface>.d`**, because an interface may
have a dot in its name. `eth0.d` is a legal VLAN interface and its report would
be indistinguishable from a fragment directory belonging to `eth0`.

## What this deletes

`DhcpcdHooks`, and `DHCPCD_SILENCED` with it.

0072 made "what netcfgd does about dhcpcd's own hooks" a two-armed type so that a
third caller could not pick "nothing" -- `Replace(script)` or `Silence`. With the
v6 client given a script, nothing constructs `Silence`, and a one-armed enum
forces no choice. `dhcpcd_start_args` takes a hook path instead, so **every**
dhcpcd netcfgd starts gets `-c` and there is no argument for one that does not.

That is strictly stronger than what it replaces: `-c` replaces dhcpcd's whole
hook directory, where `-C` silenced two hooks by name. Unrepresentable beats
documented, and the test that walked the type's two arms now walks both families
and asserts each gets `-c`.

## The gates

**Live, against a real dhcpcd and a real dnsmasq**, which is where 0072 was
measured and where this had to be. `tests/live/dhcpcd.sh` already stands up a
dnsmasq sending `option6:dns-server` and `option6:domain-search`; five checks were
added to what it does with them:

- the fragment exists, and is the client's own file;
- it carries the lease's nameserver, and its search suffix;
- the nameserver reaches the observation;
- netcfgd does **not** deliver it unasked;
- and a document with a `dns` block does get it.

The fourth is the one that keeps the two decisions from trading places. netcfgd
holds the v6 lease's nameservers now and still does not write the resolver file
on a `config = "dhcp6"` document's say-so: the reporting contract's second gate
wants the addressing to come from the report or the interface to have a `dns`
block, and `dhcp6` alone is neither. 0072 stopped dhcpcd writing that file; 0086
must not start writing it in dhcpcd's place.

Making the v6 client report into the v4 client's file turns three of the five
red.

**In `read_reports`**, three unit tests: two clients on one interface and neither
loses its nameservers, fragments read in name order whatever order the directory
holds, and an interface with *only* fragments still being an interface -- which is
the v6-only machine, and a reader that walked `reported/` and decorated what it
found would report nothing for exactly the machine this decision is about.

Not reading fragments at all turns all three red; using `read_dir` order instead
of sorting turns the second red.

## A note on the first attempt

Two of the live checks were written against `$resolv`, which in that script is
the *system* `/etc/resolv.conf` that the counter-proofs watch dhcpcd rewrite.
netcfgd writes `$NCFG_RUN_DIR`'s copy. One of the two then failed honestly and
the other **passed vacuously**: asserting a v6 nameserver is absent from a file
netcfgd never writes would pass whatever netcfgd did. Both now read netcfgd's
file, and the reason is in a comment beside them.
