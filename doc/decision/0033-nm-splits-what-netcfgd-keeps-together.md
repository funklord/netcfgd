# 0033: NM splits what netcfgd keeps together

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

Tier 2's second half: static addressing in the settings dictionary, in both
directions. A settings panel opening a profile has to see the address it is
about to edit, and a panel saving one has to produce configuration netcfgd
reads.

Until now the shim reported `ipv4.method` and nothing else. That is worse than
it sounds: a profile reporting `manual` with an empty address table is one a
panel draws as an empty table, and an operator who then presses save has just
deleted their static address.

## The mismatch, and which way it resolves

netcfgd has one list of addressing sources and one list of routes, with
`default` in the second as an ordinary destination. NM has, per family, a
`method`, an `address-data` array, a `gateway` string, and a `route-data` array
from which the default route is *absent* because it lives in `gateway`.

The translation is mechanical in both directions, and one rule matters more
than the rest: **the default route appears in `gateway` and nowhere else.**
Reporting it in `route-data` as well would draw a duplicate row in every
panel's route table -- once as the gateway field and once as a route to
0.0.0.0/0. Going the other way, `gateway` becomes `default via ...` and joins
the route list, because that is where netcfgd keeps it.

Prefixes are the other half. NM keeps the address and the prefix in separate
fields; netcfgd writes CIDR, which is what an operator types and what `ip addr`
prints. They are rejoined on the way in and split on the way out, so a
generated file reads like one somebody wrote.

## Anything that is not an address is refused

A client can send whatever it likes in `address-data`. Writing it into a
configuration file unchecked would produce a file that does not compile -- and
the failure would reach the client as netcfgd rejecting a network it had just
been told was created. So every address, gateway and next hop is parsed before
it is written, and a bad one is refused by name.

`manual` with no `address-data` is refused too. A panel that sent it would
otherwise produce a network with no addressing and no explanation of why.

## What a client asks for that it did not mean to

`nmcli connection add ... ipv4.method manual ipv4.addresses 192.0.2.5/24`
produces a file with `config = ["192.0.2.5/24", "slaac"]`. The `slaac` is not
noise: nmcli defaults `ipv6.method` to `auto`, so the client really did ask for
IPv6 autoconfiguration alongside the static IPv4 address, and netcfgd's one
composed list is the honest place for both (decision 0006).

The live test asserts the address and the `slaac` separately rather than
matching the whole line, because asserting the line would have been asserting
that nmcli's defaults never change.

## Two test bugs, one of them the interesting kind

**Grepping busctl's prose.** The first version of the read checks matched on
`"method" "s" "manual"`. busctl prints the type without quotes and wraps long
values, so nothing matched -- and because the checks compared a grep count
against zero-or-one, five of them were comparing an empty string to an empty
string and passing. They go through `--json=short` and a parser now.

**A heredoc inside a shell function inside a command substitution.** The
replacement was an inline Python snippet, and quoting an f-string containing
double quotes through those three layers produced a program that ran, printed
nothing, and made the same five checks agree with an empty string a second
time. It is `tests/live/nm_setting.py` now, a file with a name, which is the
version that cannot be broken by a quoting rule nobody remembers.

Both were caught by the checks failing when they should have passed, rather
than by suspicion -- which is the good outcome, and also luck. A check that
compares two empty strings passes silently, and the only defence is to make it
fail on purpose and watch.

## What tier 2 still needs

Per-connection options: MTU, metered, autoconnect priority, and per-profile
DNS. Each is a field-by-field mapping with no new mechanism behind it, which is
why they are last rather than first.
