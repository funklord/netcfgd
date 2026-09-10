# 0191: a lease is a precondition, not a verdict

Status: accepted
Date: 2026-09-10
Milestone: M8; asked for as "another probe method I forgot -- whether or not we
have a dhcp-lease"

## The question, and the two answers it came with

> Should this be done in a script? As it might be different based on dhcpcd
> type used... Maybe have a ncfg command to poll it? though it might cause an
> endless loop.

Both instincts point at real hazards and neither is the answer.

**A script would have to know which client is running.** dhcpcd keeps leases
in `/var/lib/dhcpcd`, dhclient in `dhclient.leases`, udhcpc keeps none at all.
That is exactly the client-specific knowledge netcfgd spends its DHCP code
avoiding -- and it is unnecessary, because **the kernel already normalises
it**: whichever client installed the route, the kernel stamps `RTPROT_DHCP` on
it. One fact, one place.

**A polling command would be a process asking netcfgd something netcfgd
already knows.** The observation carries the routes and their protocols on
every reconcile; nothing needs to be polled. (The endless-loop worry is right
in general and is why `ncfg wait-online` takes a deadline and exits with a
reason -- 0190. It just does not apply here.)

## The route, not the address

Measured on the reporting machine, on a live DHCP lease:

    address: 10.78.60.134/22  proto: None
    route:   default          proto: 16

`IFA_PROTO` -- the same stamp on an address -- arrived in Linux 5.18 and is
absent on plenty of running kernels. `RTPROT_DHCP` on a route is old enough to
rely on, so the predicate reads the route.

## A precondition, and never a verdict

**A lease is a weaker claim than connectivity**, and the probe exists because
of exactly that gap: 0119 was written for a cable in a switch that had lost its
own uplink. A local DHCP server hands out leases happily on such a network. So
this must not be a probe *method* that could stand in for the reachability
check.

What it is good for is the other direction. An interface whose `config` asks
for DHCP and has no lease has **nothing a reachability probe could succeed
over**: the program can only fail, and finding that out costs a process every
interval on the links that are already in trouble. `require_lease` answers from
the route table and spawns nothing.

Counted as a probe that *ran and said no*, not as one that could not start:
the start-failure counter exists to set aside a probe with a typo in its
command (0119), and a link with no lease is not that.

## Default on, and off is a real setting

Default on, because it is right wherever netcfgd can see the client -- which
is every client it starts. **Off is for the operator whose client netcfgd
cannot recognise**: one installing routes with a proto of its own, or none at
all. Requiring a lease there would hold a working link down for ever, which is
worse than the spawn it saves.

`require_lease = false` rather than `skip_lease_check = true`: the first reads
as a decision, the second as a workaround.

**And only where DHCP was asked for.** A statically addressed interface has no
lease and never will; requiring one there would take its routes away and never
give them back. That condition is not an optimisation, it is the difference
between a precondition and a bug.

## What is checked

Four tests, and the shape matters: the probe command in each **would succeed
if it ran** and touches a file to prove whether it did. So "no lease, and the
verdict is down" cannot pass by the program failing -- only by the
precondition deciding. With a lease the file appears, which is what stops the
first test passing because nothing ever runs. A route with `proto 3` is not a
lease -- netcfgd's own routes carry that, and counting one would make the
check pass on an interface that never had a lease. And `require_lease = false`
runs the program with no lease at all, after asserting the key survived the
compiler.

Sabotage confirms: disabling the condition turns two of them red.

## What this also fixed on the way

`doc/netcfgd.conf.example` calls itself "every feature, with the syntax to use
it" and **had no `probe` block in it at all** -- a feature with a shipped
script and no entry in the file an operator reads. It has one now, including
what `down_after` being larger than `up_after` is for.
