# 0071: a client with no socket is stopped by the pid it wrote

Status: accepted
Date: 2026-08-03
Milestone: the other half of [0070](0070-a-client-is-stopped-the-way-it-was-started.md), named there and closed here

## Context

0070 fixed a `DHCPv4` client netcfgd could not stop and wrote down what reading the
same code had turned up: **a DHCPv6 client was not stopped at all.**

```rust
other => Err(format!(
    "stopping the {other:?} backend is not implemented in this build"
)),
```

`Dhcp6` fell into that arm. So dropping `config = "dhcp6"` from a document, or
tearing down an interface that had it, produced

```
ncfg: stopping the Dhcp6 backend is not implemented in this build
ncfg: stopped at action 2 (backend.stop); 2 done, 0 not attempted
```

-- a failed apply, with the client still running, still holding the lease and still
renewing the delegation. Loud rather than silent, which is the one good thing about
it and the reason it was written down rather than fixed in the same commit as 0070.

**And `tests/live/delegation.sh` was hiding it.** Its teardown was

```sh
pkill -f odhcp6c
: > "$prefixes"
```

the test doing by hand exactly the two things netcfgd could not do -- stop the client
and empty the prefix file -- and then checking that netcfgd reacted correctly to a
world somebody else had tidied. Nothing was wrong with the assertion that followed
it; what was wrong is that the step before it was not netcfgd's.

## Decision

**`stop_backend` grows a `Dhcp6` arm with the same two shapes as `Dhcp4`**, because
which client is running is a property of the machine and not of the document:

- **dhcpcd** is stopped with `-6 -k`, which is 0070's rule unchanged -- its pid file
  is `<iface>-6.pid` and a stop that does not name the family looks for the wrong
  name. The family is now a parameter of one pair of argument builders rather than a
  constant baked into the `-4` pair, and the unit test walks both families so
  neither can be the one nobody checked.
- **odhcp6c** is stopped by the pid it was told to write. It has no control socket,
  no `-k`, and no `-x`; `-p <pidfile>` and a `SIGTERM` are the whole interface. Read
  out of `odhcp6c.c` rather than assumed: it writes the file only when it
  daemonises, removes it on the way out, and answers `SIGTERM` by sending a RELEASE,
  calling its script one last time and exiting. That last part matters -- "does it
  release?" decides whether an ISP still believes the prefix is ours.

**One function stops both clients that have no socket.** udhcpc's pid handling was
already written; odhcp6c needed the same three steps, and a second copy of "read the
pid, check `/proc/<pid>/cmdline`, signal, remove the file" is the second-list problem
this repository keeps paying for. `stop_recorded_client(program, iface)` and
`client_pid_path(program, iface)` are the pair, and a third client of this shape gets
the same convention rather than inventing one.

## What the test is worth

`delegation.sh`'s teardown is now an edit to the document, which is what an operator
does:

```
ok   the client wrote its pid where netcfgd told it to
ok   dropping dhcp6 from the document is an apply that succeeds
ok   and the client is gone
ok   and emptied the prefix file itself on the way out
ok   and removed the pid file with it
ok   a prefix that goes takes the address derived from it
ok   and the advertiser netcfgd started is stopped too
```

Nothing there truncates a file or kills a process. The prefix file emptying itself is
odhcp6c's own script call on the way out, which is the path the hook's "an empty file
means the lease is gone" comment described and nothing had ever run.

Two things the writing of it cost, both worth more than the fix:

**A check that passed because the feature was broken.** Removing `-p` from the
client's arguments -- to prove the checks could fail -- left three of them green: with
no pid file the test read `pid=0`, `/proc/0/cmdline` does not exist, "is it still
running?" answered no, and "the pid file is gone" was true because there had never
been one. The break that was meant to prove the gate works proved the opposite. The
guard is explicit now: no pid means nothing below can be checked, and that is a
failure rather than a pass.

**`kill -0` is not "is it running".** A daemonised client is reparented to init, and
an init that does not reap -- a container whose pid 1 is `sleep infinity` -- leaves a
zombie that `kill -0` reports as alive. The check reads `/proc/<pid>/cmdline`, which
a zombie does not have, and which is the same question netcfgd's own ownership check
asks.

**And the script was leaving a radvd running on every invocation**, because netcfgd
started one and the teardown never dropped the `advertise` block. It does now, and
that is another backend stop under test; the cleanup trap also kills a radvd started
from this run's directory, scoped so that a failed run does not take out a radvd the
machine was running for its own reasons.

## Consequences

- `config = "dhcp6"` can be removed from a document. That is the whole of the user
  visible change, and it was a failed apply before.
- A stopped odhcp6c releases its lease, so the ISP's delegation is handed back rather
  than left outstanding until it expires.
- The pid file convention is now shared with udhcpc, and `/run/netcfgd/<program>/`
  is where a client with no socket records itself.
- `+0 KB`: one arm, two small functions, and a copy removed.

## What is still open

**dhcpcd's own hooks still write `/etc/resolv.conf` from a `DHCPv6` lease.** 0066
ended that contention for `DHCPv4` by passing `-c`, which replaces dhcpcd's hook
directory; the `DHCPv6` start does not pass one, so on a machine using dhcpcd for
`config = "dhcp6"` both netcfgd and dhcpcd write that file and whichever ran last
wins. The generated hook already has the branch for it -- `new_dhcp6_name_servers`
and `new_dhcp6_domain_search`, asserted by a unit test -- and nothing has ever run
it.

It was not fixed here because it is not only a missing flag. The interface report is
one file per interface, and an interface with both `dhcp` and `dhcp6` would have two
clients rewriting it, each with its own `dns=` lines and each clobbering the other.
That is a report-contract question ([0047](0047-a-tunnels-address-stays-with-its-daemon.md),
[0049](0049-a-server-may-name-resolvers-not-where-queries-go.md)) rather than a
dhcpcd question, and it wants its own decision.

**Nothing notices that a client netcfgd started has died.** Unchanged from 0070, and
still the shape [0053](0053-a-file-netcfgd-does-not-read-can-still-be-hashed.md)
guessed at.
