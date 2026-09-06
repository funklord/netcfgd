# 0162: the probe gives up what it does not need

Status: accepted
Date: 2026-09-06
Milestone: the first privilege separation inside netcfgd

## Context

netcfgd runs as root and holds `CAP_NET_ADMIN`. The captive-portal probe
resolves a URL and reads a reply from the network the machine has just joined.
Until now both were true of one process.

`probe` called `to_socket_addrs`, which is glibc's `getaddrinfo` -- confirmed
from the symbol table rather than assumed:

```text
$ nm -D target/release/netcfgd | grep getaddrinfo
                 U getaddrinfo@GLIBC_2.2.5
```

So NSS modules and a DNS response parser, in C, ran in the privileged process
against a resolver the network under test had just supplied. CVE-2015-7547 is
that shape exactly. netcfgd is not unusual in calling `getaddrinfo`; it is
unusual in calling it seconds after joining an untrusted network, with those
capabilities, at that network's suggestion.

**The working example was already a dependency.** dhcpcd chroots and drops to
an unprivileged user before it parses anything off the wire, which is why
[0142](0142-systemd-kills-what-netcfgd-holds.md)'s bounding set had to be widened for
it. The question the holder asked was whether the same is expressible in C --
it is, more naturally than in Rust, since `fork`, `pipe`, `prctl` and `capset`
are C APIs that Rust reaches only through `unsafe` and libc. So the design
survives the transition in `../c-transition.md` unchanged.

## Decision

**The probe runs in a child that has given up every capability, and the parent
reads a verdict from it.**

`netcfgd_sys::privilege::shed` sets `PR_SET_NO_NEW_PRIVS`, clears the ambient
set, drops the bounding set and zeroes effective, permitted and inheritable --
then **verifies the outcome** rather than trusting the steps, because two of
them are allowed to fail on a machine that had nothing to give up. A caller
that gets an error must not do the thing it was dropping privilege for, and
`helper_main` exits 2 without touching the network.

**`exec`, not just `fork`.** netcfgd is multithreaded -- the rfkill watcher,
one thread per control connection -- and a forked child of a multithreaded
process may call only async-signal-safe functions until it execs, because
another thread may have held malloc's lock at the moment of the fork.
`getaddrinfo` allocates. The child is therefore a fresh single-threaded image
of the same binary, invoked as `netcfgd-probe`, which is what the multi-call
layout of [0024](0024-one-binary-and-what-a-megabyte-would-actually-cost.md)
already provides. Nothing on disk carries that name: the only way to reach it
is for netcfgd to exec itself.

**The child bounds itself with `alarm`.** The parent reads to end of file, and
end of file is the child exiting, so a child that cannot outlive its alarm is a
parent that cannot block. A timer in the parent plus a kill would be two
mechanisms where one does.

**Capabilities are per-thread, and the API says so.** `capset` with a pid of 0,
`PR_CAPBSET_DROP` and `PR_SET_NO_NEW_PRIVS` all act on the calling thread. In
the helper that is the whole process; called from a worker in a threaded
process it would leave every other thread holding what it held, which looks
like shedding and is not.

## Which user, and it is the kernel's answer rather than a convention

Asked directly, and the honest starting point is that the conventional answers
did not fit. **The packaging creates a `netcfgd` *group* for the control socket
and no user**, so there is nothing netcfgd-specific to become; adding one is a
change to four init systems and two package formats for a child that owns
nothing, opens nothing and lives for milliseconds. And `nobody` by name means
`getpwnam`, which means NSS -- the C library this whole change exists to keep
out of the privileged process.

So the id is **`/proc/sys/kernel/overflowuid`**, 65534 by default: the id the
kernel itself substitutes for one it cannot map, non-root on every Linux by
construction, and the same number `nobody` carries on a Debian or Alpine
machine. One file read, no user database.

**Why it is worth having on top of the capability drop.** Capabilities alone
leave uid 0, and uid 0 reads what uid 0 *owns* -- `/etc/netcfgd/secrets` is
0600 and root's, which is every wifi passphrase and 802.1X credential on the
machine. `CAP_DAC_OVERRIDE` being gone does not help: an owner needs no
override.

Order: supplementary groups, then gid, then uid. Once the uid leaves root
neither of the others can be set. It happens *before* the bounding-set loop,
because it spends `CAP_SETGID` and `CAP_SETUID` -- both of which netcfgd's unit
grants for dhcpcd's privsep and which the loop is about to take away.

**And sometimes there is no id to become, which is reported rather than
swallowed.** A user namespace with a single mapping -- `unshare -r`, and every
rootless container -- maps uid 0 and nothing else, so 65534 does not exist to
move to and the kernel refuses. Measured: the first version treated that as
fatal and the helper stopped working under `unshare -rn` entirely. Being uid 0
*there* is not being the machine's root, though: it is a mapped id with no
authority outside the namespace, so capabilities-only is the whole of what
privilege that namespace had to give. `shed` returns which of the two it
reached, the helper says so on stderr on every run, and a caller that needs the
stronger answer can insist on it. The portal probe does not.

## Two things measured, both of which would have shipped

**`PR_CAPBSET_DROP` needs `CAP_SETPCAP`, and netcfgd does not have it.** The
unit lists `CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_SYS_CHROOT CAP_SETUID
CAP_SETGID` and no more. A first version treated `EPERM` there as fatal, so the
helper refused to run -- on precisely the packaged install it was written for,
and on any machine where netcfgd is not root. **That would have been the fifth
sandbox-caused defect in the table in `project.md` 10.46, added by the change
written to argue against them.** Caught by running the helper by hand as an
ordinary user, a control that costs one command.

`EPERM` is tolerated now, and it is safe to tolerate because `NO_NEW_PRIVS` is
already set -- the thing a full bounding set would otherwise be a route around
-- and because the end state is verified rather than assumed.

**A test that shed inside a libtest worker thread reported a full set
afterwards.** `/proc/self/status` reports the thread group leader and `capset`
acted on the worker: neither half was lying, they were about different threads.
`effective_capabilities` asks `/proc/thread-self` now. That first test also
spawned a child process which re-ran its own spawner, took ninety seconds, and
terminated only because a child that has shed sees an empty set and skips --
luck standing in for a stopping condition. The test sheds in a thread now, runs
in eight milliseconds, and has a companion asserting the *other* thread kept
what it had, without which a pass would be equally consistent with the whole
process having been disarmed.

## Consequences

- +4,096 bytes, one page, re-baselined in `size-budget.txt` rather than left to
  ride the tolerance.
- `exit 0` from the helper now implies the capabilities were gone, because the
  verification is inside `shed`. That is what makes the end-to-end check
  meaningful: run under `unshare -rn` from a full set, the helper returns a
  status line and exits 0.
- The config compiler is the second candidate for this treatment -- it parses
  text from an `admin` caller who is deliberately not root. Not done.
