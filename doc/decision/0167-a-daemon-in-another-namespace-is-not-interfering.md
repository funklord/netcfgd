# 0167: a daemon in another namespace is not interfering

Status: accepted
Date: 2026-09-07
Milestone: M8; closes a hazard
[0166](0166-what-cannot-be-attributed-is-killed-by-name.md) created

## The hazard

0166 gave netcfgd a sweep that signals known resolver-writing programs by
name, found by scanning `/proc`. Its own test was isolated in a **pid**
namespace precisely so it could not reach the machine's real daemons.

**Nothing else was.** Nine live scripts configure `write_resolv_conf` and run
under `unshare -rn` -- a *network* namespace, where `/proc` still lists every
process on the host. None of them reaches three consecutive reclaims today, so
nothing was harmed; but that is a margin, not a guard, and one added check in
any of those scripts would have had `make live` terminate the developer's
`dhclient` or NetworkManager.

Isolating one test and leaving the mechanism able to reach the whole machine
is protecting the case that was thought about.

## Decision

**The sweep signals only processes in netcfgd's own network namespace.**

A daemon in a different network namespace cannot be configuring netcfgd's
interfaces, so it is not interfering whatever it is called. That is a
statement about the world rather than about tests: it is equally right inside
a container, where the host's daemons are visible through `/proc` and are
somebody else's business.

Compared by `readlink /proc/self/ns/net` against `/proc/<pid>/ns/net`.

**It fails closed, and that is the opposite of the supervision check beside
it.** Where the link cannot be read -- a process that exited between the scan
and the check, or an unreadable `/proc` entry -- the answer is "not ours to
signal". The two defaults point opposite ways because the costs do: mistaking
a supervised process for an unsupervised one wastes a signal, while mistaking
another namespace's process for one of netcfgd's kills something outside the
world netcfgd manages.

## Measured

On the machine, under `unshare -rn` -- the shape every other live script has,
with the host's `/proc` fully visible -- a persistent writer drove netcfgd to
three reclaims and the sweep ran:

```text
netcfgd: resolv.conf has been taken back 3 times and netcfgd found
         nothing it could signal
```

It saw the host's `dhclient`, which is on its own list of writers, and skipped
it. That process and the host's `wpa_supplicant` were both alive afterwards.

**The negative control was deliberately not run.** Removing the guard and
repeating this on the host is the experiment that would confirm it, and it
confirms it by killing the machine's DHCP client. The guard was made to fail
inside the pid-namespaced test instead, where the damage is contained: with it
removed, a process in another namespace is terminated and
`tests/live/resolv_defended.sh` goes red.

## What writing the test taught, which is worth more than the guard

The first version of that check asserted nothing, twice over, and each was
caught only by sabotage or by measurement:

- **The outsider was not a target.** It ran `exec unshare -n sleep`, so its
  `comm` became `sleep` and the sweep would never have matched it whatever
  namespace it was in. Removing the guard changed nothing and the test stayed
  green. It now asserts `comm` is still `dhclient` -- *the sweep would
  otherwise match it, or this proves nothing*.
- **The pid was the wrong one.** `unshare -n prog` **execs** rather than
  forking, so `$!` is the renamed program itself; taking its child found the
  `sleep` it spawned. Measured rather than reasoned about, by printing `comm`
  for each shell form.

A test for a safety guard that cannot fail is worse than none, because the
guard is exactly what nobody re-checks.
