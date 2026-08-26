# 0140: a handle must be recoverable from the process

Status: accepted
Date: 2026-08-26
Milestone: M8; found on a real machine, not in the suite

Corrects a row of [0135](0135-the-kernel-holds-the-ownership-record.md) and
adds the kind [0139](0139-three-kinds-of-state-and-one-that-must-not-survive.md)
did not enumerate.

## What happened

A laptop ran netcfgd beside NetworkManager. netcfgd took the radio, started its
supplicant, associated, took a lease -- all correct. netcfgd was then stopped.
Per [0134](0134-an-unannounced-stop-holds.md) it tore nothing down, so the
supplicant kept running. Also correct, and the whole point of that record.

**Then netcfgd could not find it again.** `RuntimeDirectory=netcfgd` deletes
`/run/netcfgd` on a real stop, and the pid file went with it. On restart:

- `dir.join(iface).exists()` -- true, the orphan still holds the socket.
- `pid_of(&pidfile, ...)` -- `None`, because the file is gone.
- `answers(&dir, iface)` -- true, the orphan is alive and replying.
- So netcfgd returned *"something else is already running a supplicant"* and
  told the operator to stop NetworkManager, **for a process netcfgd started
  itself**.

It never recovered. The error returns before `started_backends` is pushed, so
0079's counter never increments and its give-up path never runs; every
reconcile repeated the refusal. Meanwhile NetworkManager started its own
supplicant, and netcfgd's orphaned `dhcpcd` kept renewing: two supplicants and
two DHCP clients on one radio, a fresh lease roughly once a minute, thirteen
addresses consumed, and a link that disconnected continuously.

## What was actually wrong

**Not that the orphan survived.** 0134 is right, and a teardown on exit would
drop a VPN over wifi every time netcfgd was upgraded -- which is the outage
that record exists to prevent. The orphan surviving is the feature.

**The defect is that the handle did not survive with it.** netcfgd marks its
supplicant durably -- it is started with `-P <run>/supplicant/<iface>.pid`, so
that path sits in the process's own `argv` for as long as it lives. What
netcfgd lost was not the mark but the *index into it*: `pid_of` reads the pid
from a file and only then checks `/proc/<pid>/cmdline`. No file, no pid, no
answer, and the marker in argv is never consulted.

**A pid file is a fifth kind of runtime state**, and 0139's four do not cover
it. It is not intended state, not a projection of it, not a claim about objects
that exist, not a promise never kept. **It is a handle to a live process**, and
losing one is not a leak -- it is a loss of control over something still
running and still acting.

That is what 0135's table missed. It put backends in the derivable column on
the strength of "pid file plus `/proc/<pid>/cmdline>`", without noticing that
the first term lives in the directory being wiped.

## Decision

**Where netcfgd marks a process durably, it must be able to find that process
from the mark alone.**

`netcfgd_sys::process::pid_by_marker` scans `/proc` for a process carrying the
marker as a **whole `argv` element**, by the same test `pid_of` applies. It is
`pid_of`'s recovery path: `pid_of` is the cheap answer, this is what to ask
when the file that held the pid is gone.

`start_supplicant` consults it between the pid-file check and the foreign
refusal. On a hit it rewrites the pid file and returns -- **adopting, not
restarting**, because the association the orphan is holding is exactly what
0134 wanted kept. Rewriting the file is what restores the observer and
`stop_backend`, both of which key on it existing.

### The scan is the narrow exception, and the marker is why

`process.rs`'s own header forbids finding a process by name: an operator's own
`wpa_supplicant` would be reached along with netcfgd's, and that is a security
property rather than a convenience.

This does not weaken it. The marker is an absolute path netcfgd composed from
its own run directory and one interface name, matched as a whole argument. No
other manager's command line carries it. **Loosen it to a substring or to a
program name and the rule really is broken** -- which is why the negative unit
tests are not optional: a proper prefix must not match, a longer string must
not match, and a marker nothing carries must return nothing rather than a stray
pid.

### And the refusal now names the test it applied

The old message asserted "something else is already running a supplicant". It
now says a supplicant netcfgd did not start is answering, **and that no process
carries `-P <pidfile>`** -- the check it actually performed, which an operator
can disprove.

It also names both units to stop. On Debian `wpa_supplicant.service` is enabled
and runs independently of NetworkManager, parented to systemd, so the old
advice -- stop NetworkManager -- leaves the socket answering and netcfgd
declining. That was a real report ("netcfgd stops working if I don't have NM
running") and the message was part of why it stayed mysterious.

## What this cost elsewhere, recorded because it is the interesting part

**`dot1x.sh`'s simulation stopped standing for the thing it simulates.** It
faked a foreign supplicant by deleting netcfgd's pid file, with a comment
saying so: *"Simulated by taking away netcfgd's memory rather than by
installing NetworkManager"*. That was fair while a missing pid file and a
foreign process were the same observation. They are not any more -- the process
still carries the marker -- so the scenario now produces netcfgd's own orphan,
and adopting it is correct.

The test asserts adoption now, and the genuinely foreign case stays where it
was always done properly: `displace.sh` starts a supplicant that never carried
the marker. **A simulation is only ever a stand-in, and a change that makes the
real thing distinguishable retires it.**

## Consequences

**0134 is unchanged and better supported.** Holding on exit is right; this is
what makes it survivable.

**The advice in 0135's alternatives -- "a kernel-visible marker" -- has a
sibling.** Addresses, routes and links carry marks the kernel holds. A process
carries its mark in `argv`, which is equally durable and was equally
unconsulted.

**`orphan.sh` performs the step nothing else did**: `rm -rf "$work/run"` while
the process lives. Verified in both directions -- without the adoption branch
it fails on writing the pid file back, on naming the surviving process, and on
not blaming another manager; with it, `displace.sh` still refuses a stranger.

## Alternatives considered

**Add a `SIGTERM` teardown that stops the supplicant.** Rejected: it takes the
network down on every upgrade, which is 0134's whole objection, and the crash
case would still orphan.

**Stop supervised backends on a *clean* stop only.** Rejected: 0134's own table
puts a deliberate `systemctl stop` in the unannounced default whenever it does
not come through the designed channel, and `debian/prerm` already refuses the
same thing -- pulling a package is not an instruction to take the network away.
This belongs to the announced-teardown channel 0134 leaves open.

**`RuntimeDirectoryPreserve=yes`.** Rejected for the reason 0135 gives -- a
deliberate stop should clean up, and a reboot would then look like a restart --
and because it is systemd-only, while OpenRC and procd never delete the
directory at all. The fix has to work wherever the file is lost.

**Move the pid file outside `/run/netcfgd`.** Rejected: it puts runtime state
somewhere constraint 1 does not describe, and helps no init that already keeps
the directory.
