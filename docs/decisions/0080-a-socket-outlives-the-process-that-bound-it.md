# 0080: a socket outlives the process that bound it

Status: accepted
Date: 2026-08-03
Milestone: 0078's first open item, closed

## Context

[0078](0078-a-record-is-a-memory-and-a-process-is-a-fact.md) made the observation
check whether a backend's process is still there, for the kinds netcfgd holds a
pid for, and left two out with a reason: a supplicant and an access point are
reached through control sockets, and **a socket that exists does not prove a
process does**. It called that "a decision waiting to be made rather than a thing
that cannot be done".

The consequence for a supplicant is worse than for most: netcfgd's *start* path
also used the socket as the test.

```rust
if dir.join(iface).exists() {
    // Already running -- started by a previous apply, or surviving a
    // netcfgd restart.
    return Ok(());
}
```

So a supplicant that was killed left netcfgd with two wrong answers reinforcing
each other: the observation said the backend was running, and even a plan that had
correctly decided to start one would have found the socket and returned without
starting anything. On a laptop that is wifi that stops working with netcfgd
reporting a managed radio; on a wired port it is an 802.1X authentication that
never happens again.

## Decision

**netcfgd tells the supplicant where to write its pid, and asks that instead.**

`wpa_supplicant -P <run>/supplicant/<iface>.pid`, which joins it to the set 0078
checks. Three things follow:

- **The pid file's own path is the marker.** netcfgd chose it, it names the
  interface, and `-P` puts it in the command line -- so it is the strongest kind
  of marker `pid_of` takes, stronger than the interface name the DHCP clients have
  to make do with.
- **The start path asks the pid, not the socket**, and a socket with no process
  behind it is *removed* rather than worked around: the next supplicant would fail
  to bind it.
- **The pid file goes on a stop, either way.** wpa_supplicant removes its own on a
  clean exit; one that was killed leaves it, and a stale file would have the next
  observation asking about a pid that belongs to somebody else by then.

**An access point is deliberately not included.** hostapd takes `-P` and the same
three lines would work -- and nothing here could ever run them: `ap.sh`'s hostapd
never starts, because a dummy interface has no radio, and the one script that
gets a real radio needs `mac80211_hwsim` and real root. A liveness path for
hostapd would be code with no test, which this project removes when it finds it
rather than adds. It is one measurement away from being possible -- `hwsim.sh` is
where it would go -- and that is a better place for it than a decision record
promising it.

## What the test is worth

`tests/live/dot1x.sh` is where netcfgd starts a *real* supplicant itself, which
`wifi.sh` does not (there the test starts it). So that is where this goes:

```
ok   netcfgd told the supplicant where to record its pid
ok   its control socket outlived it
ok   netcfgd notices it is gone
ok   and starts another, having cleared the socket the dead one left
ok   and the network it was configured with is back
```

The second line is the one that makes the rest mean something -- a `kill -9` gives
wpa_supplicant no chance to remove either file, so a check that trusted the socket
would report a running supplicant on the strength of it. The last line is the
point of the whole thing: a supplicant holds no state
([0015](0015-the-supplicant-holds-no-state.md)), so a restarted one is empty until
netcfgd repopulates it, and a restart that did not would leave a port configured
and unauthenticated.

Removing the entry from the liveness map fails three of the five.

## Consequences

- A supplicant that dies is noticed and replaced, on the same terms as a tunnel
  and a `DHCP` client.
- A stale control socket no longer blocks a start. That was a second defect hiding
  behind the first, and it needed no new mechanism -- only the pid to tell the two
  cases apart.
- `+0 KB`.

## What is still open

**hostapd**, per above, and the shape of the answer is already written -- what it
needs is a place where a real one runs.

**A daemon that is alive and wedged still counts as up**, unchanged from 0078 and
0079. The pid says the process exists, not that it is answering.
