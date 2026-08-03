# 0074: a daemon that cannot answer is still running

Status: accepted
Date: 2026-08-03
Milestone: the third time this session that netcfgd could not stop what it started

## Context

`tests/live/openvpn.sh` was leaving a daemon behind on about every other run.
Fixing its cleanup trap (whose `pkill` pattern had matched nothing for months)
stopped the strays escaping the script, and left the interesting half unexplained:
four daemons started, three `signal SIGTERM` received, one alive, its management
socket gone, and `ncfg apply` reporting nothing to do.

It would not reproduce on an idle machine -- ten runs clean -- which is the shape
`acl.sh` and `switch.sh` already describe: a window that is only wide enough to
fall into when something else is loading the machine. So it was made explicit
rather than called unreproducible. With a deliberate gap between the fork and the
bind:

```
--- start said: 1 backend.start
--- stop reported SUCCESS
ok   backend.stop vpn0  openvpn: <absent> (was OpenVpn)
--- daemons still alive after the stop: 1
--- what netcfgd thinks now:
nothing to do
```

**`--daemon` returns as soon as openvpn forks.** The child binds the management
socket a moment later, and in that window `Management::connect` fails -- which
`stop` read as "nothing is running", the state it was asked to produce. So netcfgd
reported a stopped tunnel, left the daemon holding the link, and then had nothing
to say about it ever again: the socket it would use is gone, and the observation is
of interfaces rather than of processes.

It is [0070](0070-a-client-is-stopped-the-way-it-was-started.md) and
[0071](0071-a-client-with-no-socket-is-stopped-by-the-pid-it-wrote.md) a third
time, and the pattern is now clear enough to name: **netcfgd could stop the
daemons it could reach, and had no answer for the ones it could not.** A dhcpcd
under the wrong pid file name, a `DHCPv6` client with no arm at all, and now a
tunnel that had not finished starting.

## Decision

**A daemon netcfgd starts writes its pid where netcfgd told it to, and a stop that
cannot reach the socket falls back to that pid.**

- `--writepid <run>/openvpn/<iface>.pid` on the command line. openvpn's own
  option, so the file is the daemon's claim about itself rather than netcfgd's
  guess -- which matters, because the pid netcfgd could observe is the parent that
  exits.
- `stop` still goes through the management socket first. That is
  [0046](0046-the-ovpn-file-is-the-operators.md) and decision 0014's rule
  unchanged: a daemon is stopped through its own interface, never by finding
  something with a matching name, because an operator's own tunnels are common.
- Only when nothing is listening does it read the pid file -- and it checks
  `/proc/<pid>/cmdline` for **this tunnel's socket path**, not for the interface
  name. `vpn0` is a short string that an unrelated command line could contain; the
  socket path is netcfgd's own and unique to this tunnel on this machine. One
  notch stricter than `pppd_pid` and the DHCP clients, because here there is a
  path to match on.
- A pid file naming nothing, or naming something that is not this tunnel, is
  removed and the stop reports success. "Stopping one that is already stopped is
  not an error" stays true, and it now means what it says.

## What the test is worth

`FAKE_OPENVPN_BIND_DELAY` opens the window on purpose, and the fake writes its pid
before sleeping -- which is the order openvpn does it in, `possibly_become_daemon`
before the management interface comes up. What is faked is the *timing*, never the
protocol, which is the line `fake_openvpn.py` has always drawn.

```
ok   the daemon wrote the pid netcfgd asked it for
ok   and its socket is not there yet, which is the whole point
ok   a daemon stopped before it could listen is stopped anyway
ok   and the pid file goes with it
```

Restoring the old behaviour -- give up when nothing is listening -- fails the third
and fourth of those, and the failure prints what an operator would have seen:
`ok backend.stop vpn0` beside a pid that is still running.

The second check earns its place: without it, a machine fast enough to bind before
the stop arrives would pass the third check having tested nothing.

## Consequences

- A tunnel is stopped whether or not it got as far as listening.
- `netcfgd-openvpn` gains a dependency on `netcfgd-sys`, for `process::terminate`
  -- constraint 4's crate is where a libc call lives, and this is the second
  backend to need exactly that one.
- `+0 KB`.

## What is still open

**~~The same window exists for every daemon netcfgd starts and then talks to.~~
Measured, and it does not.** The other two were checked with netcfgd's own
invocations, against the real binaries:

| daemon | how netcfgd backgrounds it | socket when the parent returns |
|---|---|---|
| openvpn 2.6.14 | `--daemon` | **absent** -- it forks first and sets up after |
| hostapd 2.10 | `-B` | present |
| wpa_supplicant 2.10 | `-B` | present |

hostapd and wpa_supplicant complete their setup -- interface, control interface,
everything -- *before* the parent exits, so "nothing is listening" really does
mean "nothing is running" for those two, and the `stop` paths that treat it that
way are sound. openvpn is the odd one out, and the difference is worth knowing
before writing a fourth backend: `-B` is a promise about readiness in two of these
daemons and not in the third, and only the daemon can tell you which.

The relevant call sites now say so, so that nobody makes them symmetrical.

**Nothing notices a daemon that died on its own.** Unchanged from 0071, and this
decision makes it slightly sharper: netcfgd now has a pid for a tunnel, which is
the thing an observation would need to notice that the process is gone while the
document still asks for it. What it does *not* have is any pass that looks.
