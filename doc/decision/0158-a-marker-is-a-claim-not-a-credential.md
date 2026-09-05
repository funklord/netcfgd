# 0158: a marker is a claim, not a credential

Status: accepted
Date: 2026-09-05
Milestone: found by an exhaustive sweep of the core networking paths

## Context

[0140](0140-a-handle-must-be-recoverable-from-the-process.md) gave netcfgd a way to
recognise a backend it had started but lost the record of. `RuntimeDirectory=`
means systemd deletes `/run/netcfgd` when netcfgd stops, while the backends it
deliberately does not stop ([0134](0134-an-unannounced-stop-holds.md)) keep
running -- so the pid file is gone and the process is not. What survives is the
process image, and every backend netcfgd starts carries an absolute path
netcfgd composed in its own `argv`: a management socket, a generated config, a
pid file given with `-P`. `pid_by_marker` scans `/proc` for that whole argument
and adopts what it finds.

The scan was made defensible by narrowness. `netcfgd-sys`'s module header
forbids finding a process by *name*, because an operator's own
`wpa_supplicant` would be reached along with netcfgd's, and `pid_by_marker`'s
own comment said the exception was safe because "no other manager's command
line can carry it".

**That is true of managers and false of everybody else.** The marker is
composed from public parts -- the run directory, the backend, the interface --
so it is guessable, and nothing stops a local user typing it into their own
command line. Measured, as an ordinary user, against a netcfgd running as root:

```text
$ sh -c 'sleep 300' /run/netcfgd/openvpn/vpn0.sock &
$ ncfg apply
netcfgd: adopted the OpenVpn backend already running on vpn0 (pid 20114)
```

netcfgd recorded `backend.start` as done, started no openvpn, and reported the
tunnel up. The interface carries no traffic and nothing says so. netcfgd will
later `SIGTERM` the recorded pid, so the impostor also collects the stop.

Adoption is gated on `backend_is_reachable`, which answers `true` for every
kind but the supplicant, so it does not screen this.

## Decision

**A marker says which backend a process claims to be. It says nothing about
who started it, and the second question is now asked separately.**

`pid_of` and `pid_by_marker` both read `/proc/<pid>/status` and accept a
candidate only when its **real** uid is root or the uid of whoever is asking.
An unprivileged user cannot produce a root process, so the forgery is refused
where it matters; adoption then falls through to starting the real backend,
which is the safe direction.

**The real uid, and the obvious instrument reports the wrong one.**
`/proc/<pid>` is owned by the *effective* uid and the kernel reports that
directory as root's for a setuid binary, so a `stat` would answer "root" for
exactly the process this exists to refuse. Measured on this machine:

```text
$ sudo -k -S -p '' /run/netcfgd/openvpn/vpn0.sock < pipe &
stat -c %u /proc/<pid>          ->  0
grep ^Uid: /proc/<pid>/status   ->  Uid:  1000  0  0  0
```

sudo will refuse the command, but the attacker chooses how long it sits at the
password prompt and adoption needs to happen once. A guard built on `stat`
would have been a new vacuous check rather than a fix.

**"Root, or whoever is asking" rather than "root".** The second half is not
slack. `ncfg diff` and `ncfg status` observe locally and may be run by anybody:
a rule of "root only" would be read by an unprivileged observer as every
backend having stopped, and it would then plan to start them all. A rule of
"mine only" would refuse a root backend for the same reader. netcfgd applying
is root, so the pair collapses to "root" in the case that matters, and it is
also what lets the tests run as an ordinary user against their own children.

## Alternatives rejected

- **An unguessable marker.** There is nowhere to keep it. The reason adoption
  exists is that systemd deleted the run directory, which is the only place a
  token netcfgd generated could have lived.
- **A reachability probe per kind.** `backend_is_reachable` has one for the
  supplicant and could grow four more. It is worth having and it is not this:
  a probe says the process works, not that it is netcfgd's, and an impostor
  that answers would pass.
- **Matching the executable.** `/proc/<pid>/exe` would also refuse a root
  `cat` that happens to carry the path, which the uid rule does not. It needs
  a name per kind, and the names live at five spawn sites in four crates --
  a second hand-maintained list that must agree with the first, which is a
  failure this workspace has already paid for.

## Consequences

- A root process that carries a marker for some unrelated reason is still
  adopted. That is a smaller hole than the one closed -- it needs root, and
  netcfgd is root -- and it is what the executable check above would have
  addressed at the price of a list. Recorded rather than closed.
- The three adoption messages now say the privilege was checked as well as the
  marker, because the message is where the trust decision is stated.
- `tests/live/dhcpcd_orphan.sh` greps the adoption message by prefix and is
  unaffected.
