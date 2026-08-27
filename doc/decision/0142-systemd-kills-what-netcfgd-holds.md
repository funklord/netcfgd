# 0142: systemd kills what netcfgd holds

Status: accepted
Date: 2026-08-26
Milestone: M8

Corrects [0134](0134-an-unannounced-stop-holds.md), which is true of netcfgd
and false of a machine running it under the packaged unit.

## What 0134 claimed, and how it was argued

> **An unannounced stop holds.** netcfgd leaves the network exactly as it is,
> and the copy that starts next adopts what it finds.

The evidence offered was netcfgd's own source: no `SIGTERM` teardown in the
daemon, no `ExecStop` in the unit, so "killing netcfgd today leaves every link,
address, route and backend exactly where it was".

**Both facts are true and the conclusion does not follow.** It reasons from
what netcfgd does to what happens on the machine, and skips the thing in
between. `packaging/systemd/netcfgd.service` set no `KillMode=` in 122 lines,
and systemd's default is `control-group`: on stop, **every process in the
unit's cgroup is killed**, including the `wpa_supplicant` and `dhcpcd` netcfgd
started. `Restart=on-failure` means the same reaping happens on a crash, which
is the case 0134 calls decisive.

So the VPN-over-wifi that 0134 exists to protect was dropped by `systemctl
stop netcfgd` for as long as that record has stood.

## Why the tests did not catch it

`tests/live/orphan.sh` and `tests/live/revive.sh` run netcfgd as a plain child
of the script, inside `unshare`, where there is no systemd and no cgroup. They
observe that **the daemon** tears nothing down. They cannot observe what the
**init** does, and nothing said so.

**A true statement about netcfgd stood in for a false one about the machine.**
That is `evidence.md`'s vacuous pass wearing an unfamiliar hat: the checks were
real, they discriminated, and they were measuring one layer below the claim.

It was found by reading a live orphan's cgroup. The orphaned `dhcpcd` on the
machine that produced this whole investigation sits in
`/user.slice/user-1000.slice/session-c1.scope` -- **a shell session**, not a
service -- because it was started by a diagnostic script running netcfgd in the
foreground. Under the unit it would have been reaped. The orphans that
motivated 0140 were an artefact of how they were produced, and the real
systemd behaviour is the opposite of what 0134 describes.

## Decision

**The unit sets `KillMode=process`.**

**It said `control-group` first, and the sequence is the decision.** That was
the behaviour the machine already had, made explicit rather than inherited,
and it was kept while netcfgd could still not re-adopt every backend --
because holding what cannot be recovered is worse than not holding it. Once
adoption reached all of them (0140 for the argv-marked backends, 0143 for
dhcpcd, and the generic branch in `start_backend` that covers openvpn, radvd
and hostapd), the reason to stay was gone and the value flipped by the
copyright holder's instruction.

    Set: KillMode=process

That line is the one `tests/live/killmode.sh` reads. It exists because this
record necessarily *discusses* the value it does not set -- `KillMode=process`
appears twice below -- so a check that merely looked for the unit's value
somewhere in the prose would pass whichever value the unit carried. One
declarative line, matched exactly, is what makes the agreement checkable rather
than plausible.

That is the behaviour the machine already had. What changes is that it is
*chosen*, visible beside a comment saying why, and asserted by
`tests/live/killmode.sh` so it cannot silently go absent again.

**`KillMode=process` kills only the main process and leaves the rest**, which
is exactly "an unannounced stop holds". The gate on shipping it was whether
netcfgd could re-adopt what it leaves running, and every backend now answers:

| backend | how it is recovered |
|---|---|
| `wpa_supplicant` | the `-P` path in its own `argv` (0140) |
| `udhcpc` | the `-p` path, the same way |
| `openvpn`, `radvd`, `hostapd` | the marker `backend_pid_file` already returns -- a management socket, a generated config, a pid file -- through the generic branch in `start_backend` |
| `dhcpcd` | **asked**, over its control socket: `setproctitle` destroys its argv *and* its environment block, so it has no marker to find (0143) |

**Holding what cannot be re-adopted would have been worse than not holding
it.** A dhcpcd left running is one netcfgd can neither identify nor stop,
renewing against whatever manager comes next -- measured at one lease a minute
for two hours and thirteen addresses consumed. Killing it on stop costs an
outage; leaving it would have cost an outage *and* an unmanageable process.

**What the flip buys**: `systemctl stop netcfgd`, and therefore every package
upgrade, stops taking the network down. That is the whole of 0134, and it was
false for as long as this line was absent.

**The one marker deliberately not used for this.** `backend_pid_file` gives the
two DHCP clients `iface` as their marker and calls it "the weakest marker
netcfgd uses". `eth0` is a short string an unrelated command line could
contain, so scanning `/proc` for it would reach somebody else's process. The
generic branch takes absolute paths only -- excluded by shape rather than by a
list of names, so a backend added later is refused by default rather than
included by oversight.

## What the test can and cannot do

`tests/live/killmode.sh` checks the **declaration**, not the behaviour. The
suite runs unprivileged, and a test that needed root to start a unit would skip
on every machine that runs `make live` -- a check that never runs is worse than
none, because it reads as coverage.

That is still worth having, because **the defect was an absent setting**. A
unit with no `KillMode=` reads as though nobody considered it; one that names a
value has had the decision made. The test fails if the line goes away, and it
fails if the record and the unit name different values, because a reader who
finds them disagreeing cannot tell which is stale.

**The behavioural claim remains untested, and is marked as such here rather
than left to be assumed.** Verifying it needs root and a real systemd, which is
`make live`'s standing limitation and not this record's to solve.

## Consequences

**Five places cite 0134** -- 0135, 0138, 0139, 0140 and four passages in
`project.md` -- and every one of them inherits its frame. None of their
conclusions changes: they are about what netcfgd does with state it finds, and
that reasoning is untouched. What changes is the premise that the state is
still there to find under systemd.

**0140's motivation is narrower than it reads.** Its orphan was produced by a
foreground run. The defect it fixes is real -- losing the handle to a process
that outlives the daemon -- and it is exactly what `KillMode=process` would
make routine. It was fixed before the thing that makes it common was
identified, which is the right order by luck rather than judgement.

## Alternatives considered

**Set `KillMode=process` now and accept the orphans.** Rejected above: it
converts a stop into an unmanageable process on every machine using dhcpcd.

**Leave `KillMode` absent and correct 0134 to say backends are killed.**
Rejected. It documents the accident rather than deciding, and it leaves the
next reader to discover systemd's default for themselves -- which is how this
went unnoticed.

**Add an `ExecStop` that stops the backends deliberately.** Rejected: that is
teardown by another name, and 0134's argument against it stands -- it takes the
network down on every upgrade, which is the outage the whole record exists to
prevent.
