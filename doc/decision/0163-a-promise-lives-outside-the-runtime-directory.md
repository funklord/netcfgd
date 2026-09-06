# 0163: a promise lives outside the runtime directory

Status: accepted
Date: 2026-09-06
Milestone: M8; closes the gap found while looking for a consumer of the
restart intent that [0134](0134-an-unannounced-stop-holds.md) left open

Qualifies [0139](0139-three-kinds-of-state-and-one-that-must-not-survive.md),
which classified the commit-confirm window correctly and did not follow the
classification through to where the file is kept.

## Context

`RuntimeDirectory=netcfgd` with `RuntimeDirectoryPreserve=restart` keeps
`/run/netcfgd` across `systemctl restart` and deletes it on a real stop. That
was chosen for the ownership record ([0135](0135-the-kernel-holds-the-ownership-record.md))
and is right for it.

The commit-confirm window and the document it reverts to were in that
directory.

## What was measured

Two runs in a `unshare -rn` namespace against a freshly built daemon, arming a
300-second window over a first apply, killing the daemon with `kill -9`, and
starting an ordinary daemon -- no `--no-apply-on-start`, because that is what
an init starts. The runs differ in one line: whether `/run/netcfgd` is removed
in between.

| | window found | the unconfirmed change |
|---|---|---|
| directory kept -- `systemctl restart` | yes | reverted |
| directory removed -- `systemctl stop`, `start` | **no** | **stands** |

The restart row is the positive control: it is what
`tests/live/confirm.sh` case 6 already proved, so the second row is a result
rather than a broken probe.

**So `systemctl restart netcfgd` and `systemctl stop netcfgd && systemctl
start netcfgd` differed in whether an operator's unconfirmed change was taken
back.** Two spellings of one intent with opposite outcomes, and the dangerous
one is what somebody types when they are being careful.

**And the answer differed by init**, which is worse than either behaviour:
systemd is the only one of the four that removes the directory. OpenRC's
`start_pre` runs `checkpath --directory`, procd's `start_service` runs
`mkdir -p`, and sysvinit removes only the pid file -- read in full rather than
grepped. The same operator action reverted on OpenWrt and did not on Debian.

## Why this consumer and no other

Everything else in `/run/netcfgd` that matters has been given a way to be
rebuilt from the world:

- 0002 and 0135: an address or a route carries netcfgd's protocol tag in the
  kernel, and is recognised with no record at all.
- [0136](0136-a-link-carries-its-own-mark.md): a link carries its own mark.
- [0140](0140-a-handle-must-be-recoverable-from-the-process.md): a
  backend is found by scanning `/proc` for the marker in its own `argv`.

All three work for one reason: **the state is a claim about an object that
still exists, so the object can be asked.**

0139 already named the window a different kind -- *a promise that was never
kept* -- and drew the boot-scoping consequence from it. What it did not draw
is the placement consequence, and it is the same sentence one step further:
**a promise has nothing in the world to rebuild it from.** What it asserts is
that somebody applied a change and did *not* come back. Nothing holds a copy
of an absence. So it is the one kind of state in that directory for which
losing the file is losing the thing itself, and the only one with no fallback.

That also makes 0139's own reasoning inconsistent rather than merely
incomplete. It declines to boot-scope the window because boot-scoping "would
remove the protection exactly where the outage was worst" -- and a stop and a
start are strictly *less* disruptive than the reboot it was arguing about,
while removing the protection just as completely.

## Decision

**The window and the last-good document move to a sibling of the runtime
directory**, composed by `netcfgd_host::confirm::dir`: the run directory's
final component with `-confirm` appended, so `/run/netcfgd` gives
`/run/netcfgd-confirm`. A run directory with no parent and no final component
gets a subdirectory instead, which cannot escape upwards.

Deriving it from the run directory rather than hard-coding `/run` is what
keeps `NCFG_RUN_DIR` working, and every test gets the sibling for free.

**It is still under `/run`.** This is not persistence. Writing it to
`/var/lib` would survive a reboot and would also make netcfgd write outside
`/run` on a read-only root, which `doc/read-only-root.md` is explicit about
not doing. 0135 rejected `StateDirectory` for the ownership record on the
separate ground that surviving a reboot is *wrong* for a claim about objects;
that ground does not apply here, and the read-only-root one does.

**The location lives in one function.** All nineteen call sites pass the run
directory and none chooses, so a per-call-site parameter would be bookkeeping
without a decision.

`ProtectSystem=full` leaves `/run` writable, so no new `ReadWritePaths=` is
needed, and `write_atomically` already creates the parent directory on the
first write -- so no init script has to make it, and the three that are not
systemd need no change at all.

## Consequences

- `systemctl stop` and `systemctl start` now revert an unconfirmed change, as
  `systemctl restart` already did, and the four init systems agree.
- `/run/netcfgd-confirm` appears beside `/run/netcfgd`. An operator looking
  for the window has one more place to look, which is the cost.
- **The natural way to reintroduce the fault is one line in the unit**:
  adding `RuntimeDirectory=netcfgd-confirm`, which is what somebody does on
  noticing a second directory. `tests/live/killmode.sh` refuses it, and also
  refuses a rename in Rust that would leave that guard pointing at a path
  nobody writes -- a guard over the wrong name is green and guards nothing.
  Both were made to fail before being recorded here.
- `tests/live/confirm.sh` gained case 6a, whose only difference from case 6
  is removing what a real stop removes. Its `start_daemon` now clears both
  directories, or a case would revert at startup for the previous case's
  reason.

## Alternatives considered

**`RuntimeDirectoryPreserve=yes`.** One line, and it changes the lifetime of
everything else in the directory. The backend records whose removal
sections 10.13 and 10.26 of `project.md` are written about would then survive
a real stop, which is a change in both directions and belongs to those
findings rather than to this one. It also only fixes systemd.

**Tell netcfgd why it is being stopped**, the open half of the 2026-08-25
restart requirement. That is the better long-term answer and this fault is its
first concrete consumer, but it is a design that does not exist yet, and the
window is losable today.

**Boot-scope nothing and persist to `StateDirectory`.** Rejected above: it
buys reboot survival that nothing here asked for, and pays in flash writes on
exactly the devices `doc/read-only-root.md` is written for.

**Leave it and document the sequence.** Rejected. The behaviour differed by
init system, which makes it a correctness property rather than a caveat -- and
a caveat about the difference between `restart` and `stop; start` is one
nobody reads at the moment they need it.
