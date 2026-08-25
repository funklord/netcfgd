# 0138: a record outliving its boot is wrong, not stale

Status: accepted
Date: 2026-08-25
Milestone: M8; the reboot half of the restart requirement

The last of the four that started with
[0134](0134-an-unannounced-stop-holds.md), and the one those records kept
asserting was safe without ever checking it.

## Context

0135, 0136 and 0137 each closed with the same sentence in some form:

> After a reboot `/run` is empty **and so is the kernel state**. Both sides are
> cleared together, consistently, and the machine is a cold start with nothing
> to adopt.

**That is an assumption about a filesystem, stated as a property of the
design.** It holds because `/run` is conventionally a tmpfs, and it is true on
every machine anybody here has measured. It is not something netcfgd checks,
and there are ordinary ways for it to be false:

- `/run` is not required to be a tmpfs. It usually is; usually is not always,
  and the projects netcfgd targets include ones where the init system is not
  systemd and the layout is somebody's own.
- **`NCFG_RUN_DIR` points the whole thing wherever the caller says.** It exists
  for tests and for containers, and nothing stops it naming a persistent
  directory.

## What a surviving record actually costs

**Not staleness.** A record from a previous boot names objects that no longer
exist, and a claim about something that is gone is harmless.

The danger is the opposite: **parts of it can match something new.** The record
says netcfgd owns `10.0.0.5/24` on `eth0`. The machine reboots; an initramfs,
a DHCP client or an operator puts that address there. netcfgd now believes it
installed an address it did not, and may remove it to satisfy a config that
never asked for it.

That is the hazard 0135 named when it rejected persisting the record in
`StateDirectory`, and the same reasoning applies to a `/run` that merely
*happens* to persist -- the record does not know which it is.

**For most objects this is already moot**, and that is worth saying plainly
rather than leaving the fix looking bigger than it is. Addresses, routes, links
and `tc` objects all carry marks in the kernel now (0002, 0136, 0137) and none
of them consults the record first.

**The sysctls are why this record exists.** They have no mark and no way to get
one, so `forwarding`, `privacy` and `accept_ra` are the one place a surviving
record can still do harm: netcfgd reverting a `forwarding` that `sysctl.d` set
at boot, on the strength of having set one itself before the machine restarted.

## Decision

**`owned.json` records the boot it was written during, and a record naming a
different boot is discarded.**

`/proc/sys/kernel/random/boot_id` -- a UUID the kernel generates once per boot.
Read rather than derived from uptime, because uptime is a moving number and
this needs an identity: two runs of netcfgd during one boot must agree, and the
same run either side of a reboot must not.

**Stamped by `write_owned` rather than by its callers.** A record that forgot
to say which boot it belongs to is one `read_owned` cannot judge, and it would
fail open -- so no caller is given the chance to forget.

**Two unknowns both mean "do not judge", never "discard":**

- **An empty field** is a file written by a netcfgd that predates this. Throwing
  it away would lose ownership on upgrade, for a reason unrelated to a reboot.
- **An unreadable `boot_id`** is a kernel that does not expose one. Discarding
  because the check could not run is the mirror of a vacuous pass, and it
  fails in the expensive direction.

**And it says so when it discards**, because what is lost is invisible
otherwise -- the next symptom is a sysctl netcfgd declines to revert, hours
later and somewhere else.

## Consequences

**A property that was assumed is now checked.** The three records before this
one were right about the behaviour and were reasoning from a filesystem
convention. If `/run` persists, netcfgd now notices instead of acting on a
claim that no longer applies to anything.

**`NCFG_RUN_DIR` stops being able to cause this**, which matters because it is
the one that can be pointed at a persistent directory by an ordinary mistake.

**Discarding is holding**, per 0134: a netcfgd that owns nothing removes
nothing. The failure mode of the check firing wrongly is a sysctl left set,
which is the direction this whole sequence chose deliberately.

**The record grew a field, and old files still parse** -- `#[serde(default)]`,
and a test asserts an unstamped record is kept rather than discarded.

## How it is tested, since a reboot cannot be had inside a test

`tests/live/sysctl.sh` forges the boot id. That is not a shortcut around the
mechanism, it *is* the mechanism -- netcfgd compares the recorded id against
`/proc/sys/kernel/random/boot_id` and nothing else -- so a forged id exercises
the real path.

Both halves are asserted: a forged record is discarded and the sysctl held, and
**a record from this boot is still acted on**. Without the second, a netcfgd
that discarded every record would satisfy the first two checks. Verified by
breaking each: never discarding fails the two boot checks, always discarding
fails the other half and one of the checks that predates this record.

One precondition had to be established rather than assumed, and it is the kind
of thing that makes a test lie: netcfgd records having set a sysctl only when
setting it was an *action*, and it is not one where the value is already right.
A test that asks for `forwarding = true` on an interface where forwarding is
already on writes no record at all, and every check after it is measuring
nothing.

## Alternatives considered

**Require `/run` to be a tmpfs and check that at startup.** Rejected: netcfgd
does not get to make demands about a machine's filesystem layout, and the check
would fail on perfectly good systems while doing nothing about `NCFG_RUN_DIR`.

**Delete the record at startup unconditionally.** Rejected -- it throws away
the restart case that 0135 spent a decision closing, to fix the reboot case.
The two are distinguishable and should be distinguished.

**Use the record's mtime against the boot time.** Rejected: it is a comparison
of two clocks, and it goes wrong exactly where clocks do -- a machine with no
RTC, an NTP step, a filesystem restored from a backup. A boot id is an
identity, and identities do not need a clock to compare.

**Do nothing, since the marks cover everything that matters.** Tempting, and
nearly right: the marks do cover addresses, routes, links and `tc`. It leaves
the sysctls exposed to the one failure they can still have, and it leaves three
decision records asserting a filesystem property as though it were a design
one. The second reason is the better one -- an assumption written down as a
fact is how the next person inherits it without knowing it was ever a guess.
