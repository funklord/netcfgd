# 0062: A blocked radio is reported, and not unblocked

Status: accepted
Date: 2026-08-03
Milestone: the laptop list, after [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md)

## Context

A radio that is switched off looks exactly like a network that will not
associate. The supplicant starts, the scan comes back empty, nothing fails, and
`ncfg explain` had nothing to say about it. On a laptop the switch is one keystroke
away at all times, which makes this the most likely wifi problem netcfgd could not
describe.

## What the kernel exposes

`/sys/class/rfkill/rfkill<N>/` per switch, with `name`, `type`, `soft` and `hard`.
An interface's switch is found through its phy:
`/sys/class/net/<iface>/phy80211/name` gives the phy, and the rfkill entry whose
`name` matches is the one.

**A laptop has more than one `wlan` switch.** Measured on the Dell this was
written on:

```
rfkill0  name=dell-wifi  type=wlan   soft=0 hard=0
rfkill1  name=dell-bluetooth type=bluetooth
rfkill2  name=hci0       type=bluetooth
rfkill3  name=phy0       type=wlan   soft=0 hard=0
```

`dell-wifi` is the platform button's and `phy0` is the card's. netcfgd reads
**the phy's own**, because that is the switch the driver obeys, and because taking
the first `wlan` entry would report the button's state for a card it may not
govern -- on a machine with two cards, somebody else's radio.

**What was not measured: whether blocking the platform switch propagates to the
phy.** Finding out means switching off the wifi of the machine running the test,
which on the machine this was written on is the link the work is being done over.
It is not something a test may do to somebody's laptop, and it is not something to
guess at either -- so it is written down here as unknown, to be settled in a
privileged container with `mac80211_hwsim`, where the radio is nobody's.

The practical answer does not depend on it: if the radio is off, the phy's own
`soft` or `hard` says so, whatever set it.

## Decision

**Observe it, report it, and never change it.**

- `ObservedLink::rfkill` carries the switch's name and both flags. `None` means
  netcfgd could not tell -- not a radio, no `CONFIG_RFKILL`, no switch registered,
  or an entry whose flags would not read. Nothing is planned on a `None`.
- `ncfg status` prints a line only when the radio is off, because a listing is
  read to find out why something is broken. `ncfg explain interface` reports it
  either way, and *before* the addresses -- a blocked radio has none, so a fact
  after them is a fact nobody reached.
- A plan names the interface, the switch and **the remedy for the kind of block**:
  a soft block is software and `rfkill unblock wifi` clears it; a hard block is a
  physical switch and nothing in software will move it. Two messages because two
  different things have to happen.
- Nothing is refused. The supplicant is still started on a blocked radio: it costs
  nothing, and it is right the moment the switch comes back.

## Why netcfgd will not unblock a radio

It could. Clearing a soft block is a write of a `struct rfkill_event` to
`/dev/rfkill` -- no ioctl, no `unsafe`, and the device is group `netdev` on Debian.
The reason not to is not difficulty:

**A soft block is somebody's deliberate act.** It is the aeroplane switch, the
laptop's function key, or a desktop's radio toggle -- and on this machine those go
through the platform driver and the desktop, not through netcfgd. A daemon that
reads "wifi off" as a state to be corrected is a daemon that turns the radio back
on in a cabin at 30,000 feet because a config file mentions a network. That is the
same discipline as everything else here: netcfgd does not undo what it did not do
([`Ownership::may_remove`](../../crates/netcfgd-model/src/observed.rs) is the same
rule for addresses and routes).

**And the config cannot express it**, which is the honest test of whether it
belongs: `device X { wifi { } }` says how to use a radio, not whether the radio
should be on. A key for that would be the operator saying "override the switch",
which is a thing a person does at a keyboard, not a thing a file says once and
forever.

So the remedy is `rfkill unblock wifi`, and netcfgd's job is to make sure nobody
spends an afternoon before finding that out. If an explicit `ncfg wifi unblock`
ever lands it is a live command like `ncfg wifi connect` -- an operator asking,
once -- and not a document key.

## Consequences

- One observed field and one struct; the witness moved. A minor addition, and the
  first one read from `/sys`.
- `NCFG_SYS_ROOT` joins `NCFG_PROC_ROOT`, so the mapping is testable at a desk. A
  tree under a temporary directory is faking a *file layout*, not a radio, which
  is the line section 9 draws around `fake_supplicant.py`.
- `tests/live/rfkill.sh` reads the real thing, read-only, and skips its first half
  on a machine with no card. It is the first test in this project to touch real
  wifi hardware at all, which after "nobody has run this against a real radio" is
  a small thing worth having: netcfgd's answer agrees with a real driver's switch
  under a real phy name.
- The same script's second half fabricates a tree so that the *blocked* rendering
  and both warnings are exercised on every machine, including the ones with no
  radio. Without it the interesting half only ran on a laptop with its wifi
  switched off, which is nobody's build machine.
- Two flaws in this work were found by breaking it, and both were mine rather than
  the kernel's: `read_dir` order is the filesystem's, so the unit test proving the
  search picks the phy passed with the search deleted; and the reported switch name
  came from the phy variable rather than from the entry it describes, so it could
  not disagree with a wrong answer. Sorted iteration and the entry's own name fixed
  both, and the live test against the real Dell now fails when the search is
  broken.
- `+12 KB` installed, with a line in `size-budget.txt`.

## What is still missing on a laptop

The switch is now visible; the *event* is not. netcfgd learns about a block when
it next observes, which the daemon does on netlink events and a periodic
backstop -- and rfkill has its own event stream on `/dev/rfkill` that nothing
reads. So a block is noticed within seconds rather than immediately, and that is
the next piece if this turns out to matter.
