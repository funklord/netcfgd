# 0199: the switch is news where somebody is looking

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi power and rfkill audit

## What was already right

netcfgd's rfkill handling is careful and mostly finished. `/dev/rfkill` is read
with the record-growth hazard handled explicitly -- the kernel may append
`hard_block_reasons`, and one read is one record, which a reassembly buffer got
wrong once and the comment now records. The observation reads the **phy's own**
switch rather than the platform button beside it (0062). `warn_blocked_radios`
warns in a plan, with a different remedy per switch type. `explain` says it too.
And the device is opened read-only, on purpose, so "netcfgd does not overrule a
switch somebody flipped" is a property of the code rather than of the intent.

`powersave`, `regdom` and `scan_randomization` are compiled, kept, and reported
as understood-and-not-acted-on. That is honest and is not a defect.

## What was wrong: nobody reads a plan when the wifi is off

`warn_blocked_radios` carries this comment:

> a blocked radio looks exactly like a network that will not associate. The
> supplicant starts, the scan comes back empty, nothing fails, and the operator
> has no way to tell that the hardware is off -- which on a laptop is one
> keystroke away at all times.

The diagnosis is exact and the fix went into the plan. **The two commands a
person actually runs when the wifi is not working are `ncfg wifi status` and
`ncfg wifi scan`**, and neither of them looked at the switch. Status reported
`SCANNING`; the scan reported "no access points in range" -- which is precisely
the output the comment says is indistinguishable from a radio that is off.

So both report it now. Status names the switch above the association, because a
switched-off radio explains everything below it and a line printed underneath
is one the reader has already scrolled past. The scan does not send `SCAN` at
all on a blocked radio: there is nothing to scan with, the cached results are
still returned and labelled, and it saves waiting out the full patience (0194)
for an event that is not coming.

Without that short circuit the scan does now say *something* -- 0194's
machinery reports `the supplicant could not scan (ret=-100)`, which is true, and
is a translation of ENETDOWN rather than the fact that somebody pressed a
button.

## One wording, three callers

`ObservedRfkill::remedy()` lives on the model because the sentence is needed in
three places and a wording that drifts between them is one that contradicts
itself. **The two blocks have different answers and saying the wrong one wastes
somebody's evening**: `rfkill unblock wifi` clears a soft block and does nothing
whatever to a slider. The planner keeps its own phrasing, which is built into a
longer sentence about netcfgd configuring the interface anyway.

## The other silence

```rust
let Ok(mut rfkill) = netcfgd_sys::rfkill::Rfkill::open(&device) else {
    return;
};
...
Ok(None) | Err(_) => return,
```

A machine with no radio has no `/dev/rfkill`, and returning there is right.
Every other failure is not: the device exists and netcfgd cannot read it, which
costs kill-switch detection for the life of the daemon and said nothing at all.
From that point a flipped switch is never noticed, and the machine looks like a
wireless interface that silently will not associate -- the same misdiagnosis
this decision is otherwise about, arrived at from the other side.

`NotFound` still returns quietly. Anything else is a warning naming the device
and what is lost, and so is the stream ending or failing later.

## Verification

Six checks in `tests/live/wifi_trouble.sh`, staged through `NCFG_SYS_ROOT`
rather than by blocking the real radio, which would take the network off the
machine running the test.

The control is asserted first and from the other side: an unblocked radio says
nothing about a switch, so the rest cannot pass on a daemon that prints the
line unconditionally. Then soft -- said, and naming the command -- then hard,
which must **not** be offered the software remedy and must name the button.

Seven seconds between changing `/sys` and asking, because a file changing there
produces no netlink event and no rfkill record, so what picks it up is the
reconcile loop's five-second backstop. Two seconds passed the soft case by luck
of where in that cycle it landed and failed the hard one, which is worth
knowing: the first number was not wrong by much, it was wrong by *sometimes*.

Three sabotages, each landing on a different check: returning `None` for
`blocked` takes the three status assertions red, removing the scan's short
circuit takes the scan one, and collapsing the hard/soft distinction takes the
two hard-block ones.
