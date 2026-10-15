# 0272: bluetooth is observed and not driven

Status: accepted
Date: 2026-10-15
Milestone: M10; the port's remaining scope

Decided by the copyright holder, from the costing in project.md 10.484. Settles
scope rather than deferring it: the `bluetooth` block stays in the language,
netcfgd keeps observing adapters, and nothing pairs a device, connects one, or
brings a `pan` link up.

## What this decides

**netcfgd reports Bluetooth adapters and leaves the radio alone.**
`ncfg_observe_bluetooth` lists `/sys/class/bluetooth`, names each adapter and
resolves its rfkill switch; `tests/live/bluetooth.sh` checks that against a
virtual controller made through `/dev/vhci`. That is the whole of netcfgd's
part, now and not provisionally.

**The block is not a request.** A `bluetooth` device block labels an adapter
fact with a handle the operator chose. `plan/build.c` warns that nothing acts
on it, and the warning says *by decision rather than for want of a pass* --
which is the change this record makes, because the arm had been in
`ncfg_plan_warn_unbuilt`, whose sentence ends "the block is kept so a
configuration written now still means this when the code arrives". No code is
arriving, so that was a debt nobody owed.

**`warn_unported`'s body no longer calls `warn_unbuilt` at all.** 0263 requires
an arm to leave that register in the same commit as the pass that lands, and
this was its last one -- left by a decision instead of by a pass, which is the
other way an entry can go and had not happened before.

The helper itself lives on and is not dead: the wifi and offload passes call it
for blocks they own, including four halves of a `network` block, and those are
genuine unbuilt work. So what is empty is the list in `plan/build.c`, not the
tree's stock of unbuilt things, and this record claims only the first.

## Why, and what it costs

**Pairing is not netcfgd's to own, and `document.h` said so before this.** The
block has always declined to carry pairing state, because whether a device is
paired is a fact about the adapter's key store, established interactively, and
recording it would be a second source of truth. This record carries that to its
conclusion: consent is the part of pairing that matters and a daemon
reconciling unattended has nobody to ask, so the half netcfgd could automate is
the half it has no business owning.

**The alternatives were priced and are in 10.484.** Removing the block breaks
configurations that use it for no gain, since the adapter facts are real.
Connecting an already-paired device through `org.bluez` would be the first
D-Bus dependency in the C core -- a dependency decision reaching the build, the
packaging and every machine the daemon runs on -- and would need `bluetoothd`
running, a second daemon netcfgd does not supervise. Driving `bluetoothctl`
instead adds no dependency and buys an interface that is a REPL written for
people, whose output is not a contract. Pairing and `pan` are larger again and
contradict the paragraph above.

**What it costs to reverse.** Almost nothing, which is why it was the
recommendation. Nothing is removed, no dependency is taken, no test rig is
built, and the language is unchanged. A later decision to connect a paired
device starts from the same block and the same observation, and would supersede
this record rather than undo work.

## What this does not decide

Whether netcfgd should ever connect a paired device. If that is taken up, the
costing in 10.484 stands and the cheaper half of it -- driving a program rather
than taking a D-Bus dependency -- inherits this record's reasoning instead of
contradicting it. It would also need a guest with bluez installed, because
`bluetoothd` is absent here and `bluetooth.sh`'s rig cannot reach pairing.
