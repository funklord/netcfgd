# 0150: a SIM source is chosen the way an uplink is

Status: accepted
Date: 2026-08-31
Milestone: M9; LTE, generalised from one board's bringup

The holder asked whether a component that selects between two SIM sources
belongs in netcfgd. It does, apart from the part that pokes hardware.

## What the case was

A board with two SIM sources -- a socket and an eUICC -- and a mux that gives
the modem one at a time. Nothing in either device tree drives the select line.
The working solution there drives a GPIO, resets the modem, waits for
registration, and falls back to the other source when the chosen one cannot
register.

**The findings are knowledge and the code is somebody else's**, which is the
holder's ruling and the line this record follows: what transfers is what modems
do, not an artefact.

## Why the policy belongs here

**That component had to reinvent constraint 1 to be correct.** It records that
its configured preference "is the operator's intent and is never rewritten by
the script", because "a transient failure must not quietly redefine what was
asked for". That is netcfgd's first constraint, arrived at independently by
somebody solving one board. When a component has to rebuild an architecture in
order to work, the logic belongs in the thing that already has it.

Three more things line up the same way:

- **Try a source, see whether it works, fall back** is the plan and reconcile
  loop with [0119](0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md)'s
  probe. netcfgd has both already.
- **"The source that worked" is `/run`,** derived and disposable and rebuilt by
  observing -- not `/data`, which is where that component had to keep it
  because nothing else was holding observed state.
- **Registration is observable without `ModemManager`.** That component polls
  `mmcli` and therefore depends on it. netcfgd reads the link and the interface
  report, so the dependency disappears rather than being carried.

## Why the GPIO does not

Driving a select line is board enablement. netcfgd speaks netlink and
supervises backends; it has no GPIO anywhere, and one board's mux is not a
reason for it to grow one.

[0011](0011-preup-runs-before-the-link-is-up.md) already documents the answer,
and names this case: `pre_up` exists so something can happen before the
interface is configured -- "loading firmware, **unlocking a modem**, setting a
sysctl the driver reads at up time. Those need the interface down."
[0043](0043-mbim-is-ours-and-the-quirks-are-a-table.md) reached the same place
for FCC unlock, for the reason that governs both: unlocking somebody's modem
without being asked is not a networking daemon's business, and neither is
switching which SIM they are billed on.

So the split is: **netcfgd says which source is wanted and what to do when it
will not register; a hook makes the hardware do it.**

## Where this does not fit the existing model, said rather than papered over

`preference` chooses among *interfaces*, and two SIM sources back the *same*
interface. This is therefore new vocabulary rather than the existing mechanism
wearing a hat, and small as it is, it is a language change:

    device wwan0 {
        modem {
            sim = ["esim", "socket"]
            apn = "im.cxn"
        }
    }

`sim` is an ordered list because "which one do you want, and what next" is one
statement and splitting it into a preference and a fallback would let them
disagree.

## The APN is configuration, and that is measured rather than assumed

**It cannot be discovered.** Not from the card: on the board that produced this,
`EF_ACL` exists and is entirely `FF`, and `EF_UST` says the APN Control List
service is not activated -- with `EF_UST` reading successfully through the same
channel, which is what makes the empty `EF_ACL` a real negative rather than a
failed probe. Not from an offline database either: the Linux equivalent of a
phone's carrier table carries public APNs only, and a private APN is by
definition not in one.

**And an invalid APN is silently overridden.** Asking for one the subscription
does not carry gets the network's default rather than an error, and that
default may be nearly useless -- which is the next record's problem and the
reason a probe is not optional here.

So the APN is provisioning data, it belongs in the document beside the source
preference, and netcfgd must not try to be clever about it.
