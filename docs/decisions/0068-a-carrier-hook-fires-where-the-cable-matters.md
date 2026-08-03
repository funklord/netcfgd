# 0068: A carrier hook fires where the cable matters

Status: accepted
Date: 2026-08-03
Milestone: the phase a laptop notices, after [0064](0064-a-lease-is-an-address-netcfgd-did-not-install.md)

## Context

`on carrier { }` compiled, was materialised, was hashed, and never ran -- one of the
phases [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) found
inert and the one a laptop would notice, because nothing else reports a cable.
`pre_up` runs before there is one, `post_up` after the addressing, and neither fires
when somebody plugs one in or pulls it out.

## Decision

**It fires on a change, and where it goes in the plan depends on which way the change
went.** That asymmetry is the whole design, and it is the same reasoning `down`
needed ([0063](0063-the-down-hooks-run-before-the-interface-goes.md)):

- **Gained** -- after the interface's addressing actions, like `post_up`. A script
  that reacts to a cable by connecting somewhere needs the network to work, and
  before the addresses it does not.
- **Lost** -- early, at the interface's own gate. Teardown is the last thing in a
  plan, so at that point the routes and addresses are still there, which is what
  lets a script stop something that is using them.

`NCFG_REASON` is `up` or `down`. A script that has to ask the kernel which way it
went is a script racing the next change.

**The first observation fires it.** netcfgd has no record for an interface it has
never run one for, and rather than invent "no change" it tells the hook the current
state -- which is what `ifplugd -i` does, and is the honest reading: netcfgd has just
arrived and this is how things are. The alternative would need a record written by
something other than the hook, which means state written by an observation, which is
not a thing this design has.

## One memory for every event hook

0064 gave the `lease` hook a `/run` record so it would fire once per lease rather
than once per reconcile. `carrier` wants exactly the same thing with a different
value in it, and **a second customer arriving two commits later is the signal to
generalise rather than duplicate**:

```
lease_hooks: [{interface, address}]      →  hook_state: [{interface, phase, value}]
```

One list, keyed by interface and phase. `roam`, `portal` and `drift` -- the three
event phases still unfired -- get their memory for free, and there is one place where
"what was this hook last told" is decided. The op's field was renamed with it:
`address` became `value`, and the executor puts it in the variable the phase's own
vocabulary names -- `NCFG_ADDR` for a lease because the value is an address,
`NCFG_REASON` for a carrier because it is a word. Filling both on both phases would
tell a script to look somewhere its own phase never writes.

The record is written whether or not the script succeeded, for 0064's reason: a
failing event hook that kept the plan non-empty would be a plan that never converges.

## Consequences

- Six of the eleven phases fire. Five -- `up`, `pre_down`, `roam`, `portal`, `drift`
  -- are still recognised and still say so in the plan.
- The observed schema's `lease_hooks` becomes `hook_state` with a `phase` field. The
  witness moved, and it carries a sample of both phases so neither can go quiet.
- `+0 KB` measured, absorbed by the tolerance: the pass is thirty lines and the
  record it needed already existed.
- `tests/live/hooks.sh` drives a **real** carrier transition. A veth pair is the one
  device whose carrier can be made to come and go without hardware -- the near end
  has carrier exactly while the far end is up, which is a real `IFLA_CARRIER` change
  through the kernel and not a flag netcfgd set.

## Two gates that were blind, and what fixed them

Both are the same disease and both were caught by breaking the code on purpose.

**The dependency edge had no assertion.** The fixture checked that the hook came
*after* `addr.add` in the action list -- which emission order gives for free, so
deleting the `depends_on` edge changed nothing any test could see. A plan is a DAG
and a reader of `depends_on` must get the same answer as a reader of the list, so the
fixture now asserts the edge as well as the position.

**And the live test could not see the ordering at all.** It plugged the cable in on
an interface that already had its address from the previous apply, so the hook saw an
address whether it ran before or after the addressing. Taking the address away first
puts both in one plan, and the check has teeth: emitting the hook before the
addressing pass now fails it.
