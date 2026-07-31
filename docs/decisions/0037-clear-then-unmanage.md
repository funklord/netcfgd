# 0037: Clear, then unmanage

Status: accepted
Date: 2026-07-31
Milestone: settles the question 0035 left open

## Context

Decision 0035 made `managed = false` mean what the model always claimed, and
left one thing open. Walking away from a device strands whatever netcfgd put on
it, and three of those things hold credentials: a WireGuard private key loaded
in the kernel, a supplicant keeping the passphrases it was handed, a running
hostapd keeping its generated configuration under `/run`.

Walking away is right when handing an interface to another daemon. It is wrong
when the hardware is leaving your hands.

## Decision

**Two policies, one mechanism.**

```
device eth0 { managed = false }                        # leave: change nothing
device eth0 { managed = false; on_unmanage = "clear" } # clear, then leave
```

`on_unmanage` rather than `clear = true` because it is a policy, not an action.
It can sit in the configuration while the device is still managed, meaning "if
you ever stop, do this", and it leaves room for the values that will want to
exist later -- restoring from the factory layer, or running a hook.

`leave` is the default, so 0035's behaviour is unchanged for every existing
configuration.

## Clearing is a state, not a transition

This is the part that makes it fit netcfgd rather than fight it.

`on_unmanage = "clear"` does not mean "run these actions at the moment the flag
changes". It means **the desired state of this device is that netcfgd owns
nothing on it**. That is checkable, so there is no edge to detect, no record of
"have we cleared this yet", and nothing to get wrong when a daemon restarts
half way through.

The planner reaches the state and then stops. A second plan is empty because
there is nothing left carrying netcfgd's tag, which is the same reason any
converged plan is empty. Idempotent by construction rather than by care.

## Defined by ownership, which is what makes one rule enough

The question this started from was what a "standard clear configuration" would
have to say for it to apply to most devices. The answer is that it says
nothing: clearing is defined by *ownership*, not by content.

It removes addresses and routes carrying netcfgd's protocol tag (decision
0002), backends netcfgd started, and the links netcfgd created. It touches
nothing else, on any device, without a per-device baseline existing anywhere.
Whoever takes the device over keeps their own configuration -- verified against
a real kernel in `tests/live/unmanage.sh`, which puts a foreign address on a
device netcfgd did not create and watches it survive.

### The exception that is not one

A device netcfgd **created** is itself one of the things netcfgd owns, so
clearing removes it -- and everything living on it goes too, including a
foreign address somebody else added.

That was found by the live test rather than reasoned out: the first version
asserted that a foreign address survives clearing, put it on a dummy netcfgd
had created, and watched the whole link disappear. The check now uses a device
netcfgd did not create, which is what a physical NIC looks like to the
ownership rules, and asserts the link-deletion behaviour separately.

It is the right behaviour. Clearing undoes what netcfgd did, and creating the
device is the first thing it did. Handing a virtual device over intact is what
`leave` is for -- which is the clearest statement of why there are two policies
rather than one with a flag.

## Implementation, and the one sharp edge

Every teardown pass already knows how to remove what the document does not
want. So a device being cleared is decided about **as if its `interface` block
were not there**: `plan_teardown` filters the document once, and four passes
that have no interest in this policy never learn about it.

The sharp edge is decision 0035's choke point, which drops every action naming
an unmanaged interface. That would drop the clearing actions too. The exemption
is narrow on purpose: a clearing device is exempt **during the teardown passes
only**, because the forward passes must stay switched off. Planning an address
and removing it in the same plan is a loop, not a convergence.

## Schema

`Device` gains `on_unmanage`, so the document schema goes from 1.1 to **1.2 --
a minor bump**, which is what section 2 says adding a field is. Both witnesses
under `docs/schema/` moved by three lines between them, which is the freeze
machinery doing its job: the change is visible, small, and had to be blessed
deliberately.

Constraint 6 is satisfied without argument here: this is a local operator's
feature, wanted for handing hardware over, and no adapter asked for it.

## What is still open

The credential question is now answerable, not answered: an operator who wants
the keys gone sets `on_unmanage = "clear"`. Nothing yet *warns* somebody who
unmanages a device holding credentials without setting it -- the plan says what
walking away leaves behind, but only in prose, and only if they read it.

The shape that would fit is the one `--allow-disruption` already uses: notice
that a plan is about to strand credentials, refuse, and make the operator say
which they meant. That belongs with whatever else grows a refusal, and a prompt
belongs to whichever client is in front of a person -- the core has no UI and
must not grow one to be safe.
