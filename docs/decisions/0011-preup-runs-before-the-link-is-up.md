# 0011: pre_up runs before the link is up, and netifrc's preup does not

Status: accepted
Date: 2026-07-29
Milestone: ordering holds from M1; the converter warning lands with M4

## Context

Ordering rule 6 says `hook.run(pre_up)` comes before `link.up`. It is
implemented that way, there is a fixture asserting it, and the name says what
it does.

netifrc does something else, and says so:

> For historical and compatibility reasons, preup is actually normally called
> in the following sequence: up ; preup ; up.

with `up_before_preup="NO"` to opt out. The stated reason is that the first
`up` "causes the kernel to initialize the device, so that it is available for
use in the preup function".

That is not merely historical. Checked against a 6.12 kernel, on a dummy
interface, with sysfs mounted in the namespace:

| Interface state | `/sys/class/net/X/carrier` | `/sys/class/net/X/operstate` |
|---|---|---|
| down | `Invalid argument` (EINVAL) | `down` |
| up | `1` | `unknown` |

**The kernel refuses to report carrier on an administratively down
interface.** `operstate` is readable but says `down` either way, so it cannot
distinguish "no cable" from "not brought up yet". A hook that wants to know
whether a cable is plugged in has no way to find out until the interface is
up, which is exactly why netifrc ups it first.

net.example's own canonical `preup()` is that hook:

```sh
preup() {
	if mii-tool "${IFACE}" 2> /dev/null | grep -Fq 'no link'; then
		ewarn "No link on ${IFACE}, aborting configuration"
		return 1
	fi
}
```

Under netcfgd's ordering this does not merely behave differently. `mii-tool`
on a down interface reports no link, the hook returns 1, the transition
aborts, and the interface is never brought up -- so it can never acquire the
carrier the hook was checking for. **It is a deadlock, not a difference.**

## Decision

**netcfgd keeps rule 6.** `pre_up` means before the link is up. The
incompatibility is documented rather than designed around.

The name has to mean what it says. A phase called `pre_up` that runs partly
after `up` is the kind of thing that is fine for the person who implemented it
and a trap for everybody else, and netifrc's own documentation needing a
paragraph to explain the sequence is evidence of the cost. netcfgd has eleven
hook phases where netifrc has four; there is room to be precise.

Adopting `up; preup; up` would also break ordering rule 6's usefulness in the
other direction: a `pre_up` hook exists so that something can happen *before*
the interface is configured -- loading firmware, unlocking a modem, setting a
sysctl the driver reads at up time. Those need the interface down. Serving
both intents from one phase is what forced netifrc into a config switch.

### What breaks, precisely

Only hooks that read link state. A `preup` that loads firmware, sets a
sysctl, checks a file or waits for a peer works unchanged. A `preup` that runs
`mii-tool`, `ethtool`, or reads `carrier` does not, and fails closed rather
than quietly.

### What migrates instead, and what does not

The nearest equivalent is the `carrier` event hook, which fires when carrier
appears. That is the better shape for the intent -- "do not use this link
until it is plugged in" is an event, not a precondition -- and it is what
NetworkManager does.

It is **not a complete replacement today**, and this record says so rather
than implying a clean mapping. netcfgd's planner does not gate addressing on
carrier: it brings the link up and addresses it whether or not a cable is
present. So the netifrc behaviour of *refusing to configure* an unplugged
interface has no equivalent yet. Making it one needs a way to say "this
interface is configured only while it has carrier", which is a model change
nobody has asked for. Recorded as a known gap; not scheduled.

### The converter has to say so

`ncfg convert` (M4) must emit a warning for every `preup` it converts,
naming this record, and a louder one when the body matches the link-checking
idioms net.example itself demonstrates -- `mii-tool`, `ethtool`, or a read of
`carrier` or `operstate`. A silent conversion that produces a config which
cannot bring an interface up is the worst available outcome, and it is the one
that happens by default if nobody writes the check.

## Consequences

**A netifrc user's first converted config may not come up**, and the message
has to be good enough that they do not conclude netcfgd is broken. That is the
whole cost of this decision and it is worth paying only if the warning is
actually written.

**The `pre_up` documentation must state the constraint**, not merely the
order. "Runs before the link is up" is a fact about sequencing; "the interface
is down, so carrier is unreadable" is what the reader needs.

**Rule 6 is now load-bearing in a way it was not.** It was a sequencing choice;
it is now a documented incompatibility, so changing it later breaks hooks
written against this behaviour as well as fixing the netifrc ones. A comment
at the implementation site points here so it is not tidied away.

## Alternatives considered

**Adopt `up; preup; up`.** Rejected: the name stops meaning what it says, the
before-the-interface-exists use case loses its phase, and netifrc's need for
`up_before_preup` shows where that ends.

**Add an `up_before_preup` equivalent.** Rejected as the worst of both. It
makes the ordering configurable, so no hook author can rely on either
behaviour, and every reader of a plan has to check a global before knowing
what the plan means. `ncfg plan` exists so that reading it is enough.

**Introduce a separate phase that runs after `up`.** There already is one:
`up`. A hook needing an initialised device can use it. The only thing `up`
does not offer is the ability to abort before addressing, which is the
deadlock case above, and solving that properly means gating on carrier rather
than adding a phase.

**Have the converter rewrite link-checking preup hooks into carrier hooks.**
Rejected: it changes what the hook does -- from "refuse to configure" to "run
when carrier appears" -- and a converter that silently changes semantics is
worse than one that refuses and explains. `ncfg convert` reports; the operator
decides.
