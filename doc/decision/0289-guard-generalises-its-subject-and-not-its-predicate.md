# 0289: guard generalises its subject, and not its predicate

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0010](0010-interface-guards.md), [0088](0088-consent-is-a-tick-per-refusal-never-a-switch.md), [0288](0288-the-control-path-is-part-of-what-is-being-configured.md)

## What the holder decided, and the risk they named

2026-10-23, after 0288 left lockout prevention with the operator:

> we can have a concept of locking config, as in stuff that requires
> confirmation or other hoop jumping to change, so we can protect something
> that maintains an important link or vital system.

> I mean we already have a feature like this for interfaces, but it is
> stronger, maybe better?

> yes, let's generalize guard to be available for other subsystems too

> problem is defining it if becomes too general

**So: the subject widens, the word stays `guard`, and the predicate does not
widen.** The last of those is the answer to the risk, and it is already written
in this tree rather than being invented here.

## The feature that exists, measured

An interface or a device carries `guard { reason = ... }` in the document.
`prepare()` collects them before any pass runs, so a guard is known whatever
order the interfaces sort in. `refused()` is a single chokepoint every action
passes through -- "so there is one place that decides and no planner path can
route around it" -- and a refused action records the interface, the op, the
guard's reason, and `override_with = "ncfg apply --allow-disruption <iface>"`.
Consent is per interface and per apply, never a switch (0088).

**And the predicate is narrow.** `ncfg_op_is_disruptive` is a closed switch
over every op kind: **22 are disruptive and 26 are explicitly not**, each side
carrying a sentence about why. The criterion those sentences keep is not
"important" -- it is **cuts a connection that is already up**:

> The hostname is not traffic. Changing it can confuse something that cached it
> -- a Kerberos ticket, a shell prompt -- but nothing in flight is cut, and a
> guard exists to protect a connection.

> Toggling an offload re-initialises the driver's transmit path on some
> hardware, which drops what is queued. That is a packet or two, not a lost
> session.

## Why generalising the subject does not make it vague

**The predicate is a closed set that grows by somebody writing a sentence.** An
op is disruptive because a case names it and a comment justifies the side it is
on; nothing is disruptive by inference, by subsystem, or by a pattern over
names. So widening what a guard can be *attached to* cannot widen what a guard
*blocks* -- the two are separate mechanisms and only one of them is open.

That is the structural answer to "too general to define": generality is not
prevented by taste or by a review habit, it is prevented by the switch. A
subsystem whose ops nobody has classified is a subsystem whose ops a guard does
not stop, visibly, and the fix is one case and one sentence.

## What widening the subject actually requires

- **A subject key that is not a string guess.** Today the guard compares
  `builder->guards[i].interface` against `ncfg_op_interface(op)`, and every one
  of the 22 disruptive kinds resolves an interface -- measured, not assumed. A
  route, a rule, a zone or the host itself has no such name, which is **the
  same stable-identity requirement [0287](0287-a-rule-carries-its-own-standing.md)
  raised for rule standing**. Two requests converge on one piece of work: name
  the things netcfgd configures, stably, across re-plans.
- **A per-subsystem answer to the predicate, written per op.** What cuts a live
  connection differs by subsystem and is not guessable from the op's name.
- **A strength declared per guard rather than globally.** Today every guard is
  equally strong and `--allow-disruption` equally cheap. "Hoop jumping" wants
  more than one setting -- consent as now, consent only from a local client, or
  an unlock that is its own change -- and making that a property of the guard
  lets one machine protect its uplink harder than its lab bridge without a
  global mode.

## 0283 will move cases from one side to the other, and that is the mechanism working

`NAT_REPLACE`, `RULE_ADD`, `QDISC_SET` and `DNS_APPLY` are among the 26 today,
and the reasoning is sound for what those ops can currently do: replacing a
table that only masquerades does not cut an established flow.

**A full filter ruleset can.** A policy that goes from accept to drop cuts
exactly what is up, which is the predicate's own words -- so when 0283's
firewall arrives, some of those cases move, with a new sentence saying why.
**That is the design working rather than a flaw in it**: the predicate is about
effect, the ops gain effects, and the classification follows the effect instead
of the subsystem's name.

## Two gaps that "hoop jumping" names and the current guard does not close

- **The guard itself is unguarded.** Removing `guard { reason = ... }` from the
  document is an ordinary edit, and the next apply is unprotected. A lock that
  a careless config change removes is a speed bump, so changing or removing a
  guard should itself need the ceremony -- while remaining possible, because a
  guard that cannot be removed makes a bad configuration permanent.
- **A guard is not yet enforced against the network.** 0285's directives arrive
  from a coordinator, and nothing says a directive cannot carry its own
  override. It must not: **the node's guard wins**, and consent to disrupt a
  guarded subject has to be granted to the node rather than asserted by the
  message -- which is the narrower-than-admin authority 0284 already needs for
  another reason.

## The limit, restated so the lock is not oversold

A guard protects a subject **from netcfgd's own actions**. It does not protect
it from a change made elsewhere that breaks it anyway -- the upstream switch,
the jump host, the other node's route -- which is 0288's argument and does not
weaken with more guards. A guard makes netcfgd refuse to be the one that cut
the link, and says who may tell it otherwise.
