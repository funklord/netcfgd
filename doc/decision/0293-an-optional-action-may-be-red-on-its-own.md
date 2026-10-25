# 0293: an optional action may be red on its own

Status: accepted
Date: 2026-10-25
Milestone: M6
Follows: [0010](0010-interface-guards.md), [0283](0283-firewall-and-queuing-are-in-scope.md), [0287](0287-a-rule-carries-its-own-standing.md), [0288](0288-the-control-path-is-part-of-what-is-being-configured.md), [0292](0292-a-compiled-out-construct-answers-like-a-blocked-one.md)

## The instruction, and what it was answering

The copyright holder, 2026-10-25: *"do the standing thing for optional ops
then"*, closing the question project.md 10.554 had raised and 0292 had left
open.

What raised it was a measurement rather than a theory. `tests/hull/natcap/`
asked for `ingress_bandwidth` on a kernel with no `ifb` module, and netcfgd's
apply did this:

    FAIL link.create ifb-wan0   kind: ifb
    skip link.create wan0       kind: dummy
    skip link.up wan0
    skip addr.add wan0          addressing[0]: 10.9.9.2/24
    skip qdisc.set wan0 ...     (three more)
    ncfg: stopped at action 0 (link.create); 0 done, 7 not attempted

**An interface lost its address because the kernel could not shape its
ingress.** Nothing in the plan depended on the shaping; the plan merely
stopped at the first failure, and the shaping happened to be first.

## What was already settled, and why it does not answer this

0010's guards refuse an action at plan time when carrying it out would be
disruptive, and 0290's locks refuse one the operator has declared not
netcfgd's to set. Both act **before** anything runs, on things netcfgd can
know. This is the other case: the plan was right, the operator asked for
something reasonable, and the kernel said no.

0288 settled that netcfgd cannot be trusted to work out which link keeps an
operator connected -- *"I find it unlikely netcfgd will become smart enough to
never hose its necessary connections"*, and that survivability rather than
cleverness is the target. So this record does not try to rank actions by how
vital they are. It asks the one question netcfgd can answer: **is the
interface usable with this action's work absent?**

0287 has the vocabulary. A rule carries its own standing, and a red row names
its reason; the holder's example is a list of two hundred rules with one red
because a machine lacks a kernel feature. This record is that concept applied
to an action rather than a rule.

## What is decided

1. **An action is optional or required, and the default is required.**
   `ncfg_apply_optional` is the whole of the classification, and it is a short
   list: `qdisc.set`, `qdisc.reset`, `ingress.redirect`,
   `ingress.redirect.clear`, `nat.replace`, `link.set_offloads`, and link ops
   on an `ifb` device. Everything else -- addresses, routes, links, policy
   rules, bridge vlans, sysctls, backends, the wireless ops -- is required.

2. **An optional action's failure does not stop the plan.** It is journaled
   `NCFG_OUTCOME_UNMET`, the executor carries on, and an action that genuinely
   depended on the failed one fails on its own account with the kernel's own
   reason rather than being guessed at.

3. **Unmet is a failure, not a success with a note.** `ncfg apply` exits
   non-zero, `ncfg_journal_succeeded` is false, the per-action mark is `red `
   rather than `ok`, and the summary counts it: `3 done, 1 unmet, 0 not
   attempted`. The daemon's reconcile says it too, at `WARNING`, because
   `ncfg_journal_failure` answers for the action that *stopped* a pass and an
   unmet one by definition did not -- a pass that left something red said
   nothing at all before this.

4. **The `ifb` prefix is read as a fact about why a device exists.**
   `lower.c` names an ingress shaper's device `ifb-<interface>`, nothing else
   in this port creates an `ifb`, and `render_device.c` already reads the
   prefix that way. The ops after the create carry a name and no kind, so
   classifying only the create would move the stop along by one action rather
   than removing it.

## Why the list is short, and what each member rests on

An op is in it only where the interface carries traffic without it:

- **Queuing** (`qdisc.*`): a kernel with no `sch_cake` carries traffic
  unshaped. Measured refusal: `RTM_NEWQDISC`, `ENOENT` (0291).
- **Ingress shaping** (`ingress.redirect.*`, and the `ifb` device): the same,
  one layer out. Measured: `RTM_NEWTFILTER`, `ENOENT`, and `RTM_NEWLINK`,
  `EOPNOTSUPP` for the device.
- **NAT** (`nat.replace`): the host's own traffic is unaffected -- what breaks
  is translation for others, which is a service this host offers rather than a
  path it depends on. Measured: `NFT_MSG_NEWCHAIN` or `NFT_MSG_NEWRULE`,
  `ENOENT` (0292).
- **Offloads** (`link.set_offloads`): a driver that refuses a feature refuses
  the whole request and nothing changes, which is a performance difference and
  never a reachability one.

Every member has a measured capability sentence behind it, which is what makes
a red row say something an operator can act on rather than only "failed".

**Policy rules are deliberately excluded**, although 0287's example is about
rules: a rule here is `ip rule`, and a management network reached by policy
routing has its reachability in exactly that table. Netfilter rules -- 0283's
five layers, which is what 0287 is about -- do not exist as ops yet; when they
do they belong in this list, and `nat.replace` is the one that already does.

## What is not decided here

**Whether an operator may declare standing.** 0287 asks for pinning a rule as
expected-unsupported so that its red stops being noise, and the symmetric want
is marking something netcfgd thinks optional as required-for-me. Both are
config surface and neither is built; the classification is netcfgd's own for
now, which is defensible precisely because the list is short.

**What a reconcile does with a standing red.** The daemon retries every pass,
which is correct -- the state is idempotent and a kernel upgrade may fix it --
and logs one line each time. Whether that should back off, or go quiet after
the first, needs the standing to be remembered across passes, which is 0287's
"standing is computed, not stored as truth" question and not this record's.

**Ordering.** A plan still runs in the order it was built, so an optional
action can still run before a required one; nothing now depends on that order
being changed. Sorting optional work last would make the window where a
required action waits on an optional one shorter, and it would also mean
reasoning about dependencies the plan encodes today -- a separate change, with
a measurement to justify it first.
