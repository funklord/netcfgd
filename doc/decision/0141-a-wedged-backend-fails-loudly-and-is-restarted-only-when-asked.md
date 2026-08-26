# 0141: a wedged backend fails loudly, and is restarted only when asked

Status: accepted
Date: 2026-08-26
Milestone: M8, by the copyright holder's instruction

Reverses what [0074](0074-a-daemon-that-cannot-answer-is-still-running.md) and
[0098](0098-a-supplicant-that-bound-its-socket-and-stopped-answering.md) left
netcfgd doing with a daemon that has stopped answering, and settles the wider
rule the instruction states.

## The instruction

> The job of netcfgd is to fully understand everything it invokes. And if
> something does something funny it should kill it and restart it.

and, immediately after:

> Default is failure and loud error, restart is an option.

Both halves matter, and the second is what makes the first safe.

## What netcfgd did before

0074 gave netcfgd the vocabulary for a daemon that is *running* and not
*answering*, and 0098 made the supplicant carry it. Having built the
distinction, netcfgd then only described it:

> the supplicant on wlan0 is running and did not answer its control socket.
> netcfgd cannot configure it while it is like this, and **does not restart it:
> a busy machine can miss the deadline too. Check it, and restart it yourself
> if it is wedged**

**Two things were wrong with that, and only one of them was the refusal.**

The reasoning is sound: a machine too busy to answer within the deadline is
indistinguishable from a wedged one, and killing a healthy supplicant takes a
working radio off the air. That is why netcfgd still does not restart on its
own.

What was wrong is everything around it. It told an operator to go and fix a
daemon **netcfgd started** -- on a headless machine there is nobody to tell.
It named no way to have netcfgd do it, so the only route was `kill(1)` and a
reconcile. And it said this in a *warning*, among every other warning, when
netcfgd has a first-class type for exactly this and has since
[0010](0010-interface-guards.md): a `Refusal`, which carries the op
that was not planned, the guard that stopped it, and **the exact invocation
that consents**.

A refusal is also not a thing that stops an apply -- it is an action declined
-- so the old objection that acting on this "must not be a thing that stops an
apply" was aimed at something the type does not do.

## Decision

**A backend that is running and answering nothing is a loud failure. netcfgd
does not restart it unless an operator names the interface.**

- The warning stays, and stops giving advice netcfgd cannot follow.
- A `Refusal` is emitted with `op = "backend.restart"`, the guard, the reason
  (`backend.answering`: expected answering, observed running and silent), and
  `override_with = "ncfg apply --restart-wedged <iface>"`.
- `--restart-wedged IFACE` plans a `BackendStop` followed by a `BackendStart`
  ordered after it, each carrying the other as its inverse -- the shape
  `restart_stale_tunnel` already uses.
- **Per interface, never global.** Consent to restarting the supplicant on one
  radio is not consent to restarting every backend on the machine, which is the
  same reason `allow_disruption` and `strand_credentials` are separate lists.
- **Bounded even when consented.** `RESTART_LIMIT` (0079) stops after five and
  says so. Consent to a restart is not consent to a loop, and a machine that is
  merely slow would otherwise be restarted for ever by one flag.
- **The reconcile loop passes nothing.** The daemon's own tick supplies an
  empty list, which is what makes the default hold on a machine nobody is
  watching.

**`answering` must be `Some(false)`, never `None`.** That is 0074's rule and it
is load-bearing here rather than decorative: `None` means netcfgd could not
ask -- no control socket, or nothing tried -- and reading it as "not answering"
would condemn every backend that has no socket to ask.

## The first attempt was wrong, and it is worth recording why

The first implementation restarted automatically, on the strength of the first
half of the instruction alone. It was building for ten minutes before the
second half arrived. **The bound was already there -- 0079's counter -- so the
automatic version was not unsafe so much as it was not the decision**: it
substituted netcfgd's guess for a person's knowledge in the one case where
netcfgd provably cannot tell the difference.

Which is the difference the instruction draws. netcfgd understanding what it
invokes means being able to say a daemon is wedged, name it, and offer to fix
it. It does not mean acting on an observation that has a known false positive.

## Consequences

**Two tests asserted the old rule and were changed with the reason recorded.**
`fixtures.rs`'s `a_wedged_daemon_is_named_and_a_silent_one_is_not` asserted "a
warning, never a refusal"; `tests/live/wedged.sh` asserted "and nothing is
refused over it". Both now assert the refusal, that it names the flag, **and
that the flag is not decorative** -- with consent the plan contains the restart
and the refusal is gone. Without that second half the option could be accepted
and ignored, which passes a test while doing nothing.

**The socket protocol gained a field.** `Request::Apply` carries
`restart_wedged`, beside `allow_disruption` and `strand_credentials`, with the
schema witness reblessed and the members table updated.

**A tightening is still open.** The instruction says netcfgd should fully
understand everything it invokes. It does not yet: `dhcpcd` rewrites its own
command line with `setproctitle`, so netcfgd cannot identify it from `/proc` at
all -- measured live, `/proc/<pid>/cmdline` reads `dhcpcd: wlp0s20f3 [ip4]` and
nothing netcfgd chose survives in it. That is the subject of its own record,
and it is why 0140's marker approach stops at the supplicant.
