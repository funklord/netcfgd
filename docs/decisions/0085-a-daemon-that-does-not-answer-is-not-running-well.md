# 0085: a daemon that does not answer is not running well

Status: accepted
Date: 2026-08-04
Milestone: the last corner of "is what is running still what the document says?"

## Context

Four decisions have chipped at one question. 0052 asked whether a running access
point still holds the passphrase the store has. 0053 asked whether a tunnel's
config file is still the file it was started from.
[0078](0078-a-record-is-a-memory-and-a-process-is-a-fact.md) found that `running`
was a *memory* -- `/run/netcfgd/state.json` said netcfgd started something, and
nothing ever asked the machine -- and made it a fact about a process.
[0080](0080-a-socket-outlives-the-process-that-bound-it.md) did the same for a
supplicant, where a socket had been standing in for a process.

Section 10 carried the remainder as: *"a daemon that is alive and wedged still
counts as running, which is 0052's shape applied to behaviour rather than to
configuration."*

**netcfgd already knew.** `read_access_control` has asked hostapd for its station
lists on every observation since 0052, under a one-second deadline. When that
round trip fails it does this:

```rust
let Ok(live) = netcfgd_hostapd::acl::read(run_dir, &backend.interface) else {
    // hostapd is gone, or was never reachable. [...] saying nothing is the
    // honest answer.
    continue;
};
```

Saying nothing is the honest answer *about the list* -- converging against a list
netcfgd could not read is converging against a guess, which is the rule that
comment exists to state. It is not the honest answer about the **daemon**. The
verdict was computed on every observation and thrown away, and `running: true`
went on the socket over the top of it.

So this was not a missing check. It was a check whose answer nothing wrote down.

## Decision

**`ObservedBackend::answering`**, an `Option<bool>` beside `running`.

Separate from `running` rather than folded into it, for the reason 0078 exists:
`running` is a fact about a process, "answering" is a fact about behaviour, and
a daemon can be the first without being the second. Conflating them would repeat
the mistake 0078 corrected, one level up.

**`None` is not `false`** -- the same rule the liveness pass turns on. `None`
means netcfgd could not ask: the kind has no control socket, nothing tried, or it
is not running. Reading it as "did not answer" would put a warning on every
dhcpcd on every machine.

A plan **warning**, naming the interface and saying what to do.

## What it deliberately does not do

**It does not restart anything, and it is not a refusal.**

netcfgd cannot tell a wedged daemon from a slow answer. The deadline behind this
is one second and it is one second *on purpose* -- 0041 measured a wedged hostapd
holding a single `ncfg plan` for 10.2 seconds, and the deadline is what keeps a
wedged daemon from stalling the reconcile loop. `tests/live/acl.sh` already
carries a note about a *healthy* Python fake missing that deadline during a
`make live` sharing the machine with a container build.

A netcfgd that restarted on that reading would take working access points off
the air on busy machines. That is a worse failure than the one being reported,
and it is the failure mode of the thing the operator would most like this to do.
So the operator is told, and the operator decides.

The same argument in the other direction is why it is not a refusal either: a
plan that refused to run because a daemon was slow to answer would be a plan that
stops working on load.

## The gates

**Live, against a real wedged daemon.** `fake_hostapd.py --wedged` binds the
socket and answers nothing, ever -- a flag rather than a second fake, because the
state is precisely "the real one, minus the reply". Four checks in
`tests/live/acl.sh`: the observation says `answering: false`, the list is
**absent** rather than empty beside it (the failed round trip is *why* there is
no list), the plan names the interface in a sentence, and nothing is stopped or
started on the strength of it.

Breaking the two lines that record the verdict -- restoring exactly the `continue`
that was there before -- turns two of those red.

**In the planner**, all three states in one test: `Some(false)` warns,
`Some(true)` does not, `None` does not. Breaking the condition so that `None`
warns turns it red, which is the case that would otherwise have shipped as a
warning on every machine with a DHCP client. A second test covers `running:
false` with a stale `answering`, which is reachable because the liveness pass
runs *after* the round trip.

**In the witness.** `docs/schema/observed.json` carries both verdicts -- an access
point that answered, and `wedged0`, which is running, not answering, and has no
list. The second is the shape this decision is about, and a witness with only the
first would pin a field that never disagrees with itself.

Additive: `answering` is skipped when absent, so a `/run` record written by an
older netcfgd still parses and a new one is byte-identical where nothing asked.
A **minor** bump.

## What is left

Only access points answer this today, because only access points are asked
anything. A supplicant has a control socket and netcfgd does not read it during
observation; giving it the same treatment is a real piece of work rather than a
line, and it is worth doing when something wants the answer. hostapd's own
liveness is still 0080's open item for its own reason: nothing here can run a
real hostapd on a dummy.
