# 0107: you cannot ask the caller a question

Status: accepted
Date: 2026-08-05
Milestone: the shim stall, found by watching without touching

## Context

[0106](0106-two-twenty-five-second-timers-racing.md) established that
`ActivateConnection` occasionally returns no reply, nmcli gives up at GDBus's
twenty-five-second default, and the secret agent is never asked — and guessed
at the cause: zbus re-entrancy, an outgoing D-Bus call made from inside a method
handler.

**That guess was wrong too.** Instrumenting the handler with `eprintln!` to
confirm it made the stall stop happening — eighteen consecutive clean runs
against something that had reproduced twice in four. A write syscall per
checkpoint was enough to move it, which is also the reason the guess could not
be tested.

## Watching without touching

`adapters/netcfgd-nm/src/trace.rs` is a ring of checkpoints: a monotonic
timestamp and a `&'static str`, into memory, with no formatting, no allocation
and no syscall on the measured path. A watchdog thread notices a handler that
has been in flight for ten seconds and dumps the ring **afterwards**, so nothing
being measured ever writes to a file descriptor. Off unless `NCFG_NM_TRACE` is
set.

It was proved before it was trusted: an eleven-second sleep injected into the
handler produced

```
nm-trace: a handler has been in flight for 10217548us -- the ring follows
nm-trace:   + 11000332us  @  12788163us  activate: asking netcfgd to activate
```

and it did **not** perturb the real stall away. Fifth run:

```
+       13us  ask: calling NameHasOwner
+    11434us  ask: NameHasOwner returned
+        3us  ask: building the agent proxy
+       26us  ask: calling GetSecrets
nm-trace: end
```

The shim's own outgoing calls are fine — `NameHasOwner` answers in milliseconds,
which disposes of the re-entrancy theory. It stalls inside `GetSecrets`, waiting
for an agent.

## What it is

The agent it waits for is not the one the test started.

```
agent log:  registered as :1.99
nm-trace:   last agent asked for a secret: :1.100
```

`:1.100` is **nmcli**, which registers a secret agent of its own for
`connection up` — and which is, at that moment, blocked waiting for
`ActivateConnection` to return. The shim asks it for a passphrase; it cannot
answer until the call it is waiting for completes; that call is waiting for the
answer. A circular wait, unwinding at the default timeout, and intermittent
because it depends on which agent the list yields first.

Real NetworkManager does not have this problem, and the reason is structural:
it returns the active-connection path **first** and asks for secrets during the
asynchronous activation that follows, by which time the caller is free.

## Decision

**The shim never asks the caller for a secret.**

`ActivateConnection` has the sender in its header, and any agent registered on
that same connection is provably unable to answer while the call is outstanding.
Skipping it costs nothing — every other registered agent is still asked, in
order — and it converts a deadlock into either a working answer or netcfgd's own
"secret not found", which is the honest outcome.

**Not made asynchronous.** Returning the path first and asking afterwards is
what NM does and is the deeper fix, but it means an `ActiveConnection` that
changes state after the method returns, with signals and a state machine behind
it. That is a feature, not a bug fix, and it should not ride in on this.

## The gates

| | cancelled-prompt failures |
| --- | --- |
| with the skip | **0 of 12** |
| with it removed | 3 of 8 |

The break needed doing twice: the first attempt edited paths relative to a shell
still sitting in `adapters/netcfgd-nm` from an earlier `cd`, so nothing was
modified and eight runs of the *fixed* binary reported a clean break. §9's rule
about a break that does not apply, in a new disguise.

## What this corrects

Two earlier readings in this repository, both mine and both stated with more
confidence than the evidence carried:

- 0106's "the stall is in the shim's re-entrancy" — the outgoing calls are
  milliseconds; the wait is on somebody else's answer;
- the fake agent's registration window — investigated, changed, and **the
  failure survived it**. The change is kept because announcing readiness before
  being able to answer is wrong on its own terms, and its comment now says
  plainly that it fixed nothing.

## What is left

`trace.rs` stays for now: it is the only thing that could see this, the question
it was built for is closed, and the next one in this adapter will want it. It is
inert without `NCFG_NM_TRACE` and is documented as removable.

The other nm.sh flake — *"the nameservers come from what was applied, not from
the config"*, about two runs in ten — is untouched and unexplained.
