# 0063: The down hooks run before the interface goes

Status: accepted; `down` and `post_down` fire, `pre_down` deliberately does not
Date: 2026-08-03
Milestone: the laptop list, after [0062](0062-a-blocked-radio-is-reported-and-not-unblocked.md)

## Context

[0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) found that
nine of the eleven hook phases were recognised, materialised into
`/run/netcfgd/hooks/`, hashed into the document, and never run. `down` and `lease`
were named as the two an operator reaches for first. This is `down`.

## Decision

**`down` runs immediately before the action that takes the interface away, and
`post_down` immediately after it.** Two sites emit them, and both are places where
the document still describes the interface:

- `link.down`, for `enabled = false`.
- `link.delete` in the recreation pass
  ([0059](0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md)) --
  where the interface comes straight back, and where `pre_up` and `post_up` already
  fired because the creation pass plans a remade interface as absent. A `down`
  beside them is what makes an operator's pair symmetrical.

**"Immediately before" is not "during", and the difference is what makes the hook
useful.** Teardown is the last thing in a plan (make-before-break), so at the
moment a `down` hook fires the interface still has its addresses, its routes and
its carrier. That is what lets one unmount a share or stop a service that is using
them. `tests/live/hooks.sh` checks that by having the hook look: it runs `ip addr
show` on itself and the transcript says the address was still there.

**A guard refuses the hook with the transition it belongs to.** `link.down` is
disruptive and a guarded interface refuses it (0010); the `down` hook has to go
with it, because a `down` script that runs when nothing goes down has *already*
unmounted the share and the guard has kept the interface up. So `Op::HookRun` is
disruptive for the down phases and not for the up ones -- the same
payload-dependent answer `AccessControlAdd` already gives -- and both are refused
by the one function that decides.

**`pre_down` is not implemented, and that is a choice rather than an oversight.**
It would fire at the same point in a plan as `down`, so the two would be
indistinguishable. The phase's distinct meaning -- "before anything is withdrawn"
-- needs an ordering netcfgd does not have: for `enabled = false` the addresses go
in the teardown pass, *after* the `link.down`. A plan names it as unfired.

## What this found, which is worth more than the feature

Putting hooks in front of a real kernel turned up two defects that had been there
since hooks existed. Both come from the same line: the up hooks were emitted
unconditionally.

**A converged interface ran its `pre_up` and `post_up` on every apply.** The second
plan was never empty, against the brief's own words -- "applying an already-correct
state produces zero actions, runs zero hooks, and touches nothing" -- and against
section 6's plan-idempotence gate. On a *daemon* that means somebody's `post_up`
script runs on every netlink event the machine sees.

**And a disabled interface ran them too**, producing this:

```
0  hook.run eth0   hooks[pre_up]
1  link.down eth0  enabled: false (was true)
2  hook.run eth0   hooks[post_up]
```

Now both fire only where they mean something: `pre_up` when a `link.up` is planned,
`post_up` when that or any addressing action is. "After the last addressing action"
is not a moment in a plan that has none.

**The idempotence gate could not see any of it**, and the reason is section 9's
oldest lesson: the one fixture with hooks in it called `plan` and `simulate` by
hand rather than going through `settle`, so no document with a hook had ever been
run through the gate that asserts the second plan is empty. It goes through it now.

## The hash check had never been exercised, and could not be

Section 2.2 gives each hook a `sha256` so that "drift detection notices that a hook
script changed underneath you". Nothing had ever tested it, and the first attempt
to could not: **`ncfg apply` compiles and materialises the hooks microseconds
before running them**, so the hash it checks is of a file it has just written. The
daemon re-materialises whenever the config changes, which closes the other obvious
window.

The check has teeth in exactly one place: a plan that comes from a **kernel**
change against a document compiled earlier. That is drift, which is what 2.2 said
in the first place. `tests/live/hooks.sh` now reaches it -- daemon running,
somebody brings a disabled interface up by hand, the materialised `down` hook is
edited, and the apply refuses the hook by hash and stops before the `link.down` it
was bracketing.

**And the failure was invisible over the socket.** The journal record has carried an
`error` field all along; the `--confirm-within` path printed the outcome and the op
name and dropped it, so a client saw `Failed hook.run` and no reason, while the same
failure through a local `ncfg apply` printed it. One line.

## Consequences

- Four of the eleven phases now fire. The warning 0061 added shrinks to seven, and
  each still names itself.
- `Op::HookRun` gains `address`, which is `NCFG_ADDR` in the environment. Unused by
  the four phases here and set by the `lease` phase, which is the next piece. The
  plan witness moved: a minor addition.
- One `plan_hooks` helper for what had been two emission sites and was about to be
  four, so the shape of a hook action is decided once.
- An interface removed from the document entirely gets **no** `down` hook, and that
  is inherent: the document is the only place the hook is described, and its
  materialised file is gone on the next compile. An interface being *cleared*
  (`on_unmanage = "clear"`) also gets none, which is not inherent -- the teardown
  pass filters the interface out before it could look -- and is named here rather
  than left to be discovered.
