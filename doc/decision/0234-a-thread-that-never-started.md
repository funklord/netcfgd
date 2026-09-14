# 0234: a thread that never started

Status: accepted
Date: 2026-09-14
Milestone: M9; the thread lifetime audit

## The question 0233 said was not being asked

0233 fixed a daemon that went deaf when one thread returned, and ended by naming
what would have found it: *which threads must stay alive for this daemon to keep
working, and what happens to each if it returns?* This is that audit.

Every thread, what ends it, and whether anything notices:

```text
thread    spawn result   ends on                          says what is lost
control   checked (?)    nothing: incoming() is endless    n/a
client    handled        the request finishing             n/a
join/scan captured        the command finishing            n/a
netlink   DISCARDED      a fatal error, or shutdown        yes
config    DISCARDED      any watch error, or shutdown      no, only the error
roam      DISCARDED      shutdown only                     n/a
rfkill    DISCARDED      an absent device, a read error    yes
confirm   DISCARDED      one-shot: sleep, send, end        n/a
```

**`serve` already does it correctly**, which is what makes the rest a defect
rather than a gap. The control thread is spawned with `.spawn(...)?`, so a
daemon that cannot accept connections fails to start instead of pretending to
have started; and a client thread that cannot spawn is handled deliberately,
with a comment, keeping the accept loop alive. The idiom exists in this
codebase, in the file most likely to be read first, and five spawns in `lib.rs`
do not use it.

## A thread that never started looks exactly like one that is running

`let _ = std::thread::Builder::new()...spawn(...)` discards two things: the
handle, which is right -- none of these is ever joined -- and the `Result`,
which is not. The process comes up, systemd calls it active, and whatever that
thread was for never happens.

`note_spawn` takes the outcome and says what was lost when there is nothing to
say it otherwise. The sentence is about the consequence rather than the thread's
name, because the name is netcfgd's word and the consequence is what the
operator will see:

```text
kernel changes will be noticed only on the loop's own tick, not as they happen
a configuration change will not be noticed until something else wakes the loop
roaming, authentication failures and refused associations will go unreported
kill-switch changes on this radio will not be noticed
a commit-confirm window will not close on time
```

## The one that is a safety mechanism

The last of those is different in kind, and it is the finding of this round.

`spawn_expiry_timer`'s own documentation says why it exists:

> A dedicated one-shot thread rather than the 5-second tick, because a safety
> mechanism that fires up to five seconds late is one whose window is not the
> length it says.

It is the thread that closes a commit-confirm window. Commit-confirm is what
reverts a change the operator did not confirm -- the mechanism for applying a
configuration over the very link it might break. And `resolve_expired_window` was
called from exactly one place:

```rust
if confirm_expired {
    resolve_expired_window(&mut state, &mut subscribers);
}
```

`ConfirmExpired` is sent by that thread and by nothing else. So a spawn that
failed left the window open for ever: the change stayed applied, no revert
happened, and no line anywhere said the timer had not started. **The safety
mechanism failing silently through the mechanism meant to be the safety.**

The tick asks now as well. The timer stays, for the reason its comment gives --
a missing timer costs seconds rather than the window, which is the trade that
comment is about. It is free to ask on every pass because the resolver already
asks the window whether it has *really* expired, and `Window::expired_at` is
tested against a window with time left, a machine that slept through one, and a
clock somebody moved.

It is `should_resolve_window` rather than an inline `||`, because the second
half reads like an accident and its absence was one.

## Threads are still not restarted

None of these is supervised. A thread that ends is gone until the daemon
restarts, and this decision does not change that -- it makes the loss *visible*
and gives the two whose work has a deadline a backstop that does not depend on
them:

- the reconcile loop ticks on its own (0233), so a dead netlink or config
  watcher costs immediacy rather than reconciliation;
- an expired window closes on that tick, so a dead or never-started timer costs
  seconds rather than the revert.

`roam` and `rfkill` have no backstop and would go quiet. Both report events
rather than driving anything, so the cost is diagnosis rather than
configuration -- but it is a real cost and it is recorded here rather than
fixed. Restarting a watcher that died needs somewhere to decide *when to give
up*, and that is a design question rather than a patch.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| discard the spawn result again | `a_thread_that_cannot_start_is_reported` | FAILED |
| the tick stops asking about the window | `a_tick_also_asks_whether_the_window_closed` | FAILED |

The second one passed on its first run, against a fix written minutes earlier --
the seventh time in this campaign that a change went in with nothing holding it
until the sabotage pass asked. It is the reason that pass exists.
