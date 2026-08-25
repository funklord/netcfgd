# 0094: a confirm default nobody read

Status: accepted
Date: 2026-08-04
Milestone: found while closing the GUI's last item

## Context

`gui/project.md` carried one line of unfinished business: `globals.confirm_default`
was unreachable from the window, so the apply dialog offered 60 seconds of its
own. Going to fix that meant asking where the machine's number lives.

It lives in the document and nothing reads it.

```
global { confirm = 90 }
```

compiles to `Globals::confirm_default`, is carried in the compiled document, is
pinned in `doc/schema/document.json`, and appears in `project.md`'s config
listing as *"seconds; commit-confirm default window"*. Grepping every crate for
a read finds the definition, the line in the compiler that writes it, and a test
fixture. Nothing else.

`PlanOptions::confirm_window` came from `--confirm-within` alone. So an operator
who wrote `confirm = 90` believing every apply had a ninety-second safety net
had **none**, silently — the same shape as the four inert config keys 0061
closed, and found the same way: by reading the config surface against the code
rather than by any gate going red.

The dialog's hardcoded 60 was the smaller half of the same problem: two clients
with two answers to one question, on a machine that had stated the answer.

## Decision

**The planner uses the document's window when the caller does not name one.**

Opt-in, so nothing changes for a machine that never wrote the key: `None` stays
`None` and no window is armed. Arming one everywhere would make a change revert
itself on machines that never asked, which is a worse failure than the one being
fixed.

**`--confirm-within 0` means no window**, and is the only way to say it on a
machine that set a default. It cannot mean a window of zero seconds — that would
arm and expire, which is two spellings of "no" where one of them reverts the
change, and the C client already refused to send `"confirm":0` for that reason.

**The dialog asks the machine.** `ncfg_client_confirm_default` reads it out of
the compiled document — a large answer for one number, asked once when the
dialog opens. A client with a default of its own would disagree with `ncfg
apply` on the same box about how long an operator has to confirm, which is the
shape this project keeps having to undo.

A daemon that cannot be asked leaves the dialog's own 60, which is the same
answer as a machine that names none.

## The gates

Four cases, and the fourth is the one that keeps this safe:

- a document that names a window gets one, with **its** number and not the
  planner's;
- an explicit `--confirm-within` beats it;
- `0` arms nothing while leaving the rest of the plan intact — so it refuses the
  window and not the apply;
- **a document that named nothing still gets nothing.**

Breaking the first turns one test red. Breaking zero-means-none turns one red.
Breaking the fourth — arming a window when the document named none — turns
**102** red, because a `commit.arm` on a converged plan makes every idempotence
check in the suite non-empty. That is the suite noticing a behaviour change
nobody asked for, from tests written for something else entirely.

End to end against a real daemon: `ncfg plan` on a machine with `confirm = 90`
arms `commit.arm globals.confirm_default: 90s`, `--confirm-within 0` arms
nothing, and the dialog's spinbox opens at 90.

## What this does not change

Whether a window is a good idea by default. It is not one by default: a machine
gets what its own configuration asked for and nothing more. The key existed and
said what it meant; what was missing was anything acting on it.
