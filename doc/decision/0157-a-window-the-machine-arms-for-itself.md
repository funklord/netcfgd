# 0157: a window the machine arms for itself

Status: accepted
Date: 2026-09-05
Milestone: found while making commit-confirm's reversibility mark truthful

## Context

[0094](0094-a-confirm-default-nobody-read.md) found that `global { confirm = N }`
compiled to `Globals::confirm_default`, was carried in the document, was pinned
in the witness, was listed in `project.md`'s config surface, and was read by
nothing. It fixed that in the planner: `netcfgd_plan::confirm_window` -- the free
function, not the `PlanOptions` field of the same name, which is the caller's
answer and does not fall back -- resolves the caller's number, the caller's
zero and the document's own, and the plan gains a `commit.arm` action.

That was half the path. `commit.arm` is a marker the executor deliberately
no-ops, because the window belongs to the daemon rather than to the kernel --
so the action was recorded `Done`, counted in "applied N actions", and no
`/run/netcfgd/confirm.json` was ever written. `confirm::arm` had exactly one
caller in the workspace, `apply_request`, and it armed from the *request's*
`confirm` field rather than from the plan's effective window. It has two now.

Measured on a machine whose config said `confirm = 30`, against a control with
no key at all:

    startup apply        plan contains commit.arm    no window written
    watcher applies      commit.arm dropped entirely no window written
    control, no key      identical in both rows

The middle row has a second cause worth recording: `state::restrict` keeps only
actions whose op names an interface, and `Op::CommitArm` names none, so on the
drift path the arm was discarded before it reached the executor.

So an operator who wrote the key, ran `ncfg plan`, saw `commit.arm
globals.confirm_default: 30s` and watched an apply succeed had exactly the
safety net they would have had without writing it.

## Decision

**The daemon arms a window from the document when it applies a change it made
for itself because the configuration changed.** The window is real: it writes
`confirm.json`, records the inverses of what ran, and spawns the expiry timer,
so an unconfirmed change reverts on its own.

**It is narrower than that sentence, and the narrowing is the reconcile path's
rather than this decision's.** The arm sits after two early returns: no
interface is reconciling, and the narrowed plan is empty. So a change touching
only globals -- DNS, the hostname -- or touching only interfaces whose
`on_drift` is `report`, arms nothing, because that path applies nothing. Those
changes reach the machine by other routes or not at all, and a window over an
empty plan would be a safety net over nothing. Worth stating because the
sentence above promises more than the code does.

**Two exclusions, and they are the design rather than gaps in it.**

**Startup never arms.** `establish_first_last_good` writes an empty document as
the last-good *before* the first apply, so on a machine that has never applied,
a window armed at boot and left unconfirmed reverts to nothing -- every address,
route and backend netcfgd has just brought up, taken down N seconds after start
with nobody present. `converge` runs from `start_up` rather than from the
command loop, so it is exempt by construction; the exemption is written down
because nothing structural stops somebody wiring it in later.

**And excluding the startup apply does not exclude the empty document it leaves
behind.** That was this record's first mistake, caught by review before it
shipped: the reasoning above protects the boot-time apply and says nothing
about the placeholder still being on disk for the next config change.
`converge` replaces it only when the startup journal has *no* failure, so a
single failing action -- an unreachable gateway, a backend not up yet -- leaves
the placeholder indefinitely. An operator then changing one field arms a window
whose revert removes everything netcfgd installed. Measured with the guard
removed: the window armed, and six seconds later the interface had no address
at all. So the arming path refuses a last-good equal to `Document::default()`
and says why. The distinction that makes the placeholder acceptable for
`--confirm-within` and not here is that somebody asked for that one and is
watching it.

**A pass that corrects only drift never arms.** netcfgd putting back what
something else changed is not a change anybody is waiting to confirm. Arming
there would revert netcfgd's own correction when nobody did, and the drift would
be found again on the next pass.

**Stated precisely, because the loose version is false and was written here
first: a pass in which the desired document did not change never arms.**
`reconcile_drift` builds one plan from desired against observed, and a config
delta and a drift delta are indistinguishable inside it -- so a pass caused by a
real edit arms over whatever else that pass also corrected, drift included. That
is not the oscillation above: after such a revert the drift is still there, the
next pass corrects it with no document change and therefore no window, and it
stays corrected. It does mean a window's revert can undo a repair the operator
never asked about, which is worth knowing and is not what "a drift correction
never arms" would lead anybody to expect.

The loop already separates the two: `config_changed` is a distinct signal from
the drift tick. **But it means "the file was written", not "the configuration
changed"**, which is the record's second correction from the same review.
`Command::ConfigChanged` is sent for any inotify event, so an editor writing
identical bytes sets it, and so does a reload that fails to compile and leaves
the desired document untouched. Either on a pass that is also correcting drift
armed a window over the drift correction -- the thing this record says never
happens. Measured with a sysctl, whose drift the kernel announces no event for
and which is therefore still outstanding when the rewrite wakes the loop: a
byte-identical write armed a window over netcfgd putting `forwarding` back.
The document is hashed either side of the reload now, so the exclusion is true
rather than intended.

**And a document saying `confirm = 0` means no window.** The `Some(0)` guard
0094 describes covered only the caller's option, so a zero written in the file
fell through to the document arm and produced `commit.arm { window_seconds: 0 }`
-- a window that arms and expires, which 0094 says in as many words is not a
thing anybody should be able to express. Nothing rejects it at compile time:
`as_u32` accepts any number that fits.

## What was rejected

**Arming on every apply, as `project.md`'s model listing said.** That listing
read "armed on every apply that does not say otherwise", which is what the key
means in the abstract and is unsafe for the two paths above. The listing now
states the rule that is implemented rather than the one that is not.

**Refusing a zero at compile time.** It would be a clearer error, but the value
is legal `u32` and a config that has always compiled would stop compiling. The
planner treating it as "no window" is the same answer 0094 gives the caller's
zero, and it costs nobody a broken file.

**Arming from the plan's effective window in `apply_request` too.** That would
make `ncfg apply --confirm-within` and the document's default converge on one
code path, which is tidier. It is not done here because that path is reached
only when the operator passed the flag -- a plain `ncfg apply` applies locally
in the CLI process and never reaches the daemon at all -- so the change would
be inert. The CLI's own handling of the document default is a separate question
and is left open rather than answered in passing.

## What the surrounding machinery needed first

**A window nobody asked for is not the same object as one an operator armed
and is watching, and four things in commit-confirm had quietly assumed the
second.** None of those four was introduced here: all were latent, rare while
only `--confirm-within` armed a window, and routine the moment a config edit
did. Two further defects belonged to the new arming path itself and were fixed
before it shipped -- they are under *Decision* above, and they went from
impossible to reachable rather than from rare to routine, which is a different
thing and worth not blurring. Six in all. Each was measured, each fixed, and
each has a live case that goes red against the code without its guard.

**A timer resolved whichever window was open, not its own.** `ConfirmExpired`
carries no identity and `revert` never asked whether the window had actually
expired -- `Window::expired` existed and had no caller outside tests, while
`remaining` had exactly one, in `may_arm`'s refusal message. Measured: a window
confirmed at three seconds left its
six-second timer running, a second change armed a window at five, and at six
the first timer reverted the second two seconds into its life, logging "the
window closed unconfirmed" about a window nobody had had time to confirm. This
needed two windows inside one window's length, which is the ordinary
edit-confirm-edit loop once config changes arm.

**An apply served inside a window ate the way back.** The no-window arm of
`apply_request` clears the recorded inverses and overwrites the last-good, with
no check for an open window. Measured with a window open over 10.0.0.2: an
apply served by the daemon
replaced the last-good with 10.0.0.2, and the expiry then found nothing to take
back, re-planned to what was already in effect, and reported a revert that had
reverted nothing.

**The reproduction needs a note, because the obvious way to drive it does not
work on the unfixed code.** `--confirm-within 0` was used, and on the original
daemon that request never reaches this arm at all: `Some(0)` is a `Some`, so
`may_arm` refuses with "already armed" and the apply returns an error before
touching anything. It reaches the no-window arm only once the zero guard above
exists -- which is the build it was measured on. On the original code the arm is
reached by a client sending an apply with no `confirm` member at all, which the
Rust CLI cannot do, since a plain `ncfg apply` never opens the socket.

**`--confirm-within 0` armed a zero-second window.** 0094 makes zero the way to
decline a window on a machine that sets a default, and the planner honours it --
but the daemon armed from the request's number without looking at it. Measured:
it printed "confirm window open for 0s" and four seconds later the interface had
no address at all. The flag documented as the safe way to skip the safety net
was the most destructive thing in the command. The CLI said so too, and now
reports that no window was armed.

**A revert blacklisted whatever was on disk, not what it reverted.**
`state.rejected` stops a reload putting back the configuration that just broke
the machine, and it was taken from `state.desired` at revert time. An operator
editing twice inside one window leaves `desired` holding the *second* edit,
which was deferred, never applied and never at fault. Measured: the window
reverted the first edit and blacklisted the second, so `ncfg reload` answered
"this configuration was reverted away from and has not changed since" about a
configuration that had never been tried -- and the operator's newest work could
not be loaded until they edited the file again.

The window now remembers the hash of the document it covered, beside the
inverses, in one record rather than two fields that must be kept in step. That
grouping is deliberate: two `Option`s set, cleared and consumed at the same
three sites are a second list nothing compels to track the first, which is the
failure this codebase keeps finding in its own walks.

**And the same zero written in a document.** Covered above under the decision.

The shape they share is worth keeping: **each was a correct guard sitting one
layer away from where the value was used.** The planner knew zero meant no
window; the arming site did not ask it. `Window` knew whether it had expired;
the expiry handler did not ask it. `may_arm` knew whether a window was open;
the no-window arm asked nothing at all -- it reads `confirm::read_window`
directly, `may_arm` being a question that also hands back a last-good this
caller has no use for. Making the daemon arm windows on its own did not create
any of the four -- it removed the rarity that was standing in for a check.

## Consequences

An operator who writes `confirm = 90` and edits the config on a machine they are
logged into remotely gets the safety net without remembering a flag, which is
the case commit-confirm exists for and the one where the flag is most likely to
be forgotten.

A machine that never wrote the key arms no window it did not ask for, which is
0094's opt-in half. It is not otherwise unchanged, and the difference matters to
anybody reading that as a scoping statement: the four fixes above are in the
machinery every `--confirm-within` goes through, so a machine that has never
heard of the key still gets a timer that resolves only its own window, an apply
that leaves an open window's record alone, a zero that declines rather than
reverts, and a revert that blacklists what it reverted.

The watcher no longer races an operator's `ncfg apply --confirm-within`: on a
machine that sets the key there is nothing to race, because the change the
watcher applies carries its own window. The race is recorded in `project.md`
10.41.3 and is closed for that case rather than in general.

**The way it is closed is worth stating plainly, because it is not free.**
`may_arm` refuses a second window over the first, so on a machine setting the
key, `ncfg apply --confirm-within 60` in the seconds after an edit is now
answered "a confirm window is already open with Ns left; confirm or revert
first". The habit of editing the file and then running the flag therefore
changes: the flag is for a machine that has not set the key, or for asking for
a different length, and on a machine that has set one the edit already carried
its window. The refusal names the window and its remaining time, which is the
information needed to act, but nothing warned an operator this would change.

**Two things are left as they are, deliberately.** `confirm::confirm_window`
records the desired document as last-good whether or not the apply that ran
under the window failed part-way, where `converge` records one only when the
journal had no failure. The asymmetry is real and arguably correct -- a person
saying "keep this" is a stronger signal than an apply not erroring -- so it is
recorded rather than changed. And `confirm = 0` still compiles and still
renders back, so `ncfg show` reports a key that now means nothing; refusing it
at compile time would break configurations that have always compiled, and a
warning is a change to the diagnostic surface rather than to this decision.
