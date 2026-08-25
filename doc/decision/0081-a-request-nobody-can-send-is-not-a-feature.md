# 0081: a request nobody can send is not a feature

Status: accepted
Date: 2026-08-04
Milestone: M2, closing a gap found while building the GUI's event pane

## Context

`Request::Reload` has been in the protocol since M2. It is in
`crates/netcfgd-proto`, it is pinned in `doc/schema/socket.json` line 7, it has
an authorisation tier (`Tier::Admin`, with three tests in `authorize.rs`), and
the daemon has handled it since the socket existed.

No shipped client could send it.

This was found while measuring what a monitor stream actually carries, for the
GUI's events pane. Building a scenario that produces a `reloaded` event meant
changing the config after the daemon was up, and the obvious way to make that
happen was `ncfg reload`:

```
$ ncfg reload
ncfg: unknown command `reload`; try `ncfg --help`
```

The daemon watches the config directory by inotify and reloads by itself, so
nothing was broken. What was missing is the *answer*: an operator who edits a
config and gets it wrong is told so in the daemon's log, and the person holding
the editor is told nothing at all. That is the shape of every "I changed it and
nothing happened" report.

It is also the only recourse when the watch is not watching what the operator
thinks it is -- a file replaced through a bind mount, a config directory on a
filesystem that does not report changes. Asking is then the only way to know.

## Decision

**`ncfg reload` exists, and it reports whether the configuration compiled.**

Exit 0 and `reloaded; the configuration compiles`, or exit 1 and the daemon's
own diagnostics, which name a file and a line. Non-zero for a config that does
not compile even though the last good state is still in effect (design section
17): the file on disk is not what is running, and a script must not read that as
success.

## What exposing it found

The daemon's answer to `reload` was read from the wrong place.

```rust
let event = state.reload();
server::broadcast(subscribers, &event);
match &state.diagnostics {
    Some(diagnostics) => Response::error(diagnostics.clone()),
    None => Response::Ok,
}
```

`State::reload` ends three ways and only two of them set `diagnostics`. The
third is `State::rejected`, a rule that lives in a code comment and in no
decision record: a configuration a revert rejected is refused until it is
edited, so that a reload cannot quietly undo the revert. It refuses by returning
an event and leaves `state.diagnostics` untouched -- which is correct, because a
refusal is not a compile error. So the socket answered
`ok` for a reload that did not happen, and where an earlier reload had failed to
compile it answered with *that* failure's text.

Measured, with the original handler restored, against a real daemon in a
namespace:

```
=== 4. a config a revert rejected -- the case that used to answer ok ===
reloaded; the configuration compiles
exit=0 -- WRONG, it was refused
```

and with the fix:

```
=== 4. a config a revert rejected -- the case that used to answer ok ===
ncfg: this configuration was reverted away from and has not changed since; edit it to try again
exit=1
```

Cases 1 to 3 -- compiles, does not compile, fixed again -- are byte-identical
either way. The bug lived entirely in the case no client could reach, which is
why nothing had ever seen it.

The fix is `state::reload_answer(&event)`: **the event is the answer**. It is
the only complete account of a reload, it is what subscribers get, and there
should not be a second account for the asker to get a different answer from.
It is the same rule
[0078](0078-a-record-is-a-memory-and-a-process-is-a-fact.md) reached from the
other side: two accounts of one thing is how the two come to disagree, and the
one nobody reads is the one that goes wrong.

## The gate

Two, and both were made to fail before being believed.

`state::tests::a_rejected_configuration_refuses_without_setting_diagnostics`
drives a real `State` through compile, reject, recompile and asserts the
disagreement itself -- that the event says `ok: false` while `diagnostics` is
`None`. It is written as a pin rather than as a bug report, because the
disagreement is legitimate: `reload` is right not to record a rejection as a
diagnostic. What was wrong was reading the field.

`tests::every_command_in_the_help_text_is_dispatched` compares the two lists
that had drifted. It catches a name in the help with no arm behind it; it does
not catch the direction this decision is about, and says so. Removing the
`reload` arm turns it red, and so does reformatting the help text out from under
it.

## What this does not do

The reverse gate -- every request the protocol defines has some way for an
operator to send it -- is not written. It wants a list of what is deliberately
socket-only (`hello` is not a command and should not be), and that list is a
judgement rather than an enumeration. Recorded as open rather than pretended
away.

`ncfg reset` still leaves the daemon to notice by itself. It is a config edit
and the inotify path is the right one; a reset that also asked would be a second
way to do one thing.
