# 0147: global is a singleton several writers contribute to

Status: accepted
Date: 2026-08-29
Milestone: M8; the gui, which met it first

Qualifies the drop-in rule set out in
[0069](0069-adding-a-network-is-writing-a-file.md) and
[0030](0030-a-gui-is-an-editor-of-config-files.md), which is right for
collections and has no answer for a singleton.

## The failure

A gui that could set the dns mode was written, tested, and did not work on the
machine that asked for it:

    `global` is already defined
      help: first defined at conf.d/00-control.conf:10; write `override global`

`ncfg control set` had written `global { control { ... } }` into its own
drop-in, which is what every writer here does. The dns tab wrote
`global { dns { ... } }` into another, and two files may not define one block.

**The machine's own tooling created the state that made the documented
configuration impossible.** Any machine that has ever run `ncfg control set` --
which is any machine that has opened a tier to a group -- could not afterwards
add anything to `global` as a drop-in.

## Why the existing answers do not answer

**`override` is worse than the error.** It replaces the block entirely, and
`netcfgd.conf.example` already names this exact case: an `override global`
carrying only a `control` block "silently discards the `dns` block the file it
replaced was carrying, and takes name resolution away from the machine in order
to change who may open a socket".

**"Edit the block where it lives" is the example's advice and it is right for a
person.** It is not available to a program: the gui would have to read, parse
and rewrite a file `ncfg control set` also owns, and two tools owning one file
is the arrangement drop-ins exist to avoid.

**One file owning `global`** would work and makes every writer share it, which
is the same problem with fewer files.

## Decision

**Distinct contributions to `global` combine. A genuine collision is still an
error.**

Two files each naming a *different* sub-block -- `control` and `dns` -- produce
one `global` holding both. Two files both naming `dns` get the error any
duplicate gets, because that is two files disagreeing about one setting, which
is what `override` is for. A scalar directly in `global`, `confirm_default`
say, takes the language's existing rule: later wins for a single key.

**Only `global`.** `interface eth0` in two files is still an error, and must
stay one: an interface is a collection member, each file that names one is
claiming the whole thing, and merging them would make the result depend on
which keys each happened to set. `global` is different in kind -- it is the one
block that is not a member of anything, holding several settings that have
nothing to do with each other.

## Why this shape rather than a general merge

The rule the language already states is "later files win for a single key, and
a redefined block is an error". This extends the first half to the one block
where independent writers legitimately meet, and leaves the second half intact
everywhere it was doing work. A general block merge would remove the property
that makes drop-ins predictable, to solve a problem exactly one block has.

## What it does not fix

`ncfg control set` and the gui still write different files, so nothing here
makes them agree about *content* -- only about coexisting. Two tools that both
decided to write a `dns` block would still collide, correctly.
