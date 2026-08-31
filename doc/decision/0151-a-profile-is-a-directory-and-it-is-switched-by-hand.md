# 0151: a profile is a directory, and it is switched by hand

Status: accepted
Date: 2026-08-31
Milestone: M9; a laptop that behaves differently in different places

A machine needs to behave differently by place or preference -- at home, at the
office, travelling -- and until now the only way was editing `conf.d` and
remembering what it used to say.

## A profile is a directory of drop-ins

    /usr/share/netcfgd/profile/<name>/*.conf    shipped
    /etc/netcfgd/profile/<name>/*.conf          the operator's

**No new block syntax.** A profile is read the way `conf.d` is read, layered
the way the factory and runtime directories already layer, and removed with
`rm`. Everything the drop-in model already gives -- precedence, `override`,
provenance, deleting by deleting -- applies unchanged, because it is the same
mechanism pointed at another directory.

The alternative was a `profile "office" { ... }` block containing other blocks,
which is a language change, a nesting rule, and a second way to say what a file
already says.

## Switched by hand, and that is a decision rather than a first step

**Automatic switching is a control loop.** A profile keyed on what the network
looks like, which then changes what the network looks like, is a system that
can oscillate -- and the same tree already carries the evidence: 0119's
hold-down exists because a link alternating on every probe moved the default
route on every tick. A profile switch moves considerably more than a route.

So: chosen by an operator, applied like any other configuration change. If
automatic switching earns its place later it needs a mechanism designed against
that failure rather than a condition bolted to this one.

## The default is no profile, not a profile called "none"

**They are different states and one name for both would be a permanent
confusion.** A machine with hand-written `conf.d` and no selection is not
running a profile; a machine that has chosen the do-nothing profile is. If the
default were spelled `none`, the first machine would appear to be running
something, and "no profile" against "the none profile" would be a distinction
nobody could keep straight in a diagnostic.

So an absent `profile` key is the default, and it means exactly what it says.

## `offline` configures nothing, and is not the same as walking away

The shipped do-nothing profile is called `offline` rather than `none`, for the
reason above.

**What it must not be is `managed = false`.** That hands every interface to
whatever else is running and leaves the machine configured by somebody
netcfgd is not watching -- the opposite of what an operator asking for no
networking wants. `offline` means netcfgd manages everything and configures
nothing: links down, no addresses, no routes.

The two are easy to confuse and the shipped file says which it is.

## A profile switch is the strongest case for the confirm window

Applying `offline` on a machine reached over the network disconnects the person
applying it. netcfgd already has `--confirm` and a revert window, and a profile
switch is the change most likely to need it: it is large, it is deliberate, and
it is exactly the class that cannot be undone remotely once it has taken
effect.

## A profile writes `override`, and that is not a wart

Found by running the thing rather than reasoning about it. A profile
directory is read **after** the base, so a profile that changes an interface
the base already describes writes `override interface eth0 { ... }`; a plain
`interface eth0` is `already defined` and the profile does not load at all.

That is the language working as designed -- redefinition is an error
everywhere else too, and the diagnostic names both files and suggests the
word. It is recorded because it is the first thing an operator writing a
profile will hit, and because it is the opposite of the rule for `global`:
sub-blocks of `global` merge (0147), so a profile setting `dns` writes
`global`, while a profile setting an interface writes `override interface`.
One reads as an exception to the other until you see that the unit differs --
`global` is a singleton whose parts are independent, an interface is a block
that is either this one or that one.

## Changing a setting puts the machine on none, and that is the directive

**Changing a setting by hand puts the machine on "none chosen". A change
netcfgd makes for itself must never move the selection at all.** Those are the
two halves, and they are not symmetrical because the two events are not: one
is somebody saying what they want, the other is a program doing its job.

The first half is the honest record. A profile is a preset; the moment an
operator edits a value they have diverged from it, and a machine that goes on
reporting `office` while running something that is not office is lying in the
place it can least afford to. "None chosen" is exactly the state 0151 already
defines: the machine runs its own configuration. So the edit does not modify
the profile -- it takes the machine off it.

**Nothing about the running configuration changes when that happens.** The
profile's drop-ins are folded into `conf.d` in the same step, as one generated
file, so the effective document before and after is identical; only the label
moves. Anything else would make a one-line edit capable of dropping every
override a profile carried -- a static address, a route, the link the operator
is connected over -- as a side effect of changing something unrelated. **The
fold is proved rather than trusted**: the loader compiles the document before
and after and refuses to write when the two differ, which is the rule for
mechanical changes applied to a change made on somebody's behalf.

The second half is the one that needs a rule at all. netcfgd writes its own
configuration, and a self-driven write clearing the selection would be a
profile switch nobody asked for, arriving through a change made for an
unrelated reason -- the hardest kind of fault to attribute afterwards. So the
line is drawn at the actor, not at the file: **a person's settings write
clears the selection; netcfgd's own writes leave it exactly where it was.**

The hazard the guard catches is the third case, which is neither: `override
global` replaces the whole block, so a hand-written file adding a search
domain silently discards `profile` along with everything else in there. That
is not an operator taking themselves off a profile, it is an accident, and it
is refused with the file named and `global` suggested instead (0147).

## A profile is written by one command and no other

**Nothing writes into `profile/` except `ncfg profile save`.** Not a settings
edit, not the gui, not the shim, not the daemon. A profile may be carefully
crafted -- ordered drop-ins, comments, overrides that took an afternoon to get
right -- and there is no way to recover that from the running state once
something has helpfully rewritten it.

So the workflow is three explicit steps, and the middle one is where the work
happens:

    ncfg profile set office      # run it
    ...change settings...        # now on none chosen; office is folded in
    ncfg profile save office     # write what is running back, and select it

`save` is the only door into the directory, it names the profile it writes,
and it refuses to overwrite an existing one without being told to. Selecting
afterwards is part of the same act: having just said "this is what office
means", being left on none would be a surprise.

**`save` is not implemented yet.** Saving must be exact, and the only exact
form is the effective document rendered back as config text -- which needs a
document-to-DSL renderer netcfgd does not have. Every writer here renders one
block it knows about; nothing renders a whole document. That work belongs
beside the parser in `netcfgd-compile` so the two cannot drift, and its gate
is render-then-reparse-then-compare, because a renderer that silently drops a
field is worse than none: the field is gone from a profile nobody will read
again until they need it.

Until then a profile is written by hand, which is the case this record was
protecting anyway. Nothing about the directive waits on it: the machine still
comes off its profile when a setting changes, and still never comes off it on
its own.

## A profile writes `override`, and that is not a wart

Found by running the thing rather than reasoning about it. A profile
directory is read **after** the base, so a profile that changes an interface
the base already describes writes `override interface eth0 { ... }`; a plain
`interface eth0` is `already defined` and the profile does not load at all.

That is the language working as designed -- redefinition is an error
everywhere else too, and the diagnostic names both files and suggests the
word. It is recorded because it is the first thing an operator writing a
profile will hit, and because it is the opposite of the rule for `global`:
sub-blocks of `global` merge (0147), so a profile setting `dns` writes
`global`, while a profile setting an interface writes `override interface`.
One reads as an exception to the other until you see that the unit differs --
`global` is a singleton whose parts are independent, an interface is a block
that is either this one or that one.

## Nothing netcfgd writes may change the profile

**A directive, and it covers the daemon's own writes.** netcfgd writes
configuration itself -- `ncfg wifi add`, `ncfg control set`, the gui's dns tab
and network editor, the NM shim -- and **none of them may add, change or remove
the profile selection.** Only an operator asking for it may, through
`ncfg profile set` or by editing the file.

The hazard is not hypothetical and 0147 already names its shape: `override
global` replaces the block entirely, so a writer emitting `override global {
control { ... } }` would silently discard a `dns` block -- and would equally
discard `profile`. A machine would then fall back to no profile, which is a
different configuration, with nothing on screen to say why. That is a
self-driven switch to "none" in everything but name.

Two things follow, and both are mechanical rather than a matter of care:

- **Writers emit their own sub-block and never `override global`.** Since 0147
  distinct sub-blocks merge, so `global { control { ... } }` from one file and
  `global { profile = "x" }` from another coexist. Nothing needs to know about
  anything else.
- **`ncfg profile` owns exactly one drop-in** and writes nothing else into it.
  A command that wrote the profile alongside something else would make the two
  impossible to change independently.

**Why this is a directive rather than an observation.** A profile decides what
the whole machine does; losing the selection is not a small drift, it is a
different machine. And the change would arrive through a write somebody made
for an unrelated reason -- adding a wifi network, opening a tier to a group --
which is the hardest kind of fault to attribute afterwards.

## Finding the name costs a compile, and the loop is refused

The selector is `global { profile = "office" }`, in the configuration language
rather than a bare file beside it, so there is one language and one authority.
That means the base configuration is compiled once to learn the name before the
profile's own files are read -- with hooks disabled, because that first compile
is a question and not an application.

**A profile that names a profile is refused.** Allowing it would be a loader
that loads until it stops changing its mind, which is the same shape as the
automatic switching this record already declined.
