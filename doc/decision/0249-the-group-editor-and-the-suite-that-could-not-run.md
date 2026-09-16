# 0249: the group editor, and the suite that could not run

Status: accepted
Date: 2026-09-16
Milestone: M9; the linkset, in the window

## What 0248 left

A linkset could be written, compiled, chosen and acted on, and the only way to
make one was to write the block by hand. The links tab showed a group as a row
and refused to open an editor for it, because there was none. That is the state
every feature in this program has had to be rescued from in turn.

## The editor

`ncfg_linkset_dialog`: a name, an ordered member list with add, remove, up and
down, and a delete for a group that exists. It writes `linkset-<name>` through
`ConfigPut` exactly as the interface and network editors write theirs.

**The order is the ranking**, so nothing sorts the list and the two buttons that
move a member are the only edit a group really has. `ncfg_linkset_block` is a
free function for that reason: what it produces is configuration text, and both
ways it can be wrong -- a reordered list, a name that ends the string it is
written into -- are invisible in a screenshot.

**The name rule is narrower than "any string"**, and it is checked here as well
as by the daemon: a group is referred to by name from other groups and is
written to a file called after it, so a space, a quote, a backslash or a slash
is refused with a sentence rather than a greyed button. The daemon would refuse
it too, but a dialog that leans on that has already composed a filename out of
the text.

**The standing is shown beside each member** -- `in use on wlan0`, `no carrier`,
`unjoined` -- and it is netcfgd's answer rather than this window's. Working it
out here would be a second opinion about a failover, which is the thing 0248
exists to prevent.

In the table itself a group's row says `using <member>` where every other row
says what the kernel reports, because a group is not a kernel device and has no
state of its own; `why` on a group names the members that lost, since "why am I
on the modem" is answered by what is wrong with everything better.

## The suite that could not run

**`make live` has never once run the GUI's live probes on this machine.**
`gui_wifi.sh` builds the C client before it starts, and under `unshare -rn` as
root every file in the tree belongs to an unmapped user -- so the build is
refused with `cannot create .build-flags.candidate: Permission denied`, and the
script skipped on it. Every run since the script was written reported
`skipping: the C client will not build` and exited 0.

The build now happens in the Makefile, outside the namespace, and the script
checks the artifacts instead of the build's exit status. Running them turned up
three things, none of which is a linkset:

* **A probe that depended on another probe.** `live_wifi` asserted that
  forgetting one network left the saved list non-empty, on the strength of
  `HomeFiber` -- which `live_add_dialog.cpp` adds, a different program against
  the same daemon. Its own comment three lines above says to name the network
  rather than count them. It now adds a second one of its own and names it.

* **Two assertions about a banner that were really about a claim.**
  `live_wifi` checked that the contention banner was *hidden* when no other
  manager held the radio. The banner carries whatever the planner warns about
  that radio, so those checks passed alone and failed in the suite. They now
  assert what they are about: that the text does not name NetworkManager.

* **A real defect in the window, which is why this is worth the space.** The
  banner took the *first* warning for the radio and stopped. On a machine with
  anything else to say -- a configured network and no supplicant running is
  enough -- the claim this banner exists for was hidden behind an unrelated
  line, and the one message that explains every other thing on the tab
  behaving oddly was the one an operator could not see. It now shows every
  warning about that radio.

**And one of my own, found the same way.** The new probe grouped whatever links
it found, which on a shared daemon meant the radio the next probe activates --
so `live_wifi` failed four checks about somebody else's leftovers. It now writes
two `interface` blocks of its own, groups those, and removes all three.
`live_interface_dialog.cpp` records the identical hazard and answers it the same
way, which is the part worth noticing: the file next door had already paid for
this lesson and the probe was written without reading it.

## Six sabotages, all caught

The member list sorted on its way to the file; every name accepted; a group with
nothing usable drawing a blank cell; the explanation listing the winner and the
ready members rather than the ones that lost; moving a member down doing
nothing; the block written without replacing the old one.

The last two are caught only by the live probe, which is the argument for having
one: both produce a dialog that looks right and a machine that fails over the
other way round.
