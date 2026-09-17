# 0257: the rule that says what a route cannot

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## What the window could only watch

A route says where a packet goes. A **rule** says which set of routes is
consulted in the first place, which is what multi-homing, split tunnelling and
per-mark routing are all answers to. The block has been the model's since 0018,
the window has listed rules since the tab existed, and writing one meant
`ncfg config edit` and knowing the syntax.

So the rules tab has `view / change` and `new rule...` behind it, like every
other list this milestone has taken in hand.

## The priority is asked for, not invented

The kernel identifies a rule by its priority -- it is when the rule is
consulted -- so the form asks for one and defaults it to 1000 rather than
letting the kernel assign. That is the model's own reasoning (`RoutingRule::
priority` is mandatory for it), and it is why two rules at one priority is a
question for the operator rather than something a form quietly renumbers.

## Zero is a value, and `none` is not zero

Three fields here are numbers where the absent case is not zero:

* `fwmark = 0` is a rule matching an unmarked packet. Legal, unusual, and a
  form that could not write it would widen the rule to match everything.
* `suppress_prefixlength = 0` ignores a table's default route so a more
  specific rule below can catch the traffic -- the commonest use of the key.
* `fwmask` has the same shape.

So the client reads all three with `-1` for absent rather than `0`, the spin
boxes start at `-1` with a special text (`any`, `all bits`, `off`), and the
block writer tests `>= 0` rather than truthiness. Three of this round's
sabotages are that one distinction, and each was caught.

## Two things the list had been showing wrongly

**The selector column was blank for any rule that matched on a mark.** The
phrase was built from the address and interface selectors alone, so
`from all fwmark 0x1 lookup 100` -- the commonest shape there is -- rendered as
an empty cell, which reads as *matches everything* and is the opposite of what
it does. It now carries `fwmark 0x1/0xff` in hex, as `ip rule` prints it, and
`l3mdev`.

**The table column was blank for every rule that has ever been listed.** The
document holds a table as a number and the client read it with `member_text`,
which returns the empty string for a number -- indistinguishable from a key
that is not there. A blank table cell reads as "the main one", which is the
single thing it never means. `member_number_text` reads it as what it is; an
absent key stays empty, which for an action that consults no table is honest.

Nothing could see either: both are a field that is *there* and renders as
nothing, and no test asserted the cell's content. The live probe found the
second by asking the daemon what it had compiled, which is the only reader in
the tree that would have.

## `invert` is not offered, and the count was wrong

`RoutingRule::invert` is in the model and the executor applies it --
`FIB_RULE_INVERT` goes on the netlink message and the kernel reader reads it
back. The configuration language has **no key for it**: `rule x { invert =
true }` is "unknown rule key". So a form offering it would write a block
netcfgd refuses, and it is left out.

That makes it a **seventh** field the language cannot reach, where `project.md`
had six -- `DnsPolicy`'s `options`, `dnssec` and `transport`, `DnsServer`'s
`port` and `sni`, and `Device`'s `match`. The count is corrected in both places
it appears. Giving the parser a key is a decision about the language and about
a witnessed schema, so it stays recorded rather than quietly added -- which is
the same disposition 0061 and the profile-renderer audit reached for the other
six.

## The harness left a link behind

`gui_wifi.sh` creates a dummy `radio0` and never removed it. Under `make live`
the whole script runs inside `unshare -rn`, so the link goes with the namespace
and for a year nothing missed it. Run by hand -- which is how a probe gets
debugged -- it stays behind, and the **next** run then fails to create it and
skips the entire GUI suite, reporting success exactly as loudly as a run that
executed. That happened here, between writing this round's probe and running
it. The trap deletes the link it made, and the skip message names the leftover.

## Six sabotages, all caught

A mark of zero treated as absent; a suppression of zero treated as off; the
table written beside an action that consults none; the dialog's refusal of a
mask with no mark removed; the table read as text again; the editor not loading
the selector it had written.

The fourth is the one worth naming: the compiler refuses `fwmask` without
`fwmark` too, so deleting the dialog's check still fails the save -- with the
daemon's sentence, after a round trip, about the configuration not compiling.
The probe asserts the dialog's own words, which is the only way a refusal test
can say **whose** refusal it is. That distinction has now cost this campaign
two vacuous assertions and is the reason this one is written the way it is.
