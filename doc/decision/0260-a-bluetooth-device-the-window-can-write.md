# 0260: a bluetooth device the window can write

Status: accepted
Date: 2026-09-18
Milestone: M9; the window can configure the machine

## The block, and what the window could do with it

A `bluetooth` block is a device declared like a network (0149): a handle the
operator chose, with the address as the fact about the hardware, so that
replacing the headphones is one line rather than every mention of them. The
window could list them and nothing more.

It has `view / change` and `new device...` now, like every other list this
milestone has taken in hand. The form is four fields -- name, address, what the
machine uses the device for, and whether to connect it unasked -- and the
profile is a list because the language's set is closed: five names, and the
compiler refuses anything else, so free text would be a round trip to learn
that.

## An address arrives in three forms and the language takes one

`normalise_address` accepts six colon-separated hex octets and uppercases them.
A person arrives with `aa-bb-cc-dd-ee-ff`, which is how a label usually prints
one, or with twelve bare digits, which is what `bluetoothctl` output looks like
once it has been through a clipboard. The editor takes all three and writes the
form the compiler asked for; what it must not do is pass something through and
call it saved, so anything that is not twelve hex digits is refused beside the
field rather than at a line number in a file the operator did not write.

## Saying what the daemon will not do

**This build does not act on a `bluetooth` block at all.** The planner warns per
device: nothing pairs a device, connects it, or brings a `pan` link up. The
block is kept so a configuration written now still means this when the backends
arrive, which is the same disposition 0061 reaches for every other understood
and unapplied field.

An editor that wrote one without saying so would be the window claiming
something the daemon does not do, so the outcome line says it in the planner's
own words. Two things say it now that did not before:

* **The empty-state note under the table said the opposite.** *"A device is
  declared like a network and netcfgd pairs and connects it."* That is the one
  sentence somebody reads before there is anything in the table, and it
  described a feature that does not exist. Both notes now say what the planner
  says.
* **The dialog says what the profile implies**, which the planner cannot: an
  audio profile carries sound, which is `bluealsa`'s business and not
  netcfgd's; a `pan` or `nap` device produces a `bnep` link when it connects,
  and a link needs an `interface` block or it comes up with no address. Which
  sentence applies depends on a choice made a moment ago in this window.

## The manual had never mentioned it

`doc/netcfgd.conf.example` calls itself "every feature, with the syntax to use
it", the postinst points an operator at it as the thing to read on a machine
with no network -- and it contained the word `bluetooth` **zero times**. The
block has been in the language since 0149.

`tool/example_gate.py` compiles every block in that file, which cannot notice a
block that is not there. It now also reads the top-level block heads out of
`lower.rs` -- from the compiler, not a second list that would go stale in the
direction of passing -- and requires each to appear in the file. Eight heads,
all documented, and the extraction refuses to pass if it reads fewer than six.

## Six sabotages, all caught

The address written as typed; the address left in the case it was typed;
`autoconnect` stated when it is the default; the profile written the model's
way rather than the language's; the editor not loading what was written; and
the outcome line losing the sentence about the block not being acted on.

The fifth passed at first. Every other assertion in the live probe sets a field
before saving, so a dialog that loaded nothing and sat at its defaults would
satisfy them all -- **the only value that proves a load is one that differs
from the default**, and `autoconnect` is the one field in this block where that
is possible. The probe now turns it off, saves, re-opens, and asserts the box
comes back off.
