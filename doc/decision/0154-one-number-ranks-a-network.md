# 0154: one number ranks a network

Status: accepted
Date: 2026-09-02
Milestone: M9; link selection

[0153](0153-a-network-is-ranked-against-a-link-not-against-a-radio.md) added
`metric` and argued at length for keeping `priority` beside it, on the grounds
that they answer different questions: `priority` chooses which network to
*join*, `metric` ranks the routes of the one joined. Both halves of that are
true and the conclusion was still wrong.

## What was wrong with it

The argument establishes that the two *questions* differ. It does not
establish that an operator has two different *answers*, and in practice they
do not: a network you prefer to be on is the network you prefer to join. The
case where they come apart -- join A when both are in range, but rank B above
the cable whenever you happen to be on B -- is one nobody has asked for and
which is hard to state without inventing a scenario for it.

What the split cost was concrete and immediate:

- **Three numbers for one idea**, across two directions. An interface's
  `preference` (lower wins), a network's `priority` (higher wins) and a
  network's `metric` (lower wins).
- **Every explanation was written in terms of another.** The interface
  dialog's tooltip said "opposite way round from a wireless network's
  priority"; the network dialog's said "the opposite of a route metric";
  the C header said a screen showing both "should not imply they order the
  same way". Three pieces of documentation whose job was to apologise for the
  design.
- **The GUI shipped half of it.** 0153's table gained a `metric` column and
  the dialog kept offering only `priority`, so a metric was visible and
  unsettable. That was an oversight rather than an argument, but it is the
  kind of oversight a design with two parallel knobs invites.

The copyright holder asked why priority was still there. This record is the
answer: it should not have been.

## The decision

**A network carries `metric` and nothing else.** Lower wins. It ranks this
network's routes against every other link, and it decides which network to
join when several are in range.

The backends still need a join order and still get one. `netcfgd_model::wifi::join_rank`
derives it -- `RANK_CEILING - metric` -- and both consumers use that one
function: `wpa_supplicant`'s `priority` directly, `NetworkManager`'s
`autoconnect-priority` scaled into its own narrower range.

**Subtracted from a ceiling rather than negated**, because a backend reads a
missing priority as 0 and 0 is a legitimate metric -- the best one. A metric
past the ceiling floors at 0 rather than wrapping, so an absurd number ranks
last instead of first.

**Scaled rather than clamped** into NetworkManager's `-999..999`. Clamping
would map every metric below about 3100 onto the same number, which throws the
ordering away for exactly the networks somebody bothered to rank.

**Shared rather than written twice**, for the reason `network_for` is shared:
two copies of a sign inversion are two chances to get it backwards, and a
wrong one is silent -- the machine simply prefers the wrong network, and
nothing anywhere says so.

## What an existing configuration gets

**Named, not left to "unknown key".** An operator who wrote `priority` had a
working configuration, and the replacement runs the *other way up* -- so the
one thing they must not do is copy the number across. Three places say so: the
compiler diagnostic for `priority` inside a `wifi` block, the CLI's refusal of
`--priority`, and the config example.

A message that only said the key was unknown would leave the inversion to
chance, and getting it wrong is silent in exactly the way this design is meant
to prevent.

## What this costs

The wire format loses a field, so the schema witness is a **major** bump
rather than a minor one. `priority` was in the document, the socket's
`wifi_add` request, the saved-network response, the C client, the GUI, the
NetworkManager adapter and the profile writer.

That is the price of having shipped the wrong shape first, and it is worth
paying now: every configuration carrying `priority` today was written by
somebody in this workspace, and the alternative is carrying two ranking scales
for the life of the project.

## What is deliberately not decided

**Whether an interface's `preference` should also collapse into something
else.** It is already the same scale and the same direction as `metric`, so
there is nothing left to reconcile -- an interface ranks a link, a network
ranks a network, and they compare directly. The confusion this record removes
was between the two *wireless* numbers, not between wired and wireless.
