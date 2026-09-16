# 0247: a radio and the network on it are one row

Status: accepted
Date: 2026-09-16
Milestone: M9; the links view, third pass

## The complaint

The links tab drew `wlp0s20f3` and `OpenPC.se` as two rows. One carried the
state, the addresses, the MTU and the MAC and said nothing about what the
machine was connected to; the other said `present` and `yes` and carried
nothing else. Every fact about one connection, split across two lines, with no
column saying they were the same thing.

That is the kernel's shape, not an operator's. The kernel keeps a link table
and knows nothing about networks; wpa_supplicant keeps networks and does not
own the link. netcfgd already joins the two -- `ObservedLink::network` is the
document's network id, resolved from the SSID and BSSID at observation time --
and the list was rendering both halves of the join instead of the join.

## The rule

**A radio carrying a configured network gets no row of its own. The network's
row is the row, and it names the radio.**

`Entry` gained two fields. `subject` says whether a row is an `interface` block
or a `network` block. `carrier` names the interface a network is running on,
and is absent for everything else -- an interface carries itself, and a network
nothing has joined is carried by nothing.

**Only when the network is one the document describes.** A radio joined to
something nobody configured keeps its own row, because there is no other row
for it to hide behind:

```quote from=crates/netcfgd-model/src/observed.rs
None for a wired link, for a radio that is not associated, and for one
associated to a network the document does not describe -- which is a real
state and not an error, since an operator may join something by hand.
```

So `link.network.is_some()` is exactly the condition under which a second row
exists to merge into, and the skip tests that and nothing else.

## The bug the union had already introduced

Found by clicking rather than by reading, which is worth saying: the union
landed in 0246 and this was in it from the first build.

The list holds two kinds of block and `configure` opened `ncfg_interface_dialog`
for whatever was in the first column. Selecting `OpenPC.se` therefore offered to
set the MTU and the addressing of an interface by that name, and there is no
such interface. A wifi network's editor is a different dialog with different
fields -- SSID, security, credential -- reached from the wifi tab and from
nowhere else.

`subject` is what fixes it, and the decision is a free function rather than a
branch inside the slot:

    QString ncfg_link_subject(const QList<ncfg_inventory_row> &rows,
                              const QString &name);

Beside `ncfg_link_shows` and for the same reason -- it can be checked without a
daemon, a window or a row, and both of its wrong answers are invisible in a
screenshot. **It defaults to `interface` in two cases and they are the same
case**: a row whose `subject` the daemon did not fill, which is a daemon older
than this window, and a row that is not in the inventory at all, which is what
the list holds when the daemon gave no inventory and it fell back to the
kernel's links. Every one of those is an interface. Defaulting the other way
would offer a network editor for `eth0`.

## The column

`network` left the table and `device` took its place. For a network row the old
column would have repeated the first one -- the row *is* the network -- and the
new one answers the question the merge raises: which hardware is this running
on. For an interface row it is blank, because an interface carries itself.

The detail on a network row is borrowed from its carrier: state, addresses, MTU
and MAC all belong to the radio, while the connection they describe is the
network. That join is one line in the view and it is the whole of what the
merge costs the rendering.

The first column is headed `link` rather than `interface` for the same reason:
it holds both kinds of block now, and `interface` over a row called `OpenPC.se`
is the two-row list's confusion moved into the heading.

A daemon that reports no inventory still gets the kernel's links, now with a
blank `device` column. That is less than it said before and nothing it says is
wrong; the old shape put the network on the radio's row, which is precisely the
shape this replaced.

## Five sabotages, all caught

The carrying radio keeping its row; every associated radio hiding rather than
only a configured one; `carrier` never filled; `subject` defaulting to
`network`; an empty `subject` returned as itself instead of falling through.

**Two of them passed on the first run, against a stale binary.** `make -C gui`
builds the program and not the probes -- `make -C gui test` builds those -- so
the two C++ sabotages ran the previous executable and reported a pass. Nothing
about the output said so. What caught it was that both GUI sabotages passed
while all three Rust ones failed, which is not a plausible split.

The lesson is `evidence.md`'s and this is the second time this campaign has
paid for it: **a passing check is evidence only once you know what it
inspected.** A sabotage pass proves the tests can fail; it proves nothing at
all if the tests did not run.
