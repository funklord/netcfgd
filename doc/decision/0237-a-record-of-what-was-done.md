# 0237: a record of what was done

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi supplicant restart and recovery audit

## What was sound

An adopted supplicant -- one netcfgd found running and did not populate -- has no
record, and the observer treats that as a reason to act rather than a reason to
shrug: "0015's whole premise is that the supplicant holds no state of its own, so
a set netcfgd cannot account for is a set that should be replaced with the
document's". A supplicant that is gone is noticed, because its control socket is,
and netcfgd starts one and populates it.

The hole is between those two. A supplicant that is **still reachable and no
longer holds anything** is neither absent nor unaccounted for.

## The record cannot see what happened afterwards

`supplicant_networks_match` compares a digest of what netcfgd recorded handing
over against a digest of what the document would produce now. Neither side asks
the supplicant. The comment says why -- `LIST_NETWORKS` returns ids and SSIDs, a
passphrase is write-only, so it cannot confirm the set -- and that is true and is
not the whole question.

It cannot confirm a set. It can refute one.

Measured against wpa_supplicant 2.10 on the `none` driver, so no radio was
involved:

```text
add_network / set_network / enable_network
LIST_NETWORKS  ->  0  probe  any
RECONFIGURE    ->  OK
LIST_NETWORKS  ->  (empty)
PING           ->  PONG
```

`RECONFIGURE` makes the supplicant re-read its configuration file, and the file
netcfgd writes names no networks -- every network netcfgd holds was added over
the control socket. So one command empties it, and it stays reachable. The
record still holds the digest, the document still hashes to the same digest,
the comparison returns "matches", and nothing acts.

**The machine has no wifi and netcfgd reports it as fine.** That is the
campaign's recurring shape once more: a record of what netcfgd *did*, used as a
statement about what *is*.

`REMOVE_NETWORK all` does the same more directly, and so does anything that
restarts the supplicant without netcfgd noticing.

## Emptiness, not a count

The observer already opens a connection for this pass -- its own comment says
"this is the one pass that has both the document and a connection" -- and makes
another round trip immediately afterwards. So `LIST_NETWORKS` costs one more
command on a connection that already exists, which is why this does not run into
the objection that rejected "a `STATUS` round trip per radio on every netlink
event".

What it asks is deliberately coarse: **none at all, where the document asks for
some.** That is the refutation which cannot be argued with, and it cannot loop --
repopulating adds networks, so the next pass sees a non-zero count and the
digest decides as before.

A count comparison would be finer and would also have to be right about every
case where the two legitimately differ. Being wrong there is a supplicant
repopulated on every pass, which is the restart loop 0222 records having had
twice, from two directions. Not worth it for the extra case.

## What is still not caught

A population that failed part-way leaves some networks behind, so emptiness does
not see it -- and the record is not written on failure, so the *previous* record
remains. If that previous record happens to match the current document, netcfgd
believes a half-populated supplicant is correct.

Recorded rather than fixed. Closing it means either a count that is right about
every legitimate difference, or recording the count alongside the digest and
comparing both, and the second is the better shape if it is ever wanted.

## Not tested on the reporting machine, deliberately

The mechanism was established on a throwaway supplicant with the `none` driver.
Running `RECONFIGURE` against the machine's own radio would have demonstrated it
end to end -- and, before this fix, would have left that machine without wifi
until somebody noticed, which is the fault itself. Afterwards it would recover,
but the recovery is a reassociation and the machine belongs to somebody who is
using it.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| the refutation never fires | `an_emptied_supplicant_is_refuted_...` | FAILED |
| it fires when nothing was asked for | `an_emptied_supplicant_is_refuted_...` | FAILED |
| it judges a count mismatch | `an_emptied_supplicant_is_refuted_...` | FAILED |

The second and third are the ones worth having. Firing on an empty document
would repopulate a radio with no networks for ever, and judging a count is the
loop 0222 found twice.
