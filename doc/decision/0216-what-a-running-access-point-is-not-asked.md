# 0216: what a running access point is not asked

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi hostapd and access point audit

Two findings, both about the gap between the file netcfgd writes and what
anybody checks afterwards.

## The mode was guaranteed on the first write and on no other

The generated hostapd configuration holds the passphrase in clear -- hostapd
has no indirection for one -- so it is opened 0600, with this reasoning:

> Truncate through `OpenOptions` rather than `fs::write` plus a chmod: the
> window between the two is a window in which the passphrase is readable by
> everybody, and a mode set afterwards is a mode that was wrong once.

The reasoning is right and the mechanism does not do it. **`open(2)`'s mode
argument applies when `O_CREAT` actually creates the file and is ignored
otherwise**, so rewriting a file that already exists keeps whatever mode it
already had. Measured directly: a file left at 0644 stays 0644 through exactly
this call, and the passphrase is written into it.

"It cannot already exist" is not true either. `/run` survives a restart by
design -- `RuntimeDirectoryPreserve=restart` in the unit -- and this code
replaced a version that used `fs::write`, which creates 0644.

Corrected with `fchmod` on the **open handle**, before a byte is written, so
there is no moment when the secret sits in a file anybody can read. That is the
property the paragraph was always about; it now holds on the second write as
well as the first. The test widens an existing file to 0644 deliberately,
because asserting only the first write would pass against the code it exists to
fail.

## Three fields of a running access point were never compared

hostapd reads its configuration once (0026), so anything netcfgd changes in the
file reaches the radio only on a restart. `restart_if_identity_changed`
compares the document against what the observation reads back out of that file
-- and `ObservedAccessPoint` carried `ssid`, `band` and `channel` and nothing
else.

So three fields of the document were silently inert once an access point was
running:

- **`proto`** -- the WPA generation. A document edited from `wpa2` to `wpa3`
  planned nothing, and hostapd went on offering WPA2. The passphrase
  comparison beside it says nothing about this: changing the generation with
  the same passphrase changes no secret. A radio advertising a weaker
  generation than the document asks for, with `ncfg plan` reporting nothing to
  do, is the one disagreement here that costs more than a restart.
- **`hidden`** -- `ignore_broadcast_ssid`.
- **`regdom`** -- `country_code`.

All three are now observed and compared, and a changed generation restarts the
access point with the warning the other restarts already carry: every station
associated with it is deauthenticated and reconnects.

## The comparison that must not be too eager

Getting this wrong in the other direction is worse than leaving it out, and the
`channel` arm records what that cost: an absent channel is `channel=0` in the
file, comparing that against the document's `None` was true on every pass, and
the access point was stopped and started on every reconcile -- "a permanent
deauthentication loop for a document nobody has touched".

Each new field therefore has its absent-value answer written down. `hidden` and
the key management are written only when they apply, so absence in the file
means the same as absence in the document. **`regdom` is the one that would
have looped**: the renderer uppercases it, so a document saying `"se"` and a
file saying `SE` are the same access point, and the comparison uppercases
before comparing.

`key_mgmt_of` lives in `netcfgd-model` beside `Security` rather than in the
backend, for two reasons: the planner must not depend on a backend crate to ask
what generation a document names, and one definition cannot drift from itself
the way two copies of the mapping could -- a drift that would look exactly like
an access point restarting on every reconcile.

## The test that would have caught the original

The plan fixtures build the observed side **from the document**, which is why
they could not see the `channel` defect and did not see these: a field the
renderer spells differently from the document compares unequal for ever, and
the harness spells both the same way by construction.

So the round trip is asserted where it can be: `netcfgd-observe` writes a real
configuration through the renderer and reads it back with `started_with`,
field by field, including a `regdom` given in lower case. A second test pins
the absences -- an open access point has no key management, an unhidden one
writes no `ignore_broadcast_ssid`, and `channel=0` reads back as hostapd having
been told to choose.

Adding the three fields made three existing fixtures fail immediately, which is
the harness doing its job: they were planning a restart on every pass because
the fixture left the new fields at their defaults. That is the loop above,
caught before it shipped rather than after.
