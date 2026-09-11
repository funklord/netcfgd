# 0214: one network by BSSID voided the record

Status: accepted
Date: 2026-09-11
Milestone: M9; the wifi roaming and BSSID audit

## The record, and why it exists

A supplicant cannot be asked what it holds -- `LIST_NETWORKS` returns ids and
SSIDs, and a passphrase is write-only by design -- so netcfgd answers "does the
running supplicant still match the document?" by recording a digest of what it
handed over and comparing it against a digest of what the document says now.

`kernel.rs` says what the absence of that record costs, from a measurement:

> Changing a passphrase, pinning a bssid, adding a network or deleting one all
> planned nothing, measured, and the supplicant kept the original credentials
> indefinitely.

## One network with no SSID turned it off for the radio

`fingerprint` began each network with `network.ssid.as_ref()?` -- and the `?` is
on an `Option` in a function returning `Option<String>`, so **any** network
without a stated SSID returned `None` for the whole list. `record_networks`
then *removes* the record file: "nothing to compare against later, so leave no
claim behind."

A network with no SSID is not an error. The model documents it as supported:
`ssid` may be absent where `bssid` names the access points, and netcfgd reads
the name off a scan. That is the BSSID-keyed configuration this project keeps
for forced-AP roaming of the pre-802.11k/v/r kind.

So a document with one such network left its radio with no record at all, and
the defect the record exists to prevent came back for **every network on that
radio** -- silently, and permanently, because nothing ever resolves the
document's `ssid: None` back into the executor's copy. `add_network` resolves
it on a local clone that never returns.

## The reason given was true about something else

This was not an oversight. It was documented:

> **`None` when any network's SSID is not stated in the document.** [...] a
> digest that guessed would differ from the recorded one on every pass and
> re-send the whole set for ever.

That is correct about guessing the *scanned* name, and it is not what the
alternative requires. Both callers digest the same value -- the executor's set
is `clone_from(&document.networks)` and the observation reads
`document.networks` -- and **neither has ever seen a scan**. A stand-in that is
the same on both sides compares equal on the next pass, which is the whole of
the loop that was feared.

**This is the session's recurring shape once more**: a true statement about one
approach, used as a verdict about the whole question. The cost of the verdict
was written down in a different file, and the record that made the decision
does not mention it.

## What it does now

A network whose SSID comes from a scan is rendered against a fixed stand-in,
preceded by a marker line so it cannot collide with a network an operator
genuinely named that. Everything else about it reaches the digest -- its access
points, its credential, its `mac_addr` -- so an edit to any of them is noticed,
which for this kind of network means the `bssid` list above all: it is what the
network *is*.

The test asserts both halves, and each fails on its own mutation: restoring the
`?` takes it red on "a bssid-named network beside it must still fingerprint",
and dropping the `bssid` setting from the rendering takes it red on "pinning a
different access point changed nothing in the record".

`None` still covers a network that cannot be rendered at all -- an unusable
credential, or a secret that will not resolve. That case is deliberately left
alone: netcfgd could not have handed such a network over, so it genuinely
cannot say what the supplicant holds, and a digest built from the error text
would move with the environment that produced it rather than with the document.

## What the audit checked and found sound

**`bssid_accept` is a per-network key.** netcfgd renders a multi-BSSID network
as `bssid_accept=<addr>/ff:ff:ff:ff:ff:ff ...`, and the obvious suspicion was
that the name belongs to wpa_supplicant's *global* section. Asked of the real
thing, wpa_supplicant 2.10 over its own control socket:

```text
SET_NETWORK 0 ssid "x"            -> OK
SET_NETWORK 0 bssid 02:...:01     -> OK
SET_NETWORK 0 bssid_accept ...    -> OK
SET_NETWORK 0 bssid_ignore ...    -> OK
SET_NETWORK 0 not_a_key 1         -> FAIL
```

The control is the last line: the parser does reject an unknown per-network
field, so the `OK`s mean the field exists rather than that everything is
accepted. `GET_NETWORK` reads the value back -- normalised, with the
all-ones mask dropped -- which is only safe because the digest is taken from
netcfgd's own intent and never from a read-back.

**Roam detection does not fire on a join.** `last.as_deref().is_some_and(...)`
is `false` for the first `CTRL-EVENT-CONNECTED` on an interface, so the first
association is not reported as a move.

**A roam re-plans nothing, on purpose**, and the tick is what catches a metric
that changed with it -- a station moving within its own network changes no
desired state.

**`network_for` compares BSSIDs case-insensitively**, so an operator writing
capitals matches a supplicant that reports lower case.
