# 0039: A station list is one list

Status: accepted
Date: 2026-07-31
Milestone: the single-host half of what 0036 named

## Context

Decision 0036 wrote down Ubiquiti-style roaming and where it splits. Forcing a
client onto one access point is done by making every *other* access point
refuse it, which predates 802.11k/v/r and still matters because the
standardised mechanisms are not everywhere. The per-AP enforcement is a
single-host feature; deciding *which* access point owns a station is
coordination between machines and belongs to section 11.

This is the single-host half. `access_point` blocks grow an `access_control`
block, hostapd is given the list, and the file it reads is generated under
`/run` like the rest of its configuration.

## One list, because hostapd has one

```
access_control { deny  = ["aa:bb:cc:dd:ee:ff"] }
access_control { allow = ["aa:bb:cc:dd:ee:ff"] }
```

`macaddr_acl` selects *either* `accept_mac_file` or `deny_mac_file`, never
both. So the model carries one list and a policy rather than two lists, and
writing both is refused at compile time rather than resolved by precedence. A
precedence rule would mean an operator's deny list quietly did nothing, which
is the failure mode this whole feature exists to prevent.

`deny` is the one Zero Handoff uses. `allow` is the private-network case.

## Addresses are normalised, and what is not an address is refused

Stations are stored lowercase, colon-separated, sorted and deduplicated.
Sorting because a list is a set: two operators writing the same stations in a
different order mean the same access point, and an unsorted list would give
them different document hashes and so a change to reconcile that is not one.
Lowercase colons because that is what hostapd prints, which makes comparing the
document against a live list a string comparison rather than a parse -- and
that comparison is what the runtime half will need.

`aa-bb-cc-dd-ee-ff` is accepted and normalised, in either case. Bare
`aabbccddeeff` is refused: with one digit dropped it is still eleven plausible
characters, and an ACL is the wrong place to guess at a typo. The refusal
happens where the address was written, with a span, rather than reaching
hostapd -- which does validate it, but reports it against a file the operator
did not write.

## What is deliberately not secured by this

An `allow` list keeps honest devices off a network and stops nobody else. A MAC
address is asserted by the station and changed with one command. This is a
policy mechanism; anything that has to be secure belongs in `wifi { .. }`,
where the key material is. Said in the type's own documentation, because the
place somebody reaches for this is the place they should read it.

## The file

`/run/netcfgd/hostapd/<device>.acl`, beside the generated configuration and
named after the device, at mode 0644 -- it holds no secret, and a list only
root can read is a list nobody debugging an access point can read either. That
is the opposite call from the configuration beside it, which is 0600 because it
carries a passphrase in the clear.

Written even when the list is empty, and removed when the block goes away.
Both directions matter: hostapd refuses to start when `deny_mac_file` points at
nothing, so a missing file takes the access point down rather than leaving the
list unenforced; and a file left behind after the block is deleted is a list
that nothing reads, which the next person to look at it will believe.

Verified against hostapd 2.10 rather than assumed. It validates the file at
parse time -- a missing path and a malformed line each produce `Failed to read
deny_mac_file` and a nonzero exit -- so `tests/live/ap.sh` feeding it the real
generated file is a check that the ACL is actually enforced, not just spelled.

## An empty allow list warns rather than fails

`allow = []` means no station may associate at all. That is a legitimate thing
to write -- it closes an access point without taking it down -- and an easy
thing to arrive at by deleting the last station from a list. So it compiles,
and the planner warns.

The warning is in the planner rather than the compiler because a `Diagnostic`
is a failure, and this is not one. Adding a severity to the compile layer for
one case would be a bigger change than the case is worth, and the planner
already has warnings that read exactly like this.

## What this does not do yet

**Changing the list restarts nothing, because nothing yet notices it changed.**
`ObservedBackend` records only whether a backend is running, so a changed
access-point configuration -- an ACL, an SSID, a channel -- is not seen by the
planner at all. This gap is older than this feature and is not made worse by
it.

For an ACL specifically the answer is not a restart. Restarting hostapd
deauthenticates every client on the radio, which for a feature whose entire
purpose is a smooth handoff would be worse than not having it. hostapd's
control socket takes `DENY_ACL ADD_MAC`/`DEL_MAC`/`SHOW`/`CLEAR` and
`DEAUTHENTICATE <addr>`, all four verified present in the 2.10 binary, which is
enough to converge the live list against the document and shake loose a station
that has just been denied.

That fits netcfgd's shape exactly -- hostapd's in-memory list is observable
state, so it is compared with the document like anything else -- and it needs
observation over a control socket, which nothing does today. It is the next
piece of this feature, not part of it.
