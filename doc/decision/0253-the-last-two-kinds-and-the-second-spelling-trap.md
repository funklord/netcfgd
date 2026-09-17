# 0253: the last two kinds, and the second spelling trap

Status: accepted
Date: 2026-09-16
Milestone: M9; the window can configure the machine

## What was left

Two kinds, and after this one: `tun`, which the model calls unimplemented, and
`ifb`, which netcfgd synthesises for ingress shaping and nobody writes. Every
other kind of link this machine can have is now made and edited from the window.

## PPPoE

Parent, username, password and the two optional names a provider may insist on
-- `service` and `ac`. The parent is required here because a PPPoE session runs
*over* an ethernet link and netcfgd cannot invent one; the username is required
because a session without it is not a session.

**The password is a reference**, like every credential in this tree:
`@secret:isp`, with `ncfg secret set isp` putting one in the store. A password
typed into the field is refused beside it, because the document type cannot hold
one at all.

## OpenVPN

The path to the `.ovpn` file, and an optional login. What netcfgd owns is the
lifecycle and not the contents:
[0046](0046-the-ovpn-file-is-the-operators.md) measured `openvpn --help`
at 253 top-level options against hostapd's couple of dozen, so expressing that
surface would be a second OpenVPN configuration language permanently behind the
first. The field takes an absolute path -- netcfgd hands it over as given, and a
relative one would resolve against whatever directory the daemon happens to be
in.

Both credentials are optional, and written only when given: a `.ovpn` that
carries its own, or a server that wants none, is the ordinary case.

## The second spelling trap, and the table that ends it

`openvpn` was in the refusal list and **never matched**. The document spells the
kind `open_vpn` -- serde's snake case for the variant -- and the language spells
it as one word, so an OpenVPN device did not trip the refusal: the kind combo
found no such entry, sat at `physical`, and a save would have written a `device`
block with no tunnel in it.

That is exactly what `wire_guard` did one round ago, and it was invisible for
the same reason: **the refusal list that should have caught it was written in
the language's spelling too.** One bug, two variants, and the second was already
in the tree when the first was fixed.

So the translation is a table rather than a special case:

```quote from=client/ncfg_client.c
The document's spelling is not always the language's.
```

A third variant is one line in it, and the mistake cannot be made a third time
quietly -- the live probe asserts the spelling that comes back for each.

## Five sabotages, all caught

The PPPoE parent dropped from the block; an OpenVPN login written when nobody
gave one; a typed PPPoE password accepted; a relative OpenVPN path accepted;
`open_vpn` handed to the form untranslated.

The last three are the live probe's, and all three assert the *dialog's* own
sentence rather than a word the daemon's refusal also contains -- the rule 0252
had to state twice.
