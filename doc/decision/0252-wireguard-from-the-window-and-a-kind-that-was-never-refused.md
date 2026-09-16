# 0252: WireGuard from the window, and a kind that was never refused

Status: accepted
Date: 2026-09-16
Milestone: M9; the window can configure the machine

## What was left

0251 made every virtual link but four from the window. `wireguard` was one of
the four, refused on the grounds that a form with no fields for the peers and
the key would empty the block. It has fields now, and so does the last of the
tunnel's: `ttl` and `key`, which the tunnel page had no row for.

## The private key is a reference, and the form says so

netcfgd's document type **cannot hold key material at all** -- that is what
makes a document safe to write to `/run` -- so what the block carries is
`@secret:wg0`, the name of something the secret store keeps. The field is an
ordinary line edit holding that reference rather than a password box, and a key
pasted into it is refused beside the field:

> the private key is a reference, not the key: `@secret:wg0`, with
> `ncfg secret set wg0` to put one there

A peer's *public* key is not a secret -- it is that peer's identity and goes in
the file as itself -- which is why one is text in the table and the two keys
beside it are references. A peer's preshared key is a reference too, and is kept
on the row rather than shown: a column of `@secret:` names on a table an
operator scans for endpoints is noise, and dropping it on save is the one thing
this editor must not do.

Peers are a table -- name, public key, endpoint, allowed prefixes, keepalive --
because a device with one peer is as ordinary as one with six, and a dialog per
peer would be a dialog inside a dialog.

## The kind that was never actually refused

The refusal list named `wireguard`. **The document spells the kind
`wire_guard`** -- serde's snake case for the variant -- **and the config
language spells it `wireguard`**, so the name never matched. A `WireGuard`
device therefore did not trip the refusal at all: the kind combo found no such
entry and sat at `physical`, and saving would have written a `device` block with
no tunnel in it. The editor would have deleted the tunnel while reporting
success.

Translated once, in the client, where the document's word becomes the
language's. A gap of exactly one round, introduced by 0251 and closed here,
found by compiling a real `wireguard` block and reading what came back rather
than by any test.

## The refusal that could not fail, again

`live_device_dialog` asserts that a pasted private key is refused *by the
dialog*. Written as "the note mentions `reference`" it passed with the check
removed, because netcfgd refuses a pasted key too and its message has that word
in it.

**That is the second time in two rounds** -- 0251's VLAN-parent check was the
same shape -- so the rule is worth stating rather than fixing twice more: **a
test of a refusal has to name whose refusal it is.** Both now assert the
dialog's own sentence.

## Five sabotages, all caught

The peers dropped from the block; a tunnel key of zero read as no key; a
preshared key dropped on save; a pasted private key accepted; the document's
`wire_guard` handed to the form untranslated.

The second is the `None` versus `Some(0)` distinction in its usual costume: zero
is a legal tunnel key and `none` is not zero, which is why the absent value is
-1.
