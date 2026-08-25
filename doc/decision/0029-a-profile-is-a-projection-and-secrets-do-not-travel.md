# 0029: A profile is a projection, and secrets do not travel

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

The last piece of design section 9.5's tier 1: connection profiles, and
activating them. A desktop needs `Settings` to list what it could connect to,
`Settings.Connection` to describe each one, `Connection.Active` to say what is
running, and `ActivateConnection` to be the button.

Three questions had to be answered, and each has a wrong answer that would have
been easier.

## Decision one: profiles are derived, and so are their UUIDs

**A `network` block and an `interface` block each become one NM profile. The
projection is computed on every read; nothing is stored.**

NM's model has profiles as records with identity and lifecycle: created,
updated, saved, deleted, each with a UUID that lives in a file. Adopting any of
that would be the foreign model leaking inward that section 9.2 exists to stop.
So the shim holds no profile store. `ListConnections` walks the document.

UUIDs are the part where that could have failed. A client stores the UUID of the
network it last used, so it has to be stable across restarts -- and storing one
would be state outside the configuration, which constraint 1 forbids. Section
9.3 already had the answer: derive it, as UUIDv5 over a fixed namespace and the
profile's identity. The same configuration produces the same UUIDs on another
machine, and nothing has to remember anything.

The identity is prefixed by kind (`network:HomeFiber`, `interface:eth0`) so an
`interface wlan0` and a `network "wlan0"` are two profiles rather than one
collision. The namespace constant is an ordinary v4 UUID generated once; its
only property is that it never changes, because changing it renames every
profile every client has ever seen. The unit test pins the literal derived
value, cross-checked against Python's `uuid.uuid5` -- a second implementation,
so the test checks the derivation rather than photographing this one.

**A radio's `interface` block is not a profile.** What you activate on a radio
is a network. Offering an `802-3-ethernet` profile named `wlan0` alongside the
`network` blocks would put a thing in every client's list that cannot be
activated and is not an ethernet.

## Decision two: secrets do not travel

**`GetSecrets` refuses, always.**

The document holds a `SecretRef`; the daemon resolves it when it connects. NM's
own answer here is to gate the method behind polkit and hand the passphrase
over. netcfgd's answer is that there is nothing to gate, because the value does
not go on the bus at all -- a message bus any local process can name is a worse
place for a passphrase than the file it came from.

This costs a client nothing it needs. `psk-flags` is reported as system-owned,
which tells a client the daemon holds the credential; it then does not prompt,
which is correct, because there is nothing for a user to type that netcfgd does
not already have. The live test asserts both halves: the refusal, and that the
passphrase does not appear in what `GetSettings` *does* return.

## Decision three: writes are refused, in netcfgd's words

Section 9.4 describes the write path -- GUI-created profiles become native
config under `/etc/netcfgd/conf.d/nm/`, marked machine-generated, followed by a
reload -- and hand-written blocks stay read-only so a stray click cannot mangle
a tuned `eth0`. That write path is a real feature with atomic writes, reload
semantics and secret-provider integration to get right, and it is not in this
commit. Every mutating method refuses.

The interesting part is *which* methods exist. `nmcli connection modify` calls
`Update2`, not `Update`; `nmcli connection add` calls `AddConnection2`. A shim
that implements only the older spellings does not produce a refusal -- it
produces `Unknown method 'Update2'`, which tells an operator nothing about
netcfgd. So the newer spellings exist for the sole purpose of being able to say
no in a sentence that names the file to edit and the command to run.

`Settings.CanModify` is false, which a GUI reads and renders by greying out its
"add" button. The errors are for the clients that ask anyway.

## Activation, and the one case that is not a verb

`ActivateConnection` on a `network` profile is `ncfg wifi connect` reached over
D-Bus. It goes through netcfgd's own join rather than a path of the shim's own,
which is what keeps decision 0013's boundary in one place: it can join what
somebody with the admin tier wrote down, and there is no request here that
could create a network. The shim holds no privilege the CLI does not.

An `interface` profile is different, and the difference is netcfgd's whole
model: an interface is up because the configuration says it should be. There is
no "activate" verb because there is nothing to activate. So an interface that is
already up answers success -- the state being asked for is the state that
holds, which is the same "empty plan is the normal case" the reconciler is built
on -- and one that is down explains that the configuration or the last apply is
why, and that `ncfg plan` will say which.

`DeactivateConnection` on an interface refuses outright. Taking a configured
interface down is `enabled = false` and an apply, not a request the next
reconcile would undo.

## What the client found this time

**A device contradicted itself.** A radio associated with a known network
reported `disconnected` -- because the device state was computed from
addressing, and a dummy standing in for a radio has no address -- while the
same object reported an active connection. A client resolves that by believing
whichever it read second. An activation on a device now settles its state.

That is not only a test artefact: a real radio is associated for a while before
DHCP finishes, and "connected to HomeFiber, state disconnected" is what an
applet would have drawn for that whole window.

**Two checks that would have passed for the wrong reason**, both caught while
writing them rather than after:

- Counting `ADD_NETWORK` over the whole supplicant log to prove activation
  reached the radio. The daemon populates the supplicant at apply time, so the
  count was already 1 before anything was activated. It is measured as a delta
  across the D-Bus call now.
- Expecting two profiles where the fixture produces three. The fixture has an
  interface the test deletes the *link* for, and deleting a link does not
  remove the block that describes it -- which is exactly the distinction
  between desired and observed that the whole project is about.
