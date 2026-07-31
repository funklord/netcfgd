# 0031: The secret bridge runs one way

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

The last piece of design section 9.5's tier 1: clients register secret agents
and expect to be asked for a passphrase. Section 9.3 sets the shape -- an
agent-supplied secret is written through the active provider and the config
gets an `@secret:` reference, never inline plaintext.

## Decision

**Agents supply credentials; nothing supplies credentials to agents.**

`AgentManager.Register` records a bus name. When an activation needs a
passphrase netcfgd does not have, the agent is called, the answer goes to the
secret provider, and the configuration keeps the reference it already had.
`GetSecrets` on a profile still refuses (decision 0029), so the bridge has an
inbound direction and no outbound one.

That asymmetry is the whole design. A desktop can *give* netcfgd a credential it
did not have; it can never *read* one netcfgd holds. Those look symmetric from
NM's side and are not: the first is a person typing something they know, and the
second is a bus handing a passphrase to whatever asked.

### The trigger is a question, not an error

The agent is asked when a `network` block's `psk` is a `@secret:` reference to a
file that does not exist. That is checked before connecting rather than
recovered after failing, so nothing parses an error string and the provider is
consulted rather than guessed at.

Only the `file` provider. `pass` may be locked and an `exec` may be about to
succeed; a shim that decided those were empty would put a dialog in front of a
user who had already answered the question somewhere else.

### Storing is a configuration write

The answer goes to `/etc/netcfgd/secrets/<name>` at 0600, through the same
`admin` tier check every other write goes through (decision 0030). A desktop
that may not change the configuration may not fill in its secrets either --
they are the same permission, and the second is how you would work around the
first.

### An agent that is gone

NM watches `NameOwnerChanged` to drop agents whose process exited. This asks the
bus whether the name still has an owner at the moment it is about to be called,
which gets the same answer with no signal plumbing and no window in which a
stale registration is believed.

## Three things a real client found

**Every interface's introspection XML was malformed.** zbus copies Rust doc
comments into the introspection data, and `--` is illegal inside an XML comment
-- which is exactly what this project's ASCII rule says to write instead of an
em dash (project.md section 9). So the house style and the framework combined to
produce a broken machine contract on every object the shim serves, and only a
client that introspects noticed: `dbus-python` does by default, GDBus does not,
which is why `nmcli` had been working against it for three commits.

Fixed with `introspection_docs = false`, which is right for more reasons than
the bug: introspection XML is a contract between programs, and a real
NetworkManager does not put its design rationale in it. `tests/live/nm.sh` now
parses the introspection of one object of each kind, and it fails when the
attribute is removed.

**A radio with no capabilities is a radio no profile fits.** `WirelessCapabilities`
was reported as 0, and libnm checks it before offering a profile: every secured
network came back "not compatible with the device" and the activation never
reached netcfgd at all. netcfgd cannot ask the radio what it supports -- it
delegates to `wpa_supplicant` and does not speak nl80211's capability dump -- so
the shim reports what any radio a supplicant will drive can do. A card too old
for RSN is described generously and fails at association with the supplicant's
own message, which is a better failure than being invisible.

**`nmcli` registers a secret agent of its own.** The test for "no agent is
registered, so netcfgd's own message about the missing secret is what surfaces"
was written with `nmcli` and hung for twenty seconds: the shim asked nmcli's
agent, and nmcli, not being in interactive mode, never answered. "No agent" is a
state `nmcli` cannot be used to observe, so that check goes through `busctl`.
The hang was the shim behaving correctly, which is the most confusing kind.

## What tier 1 looks like now

Devices, access points and scanning, connection profiles with derived UUIDs,
activation, the write path, and the secret bridge. `org.netcfgd.Compat`'s
`Supported` map says which of those this build serves, so a client learns by
asking rather than by finding an empty list.

What is not here is tier 2: the settings panels, which want static addressing,
per-connection options and profile editing beyond what a connect dialog sends.
And `AddConnection` still creates wifi networks only -- an interface is a block
to edit rather than a profile to create, and it says so by name.
