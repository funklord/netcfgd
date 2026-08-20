# 0117: Adding a network is a typed request, not a written file

Status: accepted
Date: 2026-08-07
Milestone: M8's desktop half; the blocker for daily-driving

## Context

netcfgd's own GUI can join a wireless network the configuration already
describes and no others. On a laptop that means every new café needs a
terminal, which is the difference between a client somebody uses and a client
somebody demonstrates.

The reason is not an oversight. [0069](0069-adding-a-network-is-writing-a-file.md)
settled that adding a network *is* writing a config file, and
[0013](0013-three-things-a-caller-may-be-allowed-to-do.md) puts writing config
in the `admin` tier, so the socket deliberately grew no request for it. What
`ncfg wifi add` does is write `conf.d/wifi-<id>.conf` at 0644 and a secret at
0600 into `/etc/netcfgd`, which is root's. A GUI running as the desktop user
cannot, and asking the daemon was not an option the protocol offered.

Both of those decisions were right and neither is being reversed. What was
never decided is how an *unprivileged* client reaches the same outcome.

## The policy question is already answered

It is worth separating two things that get argued as one.

**May a desktop client cause a wireless network to be written into netcfgd's
configuration?** That is policy, and the answer has been yes since M7.
[0030](0030-a-gui-is-an-editor-of-config-files.md) has `nmcli connection add`
writing a netcfgd `network` block, and
[0031](0031-the-secret-bridge-runs-one-way.md) has an agent-supplied passphrase
going to the secret provider with the block keeping an `@secret:` reference.
The shim does this today.

**Through what transport?** That is the open question, and there is only one
left. Today the answer is "through D-Bus and the NM shim" -- which for a
project whose premise is not needing D-Bus, and for the operator this GUI was
written for who has no NetworkManager applet at all, means **netcfgd's own
client is less capable than a foreign one, and the remedy is to install the
dependency the project exists to avoid.** That is not a boundary worth
keeping; it is an accident of which adapter was built first.

## Decision

**A new `admin`-tier socket request, `wifi_add`, carrying typed fields — never
config text, and never a path.** The daemon renders the `network` block itself,
writes it through the same code `ncfg wifi add` uses, and stores the credential
through the active secret provider so the block holds only an `@secret:`
reference.

The distinction that makes this safe is the whole decision, so it is stated
rather than implied:

> **A request that carries config text is remote code execution. A request that
> carries an SSID and a passphrase is not.**

A config file may name a hook, and a hook's `run_as` is absent by default,
which means root. So *anything* that can write arbitrary config into
`/etc/netcfgd` can run arbitrary code as root, whatever the file's mode says.
A typed `wifi_add` cannot express a hook, a path, a `run_as`, or any block but
`network`, because those are not fields it has. The privilege it grants is
bounded by the shape of the message rather than by the caller's good manners.

This is the same argument §2.2 makes about the desired-state document
carrying `{phase, path, sha256}` instead of inline shell: a document that can
carry shell is remote code execution with extra steps, and closing that door
structurally beats closing it by policy.

## What follows from it

- **The secret travels inbound and never back.** The passphrase is in the
  request, is written through the provider at 0600, and the block gets a
  reference. `GetSecrets` still refuses and so does everything else outbound:
  0031's bridge runs one way and this is the same direction. The
  *desired-state document* remains secret-free (constraint 5), which is a
  claim about the document and not about a request in flight -- the same
  status a passphrase on `ncfg wifi add`'s standard input already has.
- **`admin`, not `wifi`.** 0013's `wifi` tier is "join, leave and scan known
  networks", and adding one is beyond that by definition. A site that wants its
  users adding networks grants them `admin`; a site that does not, does not.
  That is a real consequence and it is the tier system working, not a gap:
  writing configuration is the thing `admin` names.
- **One writer, not two.** The rendering and the file layout must be the code
  `ncfg wifi add` already runs, moved somewhere both reach. Two implementations
  of "what a `network` block looks like" is the shape this tree keeps finding,
  most recently as three spellings of one access point's name.
- **The specification changes.** `docs/socket-protocol.md` currently says no
  passphrase crosses this socket in either direction. That becomes: inbound
  only, in one request, and never outbound.

## Rejected

**A group-writable config directory.** The obvious answer -- `chgrp netdev
/etc/netcfgd/conf.d`, mode 2770, and `ncfg wifi add` simply works for group
members -- needs no new code, no new protocol surface and no new dependency.
It is disqualified by the hook argument above: a group-writable config
directory is group-writable root code execution, and it would hand that to
everybody the `wifi` tier was designed to give something much smaller. The
cheapest option is the one that quietly grants the most.

**A privileged helper (polkit, pkexec, setuid).** The standard desktop answer,
and it puts back the stack constraint 3 exists to avoid, for an audience
substantially made of people escaping it. A helper narrow enough to be safe
would take exactly the typed fields `wifi_add` takes -- at which point it is
this decision with an extra process and a second authorization system that
must agree with 0013's tiers or be a second, disagreeing answer to "who may do
what".

**Running the GUI as root.** Named only to refuse it. A Qt application with a
network stack, a theme engine and a plugin loader is not a thing to run as root
so that it can write one file.

**Leaving it to the shim.** Coherent, and it is the status quo. It makes
netcfgd's own client permanently less capable than a NetworkManager applet and
makes D-Bus the price of a usable desktop, which inverts the project.

## What this does not decide

- **The wire shape of `wifi_add`** -- which fields, and how the enterprise
  (802.1X) case is carried. `ncfg wifi add`'s flags are the obvious starting
  set and the CLI is the reference for what a network can be.
- **Whether the TUI offers it.** It is a socket client and would gain the
  ability for free, but a passphrase prompt in a curses pane has its own
  questions about echo and about what a terminal has already logged.
- **Editing or removing a network.** This decision is about adding one. The
  same argument probably extends and has not been made.
