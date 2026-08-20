# 0127: netcfgd is the only writer, and the socket carries what clients cannot

Status: accepted
Date: 2026-08-20
Milestone: M8's desktop half, and the shape of every client after it

Supersedes the *mechanism* of
[0117](0117-adding-a-network-is-a-typed-request-not-a-written-file.md) and the
premise of [0030](0030-a-gui-is-an-editor-of-config-files.md). Keeps 0117's
principle, which is the part that was doing the work.

## Context

netcfgd runs as root because configuring a machine's network requires it.
Clients run as whoever opened them, locally or across a network, and mostly
never as root. Those two facts settle the architecture between them: **a client
cannot write system files, and system configuration cannot live under a user.**
So anything a client wants netcfgd to have -- a wifi passphrase, a certificate,
a whole subtree of configuration -- travels over the same channel the rest of
the conversation uses, and netcfgd writes it.

The tree had been arriving at the opposite arrangement one exception at a time.
`ncfg wifi add` writes `conf.d/wifi-<id>.conf` itself. `ncfg secret set` writes
`secrets/<name>` itself. `ncfg control set` writes `conf.d/00-control.conf`
itself, and [0118](0118-two-ways-to-be-allowed-and-one-of-them-is-visible.md)
and [0120](0120-the-red-frame-is-a-process-boundary.md) built an elevator, a
privileged helper and a red frame around the fact that a desktop client cannot.
The NM shim writes `conf.d/nm-*.conf` itself. Each was locally reasonable and
together they are four programs with root's write permissions on the file the
daemon treats as its only authority.

## Decision

**netcfgd is the only writer of `/etc/netcfgd`.** Every client -- `ncfg`, the
TUI, the GUI, the NM shim, anything reached through `agent/` -- sends content
over the control socket and netcfgd puts it on disk. No client writes
configuration, secrets or certificates directly, and none needs privileges to
do its job.

## What survives from 0117, and it is the important half

0117 is remembered as "typed requests, never config text". The typing was the
mechanism; the principle was one sentence:

> **A request that carries config text is remote code execution. A request that
> carries an SSID and a passphrase is not.**

The dividing line there was never *socket versus file*. It was **whether the
payload can express code**, and that question is unchanged by who does the
writing. A client that can cause arbitrary configuration to exist can cause
arbitrary code to run as root, whether it wrote the bytes itself or asked the
daemon to.

So this decision widens what the socket carries and inherits 0117's obligation
in full: **the payload a non-root client may send must not be able to express
code.**

## What that requires, which is the actual work

Not "no hooks". The productions that grant more than configuring a network were
enumerated against the compiler rather than recalled, and there are six, three
of which execute code outright:

| production | what it grants |
|---|---|
| `hook` blocks | arbitrary shell; `run_as` absent means root |
| `probe { command, args }` | [0119](0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md) says the whole block is a program |
| `@secret:exec:NAME` | `netcfgd-secret` runs a command to fetch the value |
| `openvpn { config = PATH }` | an OpenVPN config carries `up` and `down` scripts |
| `ca_cert`, `client_cert` | arbitrary paths, read by a supplicant running as root |
| `include "PATH"` | pulls arbitrary files into the configuration |

`@secret:exec:` is the one worth naming: a code-execution path inside the
*secrets* feature, which nobody would look for while thinking about hooks. An
enumeration written from memory would have listed hooks and stopped.

**So the language needs a classification, and the classification needs a gate.**
Every production is either something a non-root client may send or something it
may not, the compiler knows which because it is the compiler, and a production
added later must be classified or fail to build -- the same construction
`tier_of` already uses for socket requests, where "a request added without a
tier fails to compile" is deliberate. A review checklist would not survive the
first new keyword.

**Certificates stop being paths.** `ca_cert` and `client_cert` naming a
filesystem path is what makes them dangerous and is also why an unprivileged
client could never supply one. Sent as content and stored by netcfgd, they
become data the daemon owns, at a path the daemon chose -- which removes the
production from the dangerous list rather than guarding it.

## Consequences

**0118 and 0120 lose their premise and may not lose their value.** Both exist
because a desktop client cannot write the control policy. Under this decision
it does not need to: it asks. What an administrator mode may still be worth is
showing a boundary that remains -- if some payloads stay root-only, a mode you
can look at is the honest way to say so, and that argument is 0120's and is
untouched. Whether the elevator survives is decided when the classification is.

**One writer means one place to audit.** Four programs with write access to the
authority file was four things to get right; the reason to notice that now is
that the fourth arrived without anybody deciding to add it.

**The CLI's own direct writes go too.** `ncfg wifi add`'s local-write path,
added days before this with a daemon fallback, inverts under it: the daemon
becomes the path and the local write becomes the exception -- kept only for the
case that has no daemon, which is a machine being configured before netcfgd
runs at all.

## What this does not decide

**Who may send what, and from where.** Local and remote are different
authorization paths -- local deliberately open, potentially every user in the
`netcfgd` group by a distribution's default -- and the daemon currently cannot
tell them apart at all: `agent/` was designed so a remote client arrives as an
ordinary local socket connection and "the daemon itself is unchanged". That
reversal is its own record.

**The wire shape.** Whether content arrives as typed model documents, as config
text, or as both is a protocol question, and the classification above is what
makes either safe rather than the choice between them.
