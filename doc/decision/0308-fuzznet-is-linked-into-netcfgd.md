# 0308: fuzznet is linked into netcfgd, and netcfgd is its own node

Status: accepted
Date: 2026-11-02
Milestone: fuzznet integration (project.md 10.668)
Supersedes: [0269](0269-the-remote-half-is-a-separate-program.md)

## The holder's words

> netcfgd wasn't being used because it was far from ready, now it is kinda
> becoming ready, and should be linked in directly. Separation of process
> concerns for separations sake rarely adds much security but makes the code
> substantially harder to reason about. All peer networking and IPC should be
> coming from fuzznet, and no fuzznetd should be necessary for netcfgd.

## What changes

- **fuzznet is linked into the daemon.** netcfgd is a fuzznet node in its own
  right: its own identity, its own store, its own peers. Nothing about it
  needs a fuzznetd running beside it.
- **Peer networking is fuzznet's, in the daemon.** The rule this replaces --
  "the daemon never grows a network listener", design 11.3 and
  `doc/shared-protocol-brief.md` section 3, which 0269 applied to fuzznet --
  is withdrawn. Remote access is the daemon speaking fuzznet to a client, not
  an agent relaying to `remote.sock`.
- **The hosts it sees go into its own store directly** (10.666's records),
  through fuzznet's records API rather than a socket to another process.

## Why the old rule goes

0269's argument was that a fault in framing or reassembly should reach a
program that can do nothing to the machine. The holder's answer is that the
separation costs more than it buys: a second process, a relay protocol between
the two, and a boundary to reason across for every feature, against a
security gain that is small when both halves would run on the same machine for
the same purpose. fuzznet's parsers are fuzzed (its own sections) and its
inputs are authenticated before they are interpreted.

## What is not yet decided

Whether "IPC" includes netcfgd's **local** control socket -- `ncfg` and the
GUI talking to the daemon on the same machine, newline-delimited JSON, which
`doc/socket-protocol.md` section 3.1 argues is a product property and which
raidcfgd adopted -- or means the communication between netcfgd instances.
Asked of the holder.
