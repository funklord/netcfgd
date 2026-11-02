# 0309: one protocol -- the local socket is fuzznet's too

Status: accepted
Date: 2026-11-02
Milestone: fuzznet integration (project.md 10.668)
Supersedes: `doc/socket-protocol.md` section 3.1, and answers 0308's open question

## The holder's words

> local socket ncfg and GUI too. We need only one protocol, the fuzznet
> protocol + extensions needed for netcfgd.

## What changes

The control socket `ncfg` and the GUI use on the same machine speaks
fuzznet's protocol, with netcfgd's requests as extensions of it -- the same
protocol a remote client speaks. There is one protocol, not a local one and a
remote one. Newline-delimited JSON, which section 3.1 of the socket document
called a stated product property, goes.

## What follows from it

- **One client library.** `client/` and the GUI speak fuzznet to the daemon
  wherever it is; "local by default, another host when told" (0308's remote
  access) is the same connection with a different address.
- **The witnesses move.** `doc/schema/socket.json` pins the JSON lines a
  client and the daemon exchange; its successor pins the extension messages.
- **What carries over is the vocabulary, not the framing**: the requests and
  answers netcfgd defines (`plan`, `apply`, `wifi_scan`, ...) and the tiers
  that decide who may send them (0013, 0092, 0128), now carried as fuzznet
  extension messages.
- **raidcfgd adopted netcfgd's JSON socket** (its project.md), and is told,
  as information: what it does is its own decision.

## Not decided here

How a netcfgd request is carried inside fuzznet -- a message kind of its own,
an extension number, a body format -- is fuzznet's framing and netcfgd's
vocabulary meeting, and is worked out with fuzznet when the transport is
built, not guessed now.
