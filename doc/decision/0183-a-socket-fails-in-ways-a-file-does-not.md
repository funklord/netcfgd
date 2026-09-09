# 0183: a socket fails in ways a file does not

Status: accepted
Date: 2026-09-09
Milestone: M8; the fourth audit, after 0180 (writes), 0181 (reads), 0182 (execs)

## The question

> now check the network and socket errors too

A socket adds failures a file does not have: a peer that connects and never
speaks, a message that does not fit, an answer that arrives before the
question. Three findings, in three different places.

## A connection that says nothing held a slot for ever

The control socket caps concurrent connections at 64 and answers the 65th with
a message rather than a dropped connection -- both deliberate, both good. What
neither covered is a connection that is not a client: `handle` blocked in
`read_request` with no deadline, so a caller that connected and stayed silent
held its slot until the daemon stopped.

Measured against a real daemon: **64 silent connections, and `ncfg reload`
refused for as long as they were held**. On a machine whose `control` policy
opens `observe` to `any` -- the shape `debian/postinst` suggests, and the one
this machine runs -- that is any local user, with no credential and no
request.

**A ten-second deadline on the first request**, cleared as soon as one
arrives. A tray that idles between clicks and a `monitor` stream that says
nothing for hours are untouched, because both have spoken. What it does not
close, said rather than left implied: a caller that sends one valid request
and then idles still holds a slot. Closing that means an idle timeout on an
established client, which would drop the tray and the monitor; the cap remains
what bounds the damage.

## The refusal reached the buffer and not the operator

With the cap reached, `ncfg reload` said:

    ncfg: cannot send: Broken pipe (os error 32)

The daemon answers on accept and then closes, so the client's write lands on a
closed socket while the sentence explaining why is **already in the client's
own receive buffer**, unread. A message the daemon composed carefully, thrown
away by the client one function later.

So a send that fails now asks the socket what is there before reporting. With
the cap reached it says `too many connections, 64 are open`.

**Pinned on the function rather than through a socket**, because through a
socket it is a race: whether the write fails at all depends on whether the
close beats it, and the first version of that test passed for the wrong reason
-- the write went into a buffer, the read found the refusal, and the path being
fixed was never taken. The end-to-end behaviour is in
`tests/live/control_exposure.sh`; what is deterministic is the question the fix
asks, and that is what the unit test checks.

## A netlink reply that did not fit was silently short

`receive` used a plain `recv`. **Netlink delivers a datagram whole or not at
all**: a buffer too small takes what fits, the kernel discards the rest, and
the return value is the buffer's length -- so the caller parses the messages
that arrived and never learns there were more. What that costs is not an error
but an incomplete observation: interfaces, addresses or routes missing from a
dump, and -- where the lost tail carried the `NLMSG_DONE` -- a wait that runs
to the socket timeout for no visible reason.

**Latent rather than active on this machine, and measured to say so.** The
kernel caps a dump's datagrams just under the 32 KiB buffer: 31,944 bytes for
a link dump of 800 interfaces, whatever the interface count. What does reach
it is a single oversized *message*, since one message is delivered whole or
not at all, and a WireGuard device with a great many peers is one message.

`MSG_PEEK | MSG_TRUNC` asks the size without consuming, the buffer grows to
it, and the datagram is then taken whole. Bounded at a megabyte, with the
refusal naming the size it saw.

**The first version re-sent the request instead, and the test caught it.**
Doubling the buffer and asking again leaves the truncated reply's remaining
datagrams queued on the same socket, to be read and skipped against the new
sequence number while the new reply queues behind them. It passed once and
returned an empty dump on the next run. Asking the size first has no such
state.

## What is checked

* `tests/live/control_exposure.sh`: 64 silent connections, then a real
  `ncfg reload` -- the client must be told which wall it met, must not be left
  holding `Broken pipe`, and the slots must come back. Sabotaged by removing
  the deadline, the recovery check goes red.
* Unit tests for the client's "what did it say" path, both directions.
* A unit test for the netlink growth, **driven by starting the buffer small
  rather than by making a huge reply**, because the kernel will not make one
  on demand. A link dump read into 128 bytes must equal the same dump read the
  ordinary way -- which fails if the growth loses messages and if it invents
  any. Five consecutive runs, and removing `MSG_TRUNC` reddens it.

## What was looked at and found sound

Every socket that waits sets a read timeout (`dhcpcd_control`, the supplicant
client, openvpn's management socket, the portal probe). `ENOBUFS` on the
netlink monitor is treated as "something moved" rather than as an error, with
the argument written down: netcfgd re-reads state rather than applying deltas,
so a dropped event costs nothing and treating it as a failure would stop the
watch exactly when the most was happening. Multipart replies end on
`NLMSG_DONE`, and `NLMSG_ERROR` with a zero code is read as the
acknowledgement it is.
