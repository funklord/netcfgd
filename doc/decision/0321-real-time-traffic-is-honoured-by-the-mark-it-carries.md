# 0321: real-time traffic is honoured by the mark it carries, and fuzznet sets it

Status: accepted for the contract and netcfgd's half; fuzznet's half is offered to it
Date: 2026-11-13
Milestone: M5 (routers), and the audio handover 0148 left last
Extends: [0023](0023-netcfgd-owns-the-root-qdisc-and-nothing-below-it.md),
[0283](0283-firewall-and-queuing-are-in-scope.md),
[0148](0148-bluetooth-is-two-backends-and-an-adapter.md)

## Context

The holder, 2026-11-13: netcfgd is in a unique position to configure queuing for audio
streaming alongside the forward error correction fuzznet is to provide -- a server with no
audio card sending to a small device, or Bluetooth audio handed over between rooms.

What was planned: Bluetooth audio, several in and out, ALSA only, `bluealsa` doing the
codecs (0148, 0149), with "audio device handover over fuzznet's streaming" last and
fuzznet's protocol. What was not: anything tying netcfgd's queues to what the traffic in
them is. fuzznet has the other half's design -- a scheduler whose classes weigh latency,
loss and deadline separately, a voice class that takes the fast lossy link and is dropped
when late, and the argument that below one round trip of deadline redundancy must be sent
before a loss is known.

**Why netcfgd, specifically**: fuzznet knows each flow's deadline and nothing about the
queues it crosses; netcfgd owns every queue on the hops it configures -- a router's
uplink shaper, its access point, a host's own link -- and observes each link's loss and
rate. Neither can do the other's half.

## Decision

**The contract is one mark: Expedited Forwarding, DSCP 46**, the IETF's mark for
interactive real-time traffic (RFC 3246, RFC 4594). Whatever sends audio or voice sets it
on its packets; netcfgd's queues carry it as voice. One mark, rather than a netcfgd field
naming flows, because the sender is the only thing that knows which packets are late if
they wait, and because every hop that is not netcfgd's understands it too.

**netcfgd's half is already true, and is now measured and held.** `cake` with a
bandwidth, netcfgd's shaper (0023), runs in the kernel's default `diffserv3` tin mode,
which puts EF in its Voice tin -- served first and capped at a quarter of the shaped rate,
so a mis-marked bulk flow cannot take the link. netcfgd writes no diffserv mode and no
`wash`, either of which would lose the mark. Measured: 200 EF-marked datagrams through a
netcfgd-applied `cake` landed in the Voice tin and 200 unmarked in Best Effort.
`tests/live/qdisc.sh` holds it, read by `tc` rather than by netcfgd; sent unmarked, the
check fails. **On Wi-Fi the kernel maps it**: since Linux 6.8 (commit 6fdb8b8781d5,
"wifi: cfg80211: Update the default DSCP-to-UP mapping", with the AF3x fix after it),
mac80211 maps DSCP to 802.11 user priority per RFC 8325, which puts EF in AC_VO -- so an
access point netcfgd runs on OpenWrt 25.12 (6.12) sends it in the voice access category
with nothing configured. A station that is not Linux maps its own uplink.

**fuzznet's half, offered to it:**

- its voice and media classes set EF on their sockets (`IP_TOS` / `IPV6_TCLASS`);
- the redundancy it sends sized from the loss netcfgd observes on each link of the estate,
  rather than guessed -- netcfgd's observation is already readable by the estate's
  members;
- the stream itself, and its handover between sinks.

**The two cases the holder named, as shapes rather than code yet:**

- **A server with no audio card to a small device** -- an ESP32 with an I2S DAC, say, under
  hal9001: fuzznet carries the stream at a fixed deadline with redundancy sized to the
  path's measured loss; every netcfgd on the path queues it as voice; the device buffers a
  small known amount and plays.
- **Bluetooth audio handed over between rooms**: every netcfgd node already observes its
  own Bluetooth adapter; the signal strength several nodes see says which room a headset is
  in, and the stream moves to the nearest node's sink. 0148's last step, and fuzznet's.

## Rejected

- **A netcfgd field naming real-time flows by port or address.** It would be netcfgd
  guessing what a flow is from outside, which goes wrong with every new application and
  every changed port; the sender knows, and says so in the packet.
- **`diffserv4` or `diffserv8` by default.** More tins split the same traffic finer with
  nothing here that needs it; `diffserv3` has the voice tin this needs, and an operator who
  wants more can be given a key when one asks.
- **Writing `wash` to clear marks at the uplink.** Clearing what leaves for the ISP is a
  privacy choice somebody may make, not a default, and it would also clear what this
  record relies on inside.
