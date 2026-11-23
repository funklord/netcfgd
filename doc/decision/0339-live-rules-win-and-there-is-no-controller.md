# 0339: live rules win, there is no controller, and unreachable fields go

Status: accepted
Date: 2026-11-23
Milestone: the firewall's layers ([0284](0284-the-ruleset-is-netcfgds-and-rules-arrive-in-five-layers.md)); the model's reach
Rests on: the holder's answers of 2026-11-23 to three open questions in project.md
Supersedes: 0284's "a controller, for many hosts" and its "precedence ... is not decided here"; 0294's "precedence between layers" non-decision; the "whether that is worth building" of project.md's UniFi entry

## What the holder decided

Asked about precedence between firewall layers, the UniFi integration, and the
twenty model fields the configuration language cannot reach:

> 1. Live updates, then hand written rules, then zone and last preset, There is
> no controller, netcfgd is a distributed system which requires distributed
> algorithms for authoritative processing, but in effect any host can generate
> live updates (to those kinds of rules), we open slots on each node for what
> can be live updated, and we refuse what we otherwise deem to be a static
> value. 2. If we do this at all, we delay it until later. As it is an endless
> churn against a moving target. 3. Remove the fields with no behaviour behind
> them if they serve no purpose, fix everything that does have an obvious need,
> and remove what doesn't.

## Precedence: live, hand-written, zone, preset

A packet meets the layers in this order, and the first verdict wins:

1. **live updates** (0284's layer four),
2. **hand-written rules** (layer one, [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)),
3. **zones** (layer three),
4. **presets** (layer two).

In nftables, where the first terminal verdict in a chain ends evaluation, that
is rule order: whatever the live layer contributes is evaluated before the
operator's rules, a zone's compiled rules after them, and a preset's expansion
last. A preset is the most general and least specific thing on a host, so it is
the fallback; a hand-written rule is the operator saying something about this
machine, so a zone does not override it.

0294 said layer one's file order was not to be read as "manual rules win". It
now does mean that, against zones and presets -- and not against live updates.

## There is no controller

0284 wrote zones as "written by a controller, for many hosts", and 0285 kept
the word for whatever hands nodes their plan. **There is none.** netcfgd is a
distributed system: what is authoritative across the network is settled by
distributed algorithms between the nodes (0285's loop, carried by fuzznet),
not by one host that the others obey.

**Any host may generate a live update, and only into a slot.** Each node opens
slots for what may be updated live -- in nftables terms the sets and maps 0284
already named as layer four's mechanism -- and a live update is an element
added to or removed from an opened slot. **Anything not opened as a slot is a
static value, and a live update to it is refused**, whoever sent it. A failover,
an authentication or a quarantine changes membership; it never rewrites a
rule.

0284's and 0285's requirement survives with its subject corrected: **a node
keeps enforcing when the rest of the network is unreachable, and does not fail
open.** There is no controller to lose; there are peers, and losing them leaves
the static rules and the last membership of each slot in force.

Not decided here: how a node declares a slot, who may write into one (which is
0311's authority question at network scale), how long an element lives without
being renewed, and the zone grammar and how a zone names a host.

## UniFi waits

The controller's useful data -- which BSSIDs make one network, an access point
about to be upgraded, per-radio load -- is only in its web interface's private
API, which changes between controller versions (project.md, the 2026-11-03
reading). Building against it is churn against a moving target. **It is not
built now**, and a later decision to build it starts from that reading rather
than from this record.

## The unreachable fields

Twenty places in the model could not be set from the configuration language.
Re-measured in the C tree on 2026-11-23 by asking what writes each field, not
what parses a key. Each was given the holder's test: behaviour and an obvious
need -> reach it from the language; otherwise remove it.

**Removed, with what covers them instead:**

| field | why it goes |
|---|---|
| a DHCPv4 lease's `hostname_mode`, `client_id`, `request_options` | dhcpcd is started with `-f` on the operator's own `dhcpcd.conf`, which is where these are already said; nothing in netcfgd read them, and the renderer refused them |
| a DHCPv4 lease's `metric` | the client's metric comes from the interface's route metric policy; a second metric on the lease would have been a second answer |
| a DHCPv4 lease's `backend` | the client is chosen by what is installed (dhcpcd, else udhcpc); `builtin` never existed |
| a DHCPv6 lease's `mode`, `rapid_commit` | no client read them; dhcpcd's own configuration carries rapid commit |
| a route's `scope` and `proto` | the kernel derives a scope from the route's shape, and `proto` is how netcfgd knows a route is its own (`NCFG_ROUTE_PROTO`); a configured protocol would have defeated that |
| a delegated prefix reference's `index` | always 0; one delegated prefix per uplink is what every reference used |
| a hook's `run_as` and `timeout` | `run_as` was refused at run time, since the privileged process resolves no user names; `timeout` was never anything but the 60-second default, and a hook that needs longer backgrounds itself |
| the DNS `exec` mode and the RA `exec` backend | escape hatches that hand a script root and the whole policy; every supported resolver and advertiser has its own mode, and hooks exist for anything else |
| a device's `match` (`mac`, `path`, `driver`, `name_glob`) | nothing read it; renaming devices by property is a feature of its own (udev's and the kernel's naming already give stable names) and would be designed as one |

**Reached from the language, because they have behaviour and an obvious need:**

- **DNS `options`** -- resolv.conf's `options` line (`edns0`, `rotate`,
  `ndots:N`, `timeout:N`). The flat backends already rendered it.
- **DNS `transport`** -- `plain` or `tls`. DNS over TLS is what keeps a
  router's upstream queries from being read on the way; unbound already
  rendered `forward-tls-upstream`, and resolved takes `dnsovertls`.
- **DNS `dnssec`** -- `no`, `allow` or `yes`, which resolved takes per link.
- **A DNS server's `port` and `sni`** -- a TLS upstream is useless without the
  name its certificate must carry, and a local forwarder on a port other than
  53 is ordinary. Written `address:port#name` for IPv4 and
  `[address]:port#name` for IPv6, resolved's own spelling.

`https` stays in the model's transport set and is refused by the language: no
backend netcfgd drives speaks it.

A backend that cannot deliver one of these refuses rather than drops it -- a
TLS upstream handed to a plain `resolv.conf` would be a cleartext query the
operator believes is encrypted.
