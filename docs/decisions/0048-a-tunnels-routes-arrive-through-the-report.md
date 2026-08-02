# 0048: A tunnel's routes arrive through the report

Status: accepted; the nameservers left in "What is deliberately not taken" are
taken by [0049](0049-a-server-may-name-resolvers-not-where-queries-go.md), on
the terms that section asks for -- the servers are reported and the routing
domains are not
Date: 2026-08-02
Milestone: implements the half [0047](0047-a-tunnels-address-stays-with-its-daemon.md) chose

## Context

0047 settled *which* half of a tunnel is worth taking and deliberately did not
build it: the address stays with the daemon, as a DHCP lease's already does, and
the routes are the contested half. A VPN installing its own default route walks
into the middle of netcfgd's uplink arbitration with a metric netcfgd did not
choose, and neither side knows the other is there.

This record is how that is done, and what it costs.

## The mechanism

`openvpn` is started with three arguments it did not have:

```
--route-noexec  --script-security 2  --route-up <script>  --down <script>
```

The script is **generated** into `/run/netcfgd/openvpn/<iface>.report`, the same
way a `DHCPv6` client's prefix hook already is. Nothing packages it, nothing has
to exist under `/usr`, and it carries the interface name and the report path so
it is rewritten on every start. What it writes is
[`docs/interface-report.md`](../interface-report.md) -- the contract a modem
helper writes, which is why 0047 took the modem's name off it.

`--script-security 2` is not decoration. **The default in OpenVPN 2.6 is
`SSEC_BUILT_IN`, which runs no user script at all**: `script_security_level` is
initialised to it in `run_command.c`. Without the argument openvpn says so once,
at verb 1, and then reports nothing forever -- an apply that succeeds, a tunnel
that comes up, and no routes. `tests/live/openvpn.sh` asserts the argument for
that reason alone.

The metric is netcfgd's. A reported route carries none and the planner fills in
the interface's `preference`, which is the entire point: `preference` is one
number an operator wrote down that ranks a tunnel against a wired link against a
bearer, and a route openvpn installed could not participate in it.

## What was measured rather than assumed

Against a real `openvpn` 2.6.14 in a network namespace with a real `tun`, in
static-key point-to-point mode -- which needs no server, because there is no
handshake and the tunnel is up as soon as the device opens.

- The route environment **survives `--route-noexec`**. `setenv_routes` runs in
  `do_init_route_list` when the list is built; the flag only skips `add_routes`.
- IPv4 arrives as `route_network_N` plus a **dotted** `route_netmask_N`; IPv6
  arrives as `route_ipv6_network_N` already in CIDR. The conversion is the
  script's one piece of arithmetic.
- `route_gateway_N` is filled in even for a route whose config named no gateway:
  it becomes the tunnel's own endpoint.
- `N` is **not contiguous**. `setenv_route` skips a route that is not fully
  defined and the counter moves on anyway, so the script scans a range instead
  of stopping at the first gap. Reading `route.c` is what said so; a script that
  broke on the first gap would have passed every test written here.

## The cost, stated plainly

**`redirect-gateway` for IPv4 does not survive `--route-noexec`, and openvpn
offers no way to learn that it was asked for.**

The `0.0.0.0/1` and `128.0.0.0/1` pair it installs is added inside
`redirect_default_route_to_vpn`, which is called from `add_routes` -- the
function the flag skips. The `redirect_gateway` environment variable is set in
the same skipped branch. So a server that pushes `redirect-gateway def1` reaches
a netcfgd-managed tunnel as *no default route at all*, silently.

The IPv6 half **does** survive, because `::/3`, `2000::/4`, `3000::/4` and
`fc00::/7` are appended to the option list in `do_init_route_ipv6_list`, before
the list is built. Both halves were checked by running them.

Three ways out were considered:

- **Read the `.ovpn` for `redirect-gateway`.** Refused: 0046 makes the file the
  operator's and netcfgd does not open it. A grep for one option is still
  opening it, and the next option would be easier to justify than this one.
- **Let openvpn install its routes and pass `--route-metric`.** This is the
  tempting one: it keeps `redirect-gateway` working and still ranks the tunnel.
  Refused because it leaves two writers on one routing table, which is the
  failure 0047 is about. netcfgd would know a number and nothing else -- it
  could not name those routes in a plan, explain them, or withdraw them when
  the tunnel went, and drift would report every one of them as foreign.
- **Warn when a tunnel reports no default route.** Refused: a split tunnel is
  the ordinary case and would warn on every reconcile, which teaches an
  operator to ignore the warning that matters.

So the answer is the local one, and it is better than what it replaces: an
operator who wants everything to go down the tunnel writes it in the document.

```
interface vpn0 {
	preference = 700
	routes     = "default"
	openvpn { config = "/etc/netcfgd/work.ovpn" }
}
```

That route is visible, greppable, ranked against every other uplink by
`preference`, and withdrawn when the tunnel goes -- none of which is true of a
default route a server pushed. The tunnel is a point-to-point device, so it
needs no gateway, which is the same answer a PPPoE session already gets.

## When a report is believed

A report is acted on when the document asks for `reported` addressing **or when
netcfgd started the writer itself**. A tunnel is the second: netcfgd generated
the script, launched the process that runs it, and named the interface. Making
an operator also write `config = "reported"` would mean a tunnel silently kept
none of its routes until somebody added a word whose absence explained nothing.

A report for an interface the document says nothing about is still ignored.
Installing a default route on the strength of a file somebody dropped in `/run`
is not something to invent.

## What is deliberately not taken

**The nameservers.** `openvpn` puts a pushed `dhcp-option DNS` in the same
environment as `foreign_option_N`, and the report already has a `dns=` key, so
this is three lines away. It is left out because a VPN's nameservers usually
want *split* DNS -- resolve the company's names through the tunnel and
everything else locally -- and that is a routing-domain question decision 0007
governs, not a reporting one. Taking them as a flat list would deliver the
wrong thing convincingly.

**`pppd`.** It has `ip-up-script` and could report through the same file; a PPP
link's routes are only ever the default one, which `nodefaultroute` already
stops and which the document already spells `routes = "default"`. What `pppd`
*does* have that nothing else does is `usepeerdns`, and that is the DNS question
above.

## Consequences

- An operator's `.ovpn` that sets its own `--route-up` loses it: netcfgd's
  argument comes after `--config` and wins. Nothing can warn about this without
  reading the file.
- A tunnel's routes now appear in `ncfg plan` with a reason, are tagged with
  netcfgd's route protocol, and go when the tunnel goes.
- `tests/live/tunnel.sh` drives a real openvpn and is not run under `NCFG_LIVE`,
  for the reason `ap.sh` is not: openvpn is a package a machine with no VPN has
  no reason to have.
