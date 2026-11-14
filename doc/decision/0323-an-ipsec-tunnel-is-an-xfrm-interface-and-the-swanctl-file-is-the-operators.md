# 0323: an IPsec tunnel is an XFRM interface, and the swanctl file is the operator's

Status: accepted for the shape; the XFRM interface is built (10.856), the IKE half is not
Date: 2026-11-14
Milestone: the second half of what 0036 called the VPN end-stage
Extends: [0036](0036-the-shim-is-not-the-roadmap.md), [0046](0046-the-ovpn-file-is-the-operators.md)

## Context

0036 put VPN in netcfgd -- OpenVPN first, "IPsec later and harder". 0046 built
OpenVPN: the tunnel is an interface, and the `.ovpn` file is the operator's,
pointed at and not generated. IPsec waited. The holder, 2026-11-14: if nothing
else is left, do IPsec. ml350g6-01 carries a real case: an IKEv2 road-warrior
profile for a commercial VPN (EAP-MSCHAPv2, a virtual IP from the server, the
whole of IPv4 through it), in strongSwan's legacy `ipsec.conf`.

What IPsec has that OpenVPN does not:

- **One IKE daemon per machine.** charon negotiates every connection; there is
  no process per tunnel to supervise the way there is an `openvpn` per `.ovpn`.
- **Policy-based by default.** A tunnel is a pair of XFRM policies matching
  traffic, not a device -- so there is nothing for an `interface` block to
  address, route through or measure.
- **Two implementations that disagree**, strongSwan and libreswan, as 0036 said.

## Decision

**The tunnel is an XFRM interface** (`ip link add ipsec0 type xfrm if_id 7`):
a netdev whose traffic the kernel encrypts by the SAs carrying the same
`if_id`. That makes IPsec route-based, which is exactly the shape every other
tunnel here has -- an interface with addresses, routes, a metric, a firewall
zone and a place in a linkset -- and it is not strongSwan's or libreswan's:
both support it (strongSwan's `if_id_in`/`if_id_out`, libreswan's
`ipsec-interface`). So it is built first, alone, and does not wait on the
choice below. `device ipsec0 { xfrm { if_id = 7 } }`; the id is required and
non-zero, which the kernel also requires.

**strongSwan, driven through `swanctl`, with the connection file the
operator's** -- 0046's reasoning unchanged: a provider hands out the profile,
and `swanctl.conf`'s surface is as large as OpenVPN's. The document points at
it; the file says `if_id_in = if_id_out = 7` and so binds itself to the
interface. libreswan is not done: OpenWrt and Alpine package strongSwan with
`swanctl`, Debian both, and one is what a person can be told to install.

**Not built yet, and to be measured before it is**: whether netcfgd runs its
own charon (its own `strongswan.conf` and vici socket under `/run/netcfgd`) or
loads connections into the system's; how a virtual IP the server assigns
reaches the interface (charon's `install_virtual_ip_on`, or a report through
vici the way OpenVPN's script reports, 0046); and where the EAP secret lives
(`@secret:`, handed to charon over vici, rather than in the file). This host's
strongSwan has no vici plugin and no `swanctl` -- only the legacy starter -- so
that half is measured in a container or under hull.

## Rejected

- **Policy-based tunnels driven by netcfgd.** No interface, so nothing in the
  document could say anything about the traffic, and the planner would need a
  second model of "where packets go" beside routes.
- **netcfgd generating `swanctl.conf`.** 0046's reason: a second configuration
  language for IKE, permanently behind the first.
- **VTI** (`ip link add type vti`). The older route-based device: keyed by
  marks that collide with every other use of marks, and IPv4 and IPv6 need two.
  XFRM interfaces (Linux 4.19) replaced it.
