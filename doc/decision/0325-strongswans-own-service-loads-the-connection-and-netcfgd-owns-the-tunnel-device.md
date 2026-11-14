# 0325: strongSwan's own service loads the connection, and netcfgd owns the tunnel's device

Status: accepted
Date: 2026-11-14
Supersedes: the sentence of [0323](0323-an-ipsec-tunnel-is-an-xfrm-interface-and-the-swanctl-file-is-the-operators.md)
saying "the document points at it", and of
[0324](0324-netcfgd-drives-the-machines-charon-and-places-the-virtual-ip-itself.md)
the loading with `swanctl --load-conns` and the open EAP-secret question; its
other half -- one charon, the virtual IP through the report -- stands

## Context

0323 had the document point at the operator's `swanctl.conf`, as an `openvpn`
block points at a `.ovpn`; 0324 had netcfgd drive the machine's one charon, and
left open where an EAP secret goes. Building step three asked the question
first: does netcfgd need to load the file at all?

Measured in Alpine 3.21 with `openrc` and `strongswan`: the package's `charon`
service starts charon and, in `start_post`, runs `swanctl --load-all`, whose
`swanctl.conf` ends `include conf.d/*.conf`; its `reload` does the same. It
says `need net`, which netcfgd's OpenRC script provides (`provide net`).
OpenWrt's and Debian's packages are not measured here; that their services
load `/etc/swanctl` the same way is the claim to check when either is a
target, and on this host (Debian, strongSwan 6.0 with the legacy starter only)
there is no `swanctl` service at all.

## Decision

**The operator's connection lives in `/etc/swanctl/conf.d/`, and strongSwan's
own service loads it** -- with its secrets, in the same file or beside it, in
strongSwan's own store. netcfgd loads nothing into charon and holds no IKE
credential.

**netcfgd owns the tunnel's device and its addressing**, which is what makes it
a tunnel like the others: `device ipsec0 { xfrm { if_id = 7 } }` (step one),
the report the shipped `ipsec-updown` writes and `config = "reported"` takes
(step three), and the host route that keeps a full tunnel's peer outside it
(10.860). The file binds itself to the device with `if_id_in`, `if_id_out` and
the `updown` line -- three lines an operator adds to what a provider hands out.

Why not load it: a second loader of one directory is two owners of one charon
state, and whichever ran last would win -- the arrangement this project exists
to avoid. And charon's secret store is where strongSwan's tooling, its
documentation and every provider's instructions expect the credential.

## Consequences

- `ncfg` cannot yet bring a tunnel up or down; a connection with
  `start_action = start` comes up with charon, and `swanctl --initiate` or
  `--terminate` does the rest. A wifi-tier "connect the VPN" is a later step:
  a typed request (0117) that runs those two, never a file.
- The EAP secret is strongSwan's (`secrets { eap-... }`), root-readable in
  `/etc/swanctl`, and not an `@secret:`.
