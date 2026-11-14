# 0324: netcfgd drives the machine's charon, and places the virtual IP itself

Status: accepted, from measurement; not built
Date: 2026-11-14
Milestone: the second half of what 0036 called the VPN end-stage
Extends: [0323](0323-an-ipsec-tunnel-is-an-xfrm-interface-and-the-swanctl-file-is-the-operators.md)

## Context

0323 left three questions to measure before netcfgd's IKE half is built:
whether netcfgd runs its own charon, how a virtual IP the server assigns
reaches the tunnel's interface, and where an EAP secret goes. This host's
strongSwan has no vici and no `swanctl`, so they were measured in Alpine 3.21
(strongSwan 5.9.14) by `tests/ipsec/probe.sh`: two network namespaces, a
charon in each with its own `strongswan.conf` and vici socket, IKEv2 with a
pre-shared key, a virtual IP from the server's pool, and the client's child SA
carrying `if_id_in = if_id_out = 7` onto the XFRM interface step one makes.

Measured:

- the child SA came up and both of the client's states carry `if_id 0x7`;
- with `install_virtual_ip_on = ipsec0`, charon put `10.98.0.1/32` on the
  interface, and pings to the far side through it were answered;
- with `install_virtual_ip = no`, charon installed nothing and reported
  `local-vips=[10.98.0.1]` over vici (`swanctl --list-sas --raw`); placing that
  address on `ipsec0` from outside charon, the pings were answered again.
- two charons in one network namespace, each with its own `/run`
  (`tests/ipsec/twin.sh`): the second logged `unable to bind socket: Address
  in use`, twice, IPv4 and IPv6;
- a child's `updown` command, run by charon on `up-client`, was handed
  `PLUTO_MY_SOURCEIP=10.98.0.1`, `PLUTO_IF_ID_IN=7`, `PLUTO_IF_ID_OUT=7` and
  `PLUTO_PEER_CLIENT=10.99.0.1/32` -- the virtual IP, the device's id, and what
  to route into it -- with `install_virtual_ip = no`.

## Decision

**netcfgd drives the machine's one charon and does not run its own.**
Two charons cannot share a network namespace -- the second cannot bind IKE's
port, measured above -- so a netcfgd-run charon would conflict with any system
strongSwan, and on OpenWrt, Alpine and Debian the system's is a package and a
service already (`swanctl`'s). Running it stays the init system's; connections are loaded into
it through its vici socket.

**charon is told `install_virtual_ip = no`, and netcfgd places the virtual
IP on the tunnel's interface, through the interface report**
(`doc/interface-report.md`), the contract OpenVPN's addressing already uses
(0046). netcfgd ships an updown command; the operator's child names it with the
interface, `updown = <netcfgd's ipsec updown> ipsec0`, beside the
`if_id_in`/`if_id_out` the file needs anyway; and on `up-client` it writes the
virtual IP and the peer's subnets as the report for `ipsec0`, and on
`down-client` takes it away. `install_virtual_ip_on` names one device for the
whole of charon, which is wrong the moment a machine has two tunnels; a report
per tunnel is right for any number. Event-driven, as charon runs it, and no
vici client is needed to read anything: the address is an ordinary reported
address on an interface netcfgd owns.

**The connection file stays the operator's** (0323), loaded with
`swanctl --load-conns --file` against charon's vici socket, so netcfgd parses
none of it.

## Not decided yet

- **Where an EAP secret goes.** The measured case used a pre-shared key in the
  file. An `@secret:` handed to charon over vici (`load-shared`) keeps it out of
  the file, as every other credential here is kept; to be measured with
  EAP-MSCHAPv2, which needs a server certificate the probe does not yet make.
- **Speaking vici.** Loading through `swanctl` is what was measured and is
  enough; netcfgd speaking vici's wire format itself, as it speaks netlink, is
  wanted only if something must be read that the updown command is not handed.

## Rejected

- **A netcfgd-run charon in a private mount namespace.** Its own `/run` keeps
  the pid files apart, and the port is still one per namespace: the twin
  measurement's second charon could not bind it.
- **`install_virtual_ip_on`.** One device for every tunnel.
- **Reading the virtual IP over vici** (`list-sas`'s `local-vips`, measured to
  work). A poll, or an event subscription and a vici client, for what the
  updown command is handed when it happens.
