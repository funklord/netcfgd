# 0036: The shim is not the roadmap

Status: accepted
Date: 2026-07-31
Milestone: direction; nothing here is scheduled

## Context

Design section 9.5 lists a tier 3 -- "out of scope, reported as unsupported":
NM's VPN plugin architecture, ModemManager specifics, Wi-Fi P2P, team, OVS.
That wording reads as a statement about netcfgd. It is not, and reading it that
way produced a summary of the project's future that was wrong in five places at
once.

This record fixes the wording, states the scoping rule that actually governs,
and writes down the direction so the next person does not have to re-derive it
from a tier list that was never about them.

## Tier 3 bounds the shim, not netcfgd

**Section 9.5 is a list of things the NetworkManager adapter does not expose.**
It says nothing about whether netcfgd will ever do them.

The distinction matters most where the two disagree, and they disagree
deliberately. netcfgd is expected to grow VPN support, modem support and
complete wifi. NM's interfaces for those are not the shape netcfgd wants, and
constraint 6 forbids letting an adapter's model reach inward. So the honest
end state is a netcfgd that does far more than the shim projects, with the shim
reporting the difference as `unmanaged`/`unavailable` -- which is what section
9.5 asks for, once it is read as a statement about the adapter.

Section 9.5's wording is amended to say so.

## The scoping rule

**Virtual networking features that are not directly useful for real-world
networking, or are not very common use cases, are deferred indefinitely.**

Stated by the project owner, and the sharp end of it is worth quoting: an
overgrown VM topology is not a common use case, it is a failure. A feature
whose users are mostly people who have built something they should not have
built does not earn a place in a tool that has a size budget and an embedded
tier.

The rule is forward-looking. It is not a demand to remove what is already
built, and three existing kinds are worth defending explicitly against a
future misreading:

- **`ifb`** is what makes `ingress_bandwidth` work (decision 0023's amendment).
  Shaping arriving traffic is ordinary networking.
- **`dummy` and `veth`** are what the live test suite runs on. They are also
  how anything gets tested without hardware.
- **`vrf` and `macvlan`** are used on real routers and real container hosts,
  not only in VM sprawl.

`tun`/`tap` are schema-only, added at the M4 freeze and never implemented. The
rule suggests they stay that way.

**Open vSwitch is the immediate casualty**, and it is a clean fit for the rule:
a second software datapath with its own database, whose common deployment is
exactly the overgrown-VM case the rule names.

## Direction, by area

Nothing below is scheduled. It is written down so that the tier list is not
mistaken for the plan a second time.

**VPN -- openvpn and ipsec, end-stage.** Not a section 1.5 non-goal; that
section excludes routing daemons, DNS servers, a supplicant reimplementation, a
GUI in the core, a hard D-Bus dependency, firmware management and configuration
management. A VPN is none of those. It fits the pattern already established
three times over: netcfgd writes a configuration and supervises a daemon, as it
does for `pppd`, `wpa_supplicant` and `hostapd`. IPsec is the harder of the two
-- strongswan and libreswan disagree about nearly everything, and IKE
configuration is large. Neither needs anything from NM.

**Modems matter.** The fork to settle before any code: ModemManager as a
backend, which is D-Bus and therefore an optional package by constraint 3, or
QMI/MBIM directly, which is large but keeps the dependency posture. This
deserves its own record.

**Wifi, completely.** Decision 0016 already drew the line and it holds: the
mechanism belongs to `wpa_supplicant` and `hostapd`, the *policy* is netcfgd's,
and key management is never ours. Everything wanted here is configuration
surface on top of that, which is the cheap side of 0016's table:

| Feature | Where it lives | Verified |
|---|---|---|
| Zero Handoff -- forcing a client to one AP | `DENY_ACL`, `DEAUTHENTICATE` over hostapd's control socket; `macaddr_acl`, `deny_mac_file` in its config | yes |
| 802.11k, neighbour reports | `rrm_neighbor_report` | yes |
| 802.11v, BSS transition | `bss_transition` | yes |
| 802.11r, fast transition | `ieee80211r` | **absent from Debian's hostapd** |
| 802.11s, mesh | `wpa_supplicant` `mode=5` | yes |
| WDS, the repeater backbone | `wds_sta` | yes |
| Multi-AP / EasyMesh | `multi_ap` | yes |

Two things follow from that table.

**Zero Handoff predates the standards and is not built from them.** It forces a
device onto a chosen AP by making every other AP refuse to talk to it -- a
per-client deny list everywhere else, plus a deauthentication to shake the
client loose. Standardised roaming is still not everywhere, so this remains
worth supporting. It splits along netcfgd's existing seam: the per-AP
enforcement is single-host and needs only an `access_point` client list that
can be updated at runtime, while deciding *which* AP owns a client is
coordination between machines and therefore section 11's territory. A site can
drive the decision over the socket until then.

**802.11r is not available in Debian's hostapd.** Checked directly: `ieee80211r`
is not in the binary and its parser rejects the option. OpenWrt's build
generally includes it. So fast transition is a per-distribution packaging
question before it is a netcfgd feature, and any support for it has to detect
that rather than assume -- exactly as decision 0026 handles the rest of
hostapd's optional pieces.

**Bonding is done** -- `InterfaceKind::Bond`, since M4. Only *teaming* (teamd)
is absent, and it stays absent: it does the same job and has been deprecated by
its own sponsor in favour of bonding.

**Configuring switches over SNMP is not this.** It is worth separating from
Open vSwitch, because the two get conflated and are opposites. OVS is a switch
running *on this host*; SNMP switch management configures *other devices*. The
second is not this machine's network configuration at all, and section 11.4's
"two trees, never one" already describes the shape it would need -- a fleet
tree, entirely separate from `/etc/netcfgd`. It is a legitimate future
direction and it is not a single-host feature.

## One question this leaves open

Decision 0035 walks away from an unmanaged device without withdrawing the
credentials netcfgd left on it -- a WireGuard key in the kernel, a supplicant
holding passphrases, a hostapd configuration under `/run`. That is right for
the steady state and unsettled for the *transition*: handing hardware to
somebody else should probably take the keys out first.

The shape that fits netcfgd rather than a GUI is the one `--allow-disruption`
already uses: detect that a plan would strand credentials, refuse, and make the
operator say which they meant. A prompt belongs to whichever client is in
front of a person; the core has no UI and must not grow one to be safe.
