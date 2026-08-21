//! What the kernel and the backends currently say is true.
//!
//! The other half of the desired/observed pair (`docs/decisions/0005`). This
//! lives in the model rather than in `netcfgd-observe` because both the
//! producer and the planner depend on it, and because it is written to
//! `/run/netcfgd/observed/` where it is as much a documented artifact as the
//! desired-state document is.

use crate::route::RouteScope;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Whether netcfgd installed an object.
///
/// Drift detection is meaningless without this distinction, and the asymmetry
/// between the variants is deliberate: under-claiming ownership costs a little
/// convenience, over-claiming it deletes somebody's manual change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
	/// Carries netcfgd's protocol tag. Ours to reconcile.
	Ours,
	/// Carries somebody else's tag, or none. Never reconciled away; reported.
	Foreign,
	/// The kernel could not tell us. Pre-5.18 kernels have no `IFA_PROTO`, so
	/// address ownership falls back to recorded prior state, which cannot
	/// distinguish our address from an identical one added by hand
	/// (`docs/decisions/0002`). Treated as [`Ownership::Foreign`] for any
	/// decision that would remove something.
	#[default]
	Unknown,
}

impl Ownership {
	/// Whether an object may be removed to satisfy the desired state.
	///
	/// Only [`Ownership::Ours`] qualifies. This is the single place that
	/// decision is made, so that no planner path can accidentally widen it.
	#[must_use]
	pub fn may_remove(self) -> bool {
		matches!(self, Self::Ours)
	}
}

/// Which addressing source produced an object.
///
/// Decision 0006 rule 7 turns on this: a missing static address is re-added,
/// but a missing DHCP address means the *lease* is gone, so the remedy is to
/// restart the backend rather than to add the address back. Without knowing
/// which source produced what, the planner would fight the DHCP client for
/// ownership of its own lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
	/// Written in the config.
	Static,
	/// From a `DHCPv4` lease.
	Dhcp4,
	/// From a `DHCPv6` lease.
	Dhcp6,
	/// From a router advertisement.
	Slaac,
	/// IPv4 link-local autoconfiguration.
	LinkLocal,
	/// Built from a delegated prefix.
	Delegated,
}

/// A link as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedLink {
	/// Interface name.
	pub name: String,
	/// Kernel interface index.
	pub index: u32,
	/// Link kind as the kernel spells it: `veth`, `bridge`, `vlan`, or empty
	/// for a plain device.
	#[serde(default)]
	pub kind: String,
	/// Whether this is a radio.
	///
	/// **The kernel's answer, not the document's.** `kind` cannot supply it --
	/// a real wireless device is a plain device and reports an empty kind, the
	/// same as an ethernet port -- and the document cannot either, because a
	/// `device` block's `wifi { }` section carries things like `portal_check`
	/// that are meaningful on anything. The planner needs the difference to
	/// decide whether a supplicant belongs on an interface, and reading sysfs
	/// from the planner would make it untestable against fixtures whose
	/// interfaces do not exist.
	#[serde(default)]
	pub wireless: bool,
	/// Administrative state.
	pub up: bool,
	/// Whether the link has carrier. Distinct from `up`: an interface can be
	/// administratively up with the cable out.
	pub carrier: bool,
	/// Whether this uplink's probe says it carries traffic.
	///
	/// `None` where no probe is configured or none has finished yet, and that
	/// is **not** the same as `Some(false)`: a link nobody asked about must
	/// keep its routes, so only an explicit `false` withholds them. A reader
	/// that conflated the two would take the network away from every interface
	/// on a machine that configured no probes at all.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub reachable: Option<bool>,
	/// Current MTU.
	pub mtu: u32,
	/// Current hardware address.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mac: Option<String>,
	/// Bridge or bond this link is enslaved to.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub master: Option<String>,
	/// The device this virtual link rides on, where it has one.
	///
	/// A VLAN's and a macvlan's parent, a tunnel's and a `VXLAN`'s underlay: one
	/// field, because the document has one word for all four. What the kernel does
	/// with a *changed* one is two answers, though -- a VXLAN and a tunnel move,
	/// while a VLAN and a macvlan accept the request and ignore it, so the second
	/// pair is corrected by remaking the interface (0059, 0060).
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub parent: Option<String>,
	/// Which of the offloads netcfgd manages are currently on.
	///
	/// Kernel feature names, and only the ones the model can express -- a
	/// device reports dozens and storing all of them would put a page of
	/// driver detail in `/run` for five fields. A name absent here is off or
	/// unsupported, which the kernel does not distinguish either.
	#[serde(default)]
	pub offloads: Vec<String>,
	/// The IPv6 interface identifier, where one is set.
	///
	/// `None` covers both "no token" and "this device cannot have one" -- a
	/// dummy or any other `NOARP` device does no neighbour discovery, and the
	/// kernel refuses a token on it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ipv6_token: Option<String>,
	/// The root qdisc the kernel currently runs on this link.
	///
	/// Always present in practice -- there is no such thing as an interface
	/// without one, and an interface netcfgd has never touched reports
	/// whatever `net.core.default_qdisc` gave it. `None` means the dump did
	/// not mention it, not that there is none.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub qdisc: Option<String>,
	/// The shaped rate in **bits** per second, where the qdisc shapes.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub qdisc_bandwidth_bits: Option<u64>,
	/// Whether the root qdisc was told it is shaping traffic on the way in.
	#[serde(default)]
	pub qdisc_ingress: bool,
	/// The device traffic arriving here is redirected to, if any.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ingress_redirect: Option<String>,
	/// Whether this interface forwards, from the `forwarding` sysctls.
	///
	/// `Some(true)` only when both the IPv4 and the IPv6 one are set: half a
	/// forwarding interface routes one family and silently blackholes the
	/// other, and reporting that as "on" would make a plan claim there was
	/// nothing to do. `None` means the sysctls could not be read, which is the
	/// ordinary case in a container without `/proc/sys` mounted writable.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub forwarding: Option<bool>,
	/// Whether this interface's radio is switched off, where it has one.
	///
	/// `None` for anything that is not a radio, and for a radio whose rfkill
	/// switch could not be found -- a kernel without `CONFIG_RFKILL`, or a driver
	/// that registers none. Nothing is planned on a `None`: netcfgd does not know
	/// and says so.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub rfkill: Option<ObservedRfkill>,
	/// Whether this interface prefers a temporary address, from `use_tempaddr`.
	///
	/// `Some(true)` for the kernel's `2`, which is RFC 4941 with the temporary
	/// address preferred for outgoing connections -- the only thing the document
	/// can ask for. `Some(false)` covers both `0` and `1`: the middle value
	/// generates a temporary address and prefers the stable one, which no config
	/// here can request, so netcfgd reports it as "not what was asked for" and
	/// leaves it alone unless it wrote it itself.
	///
	/// `None` means the sysctl could not be read -- an IPv6-disabled kernel, or a
	/// container without `/proc/sys`. Nothing is written on one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub privacy: Option<bool>,
	/// Whether a router advertisement arriving here would be acted on.
	///
	/// `None` means the sysctl could not be read -- an IPv6-disabled kernel, or a
	/// container without `/proc/sys`. Nothing is written on one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub accept_ra: Option<ObservedAcceptRa>,
	/// Whether netcfgd created this link.
	///
	/// Netlink has no protocol field for links, so unlike an address or a
	/// route this cannot be read back from the kernel. It comes from recorded
	/// prior state in `/run`, and it defaults to [`Ownership::Unknown`] --
	/// which means a link nobody has a record of is never deleted.
	#[serde(default)]
	pub ownership: Ownership,
	/// Whether a `WireGuard` private key is loaded in the kernel for this link.
	///
	/// Read as the *presence of the derived public key*, never by asking for
	/// the private one -- `netcfgd_sys::wg::DeviceState` deliberately does not
	/// carry a field for that, and this must not become the reason it grows
	/// one. A keyless device reports no public key and a keyed one reports the
	/// key derived from it, checked against a real kernel rather than assumed.
	///
	/// `false` for every link that is not `WireGuard`, and for a `WireGuard`
	/// device that has been created and not yet configured.
	#[serde(default)]
	pub private_key_loaded: bool,
	/// A bond's own settings, where this link is one.
	///
	/// The bridge's story in a second kind whose name encodes nothing (0057).
	/// The kernel takes both of these on a bond that already exists -- checked
	/// by asking it -- which is what makes correcting them a `link.set_bond`
	/// rather than the delete and create a VLAN would need.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bond: Option<ObservedBond>,
	/// A bridge's own settings, where this link is one.
	///
	/// The same question 0054 asked of a `WireGuard` device, in the kind whose
	/// name encodes nothing: `stp` and `forward_delay` are applied when the
	/// link is created and were never compared again, so editing either did
	/// nothing and said nothing.
	///
	/// In **seconds**, as the document spells them and as every tool and manual
	/// page does. The kernel counts hundredths, and the conversion lives beside
	/// the one that writes them.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bridge: Option<ObservedBridge>,
	/// A macvlan's own settings, where this link is one.
	///
	/// One field, and the kernel has three answers for it: it moves the mode
	/// freely among `private`, `vepa` and `bridge`, and refuses either direction
	/// between any of those and `passthru`. Decision 0058.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub macvlan: Option<ObservedMacvlan>,
	/// A VLAN's id and tag protocol, where this link is one.
	///
	/// Neither can be corrected in place: `vlan_changelink` accepts a request to
	/// change either and ignores it, so an edited id is applied by deleting the
	/// interface and making it again. This is what says one has moved -- and a
	/// VLAN is usually named for its id, so the operator who gets any use out of
	/// it is the one who named it something else. Decision 0059.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub vlan: Option<ObservedVlan>,
	/// A tunnel's endpoints, where this link is one of the seven kinds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub tunnel: Option<ObservedTunnel>,
	/// A `VXLAN`'s own settings, where this link is one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub vxlan: Option<ObservedVxlan>,
	/// What a `WireGuard` device actually holds, where this link is one.
	///
	/// The kernel reports all of this for free on the request that answers
	/// [`ObservedLink::private_key_loaded`], and netcfgd threw it away for as
	/// long as `WireGuard` has existed here -- which is why an edited listen port
	/// or a **deleted peer** planned nothing at all. Decision 0054.
	///
	/// Nothing secret is in it. The device's own public key is derived by the
	/// kernel and is the thing a peer is given; a preshared key is a boolean,
	/// exactly as `netcfgd_sys::wg::PeerState` reports one; and the private key
	/// has no field here for the same reason it has none there.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub wireguard: Option<ObservedWireGuard>,
}

/// A bond's own settings, as the kernel reports them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBond {
	/// The mode, as the document spells it.
	///
	/// Translated in the observer, so the planner compares a `balance-rr`
	/// against a `balance-rr` rather than a number against a name -- the same
	/// call decision 0052 made for an access point's band.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mode: Option<String>,
	/// Link monitoring interval in milliseconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub miimon: Option<u32>,
}

/// A bridge's own settings, as the kernel reports them.
///
/// Only the ones netcfgd can set. A bridge has dozens of parameters and
/// carrying all of them would put a page of kernel detail in `/run` to answer a
/// question about six -- the same call `ObservedLink::offloads` already makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBridge {
	/// Whether spanning tree is running.
	#[serde(default)]
	pub stp: bool,
	/// Forward delay in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub forward_delay: Option<u32>,
	/// Hello interval in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub hello_time: Option<u32>,
	/// Address ageing time in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ageing_time: Option<u32>,
	/// Bridge priority.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub priority: Option<u16>,
	/// Whether the bridge is VLAN-aware.
	#[serde(default)]
	pub vlan_filtering: bool,
}

/// What one event hook on one interface was last told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedHookState {
	/// Which interface.
	pub interface: String,
	/// Which phase. `lease` and `carrier` are the two that have one.
	pub phase: crate::HookPhase,
	/// What the hook was told, in the phase's own vocabulary.
	///
	/// A `lease`'s address in CIDR notation -- one address, the first qualifying one
	/// in canonical order, because a lease *is* one address and an interface carrying
	/// two that netcfgd did not install has something else going on. A `carrier`'s
	/// `up` or `down`.
	///
	/// A string rather than a per-phase type: what netcfgd does with it is compare
	/// it to the next one, and a type per phase would be three types for one
	/// comparison.
	pub value: String,
}

/// Whether a radio is switched off, and by which of the two switches.
///
/// Both are read because the remedy differs and nothing else can tell them apart:
/// a soft block is software and comes back with one command, a hard block is a
/// physical switch and no amount of configuration will move it.
///
/// netcfgd reads the **phy's own** switch, which is the one the driver obeys. A
/// laptop usually has a second `wlan` switch as well -- a Dell here reports
/// `dell-wifi` beside `phy0` -- which is the platform button's, and whether
/// blocking that one propagates to the phy was not measured: doing so means
/// switching off somebody's real radio. Decision 0062 says what is known and what
/// is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRfkill {
	/// Which switch this was read from, as the kernel names it: `phy0`.
	pub switch: String,
	/// Blocked in software. `rfkill unblock wifi` clears it.
	#[serde(default)]
	pub soft: bool,
	/// Blocked by hardware: a physical switch, or a firmware one the kernel
	/// cannot override. Nothing in software clears this.
	#[serde(default)]
	pub hard: bool,
}

/// What the kernel will do with a router advertisement on this interface.
///
/// Two fields because one of them is not enough to act on and the other is not
/// enough to explain. `accept_ra=1` -- the kernel's default -- means "accept
/// unless this interface forwards", so the same value is the working state on a
/// laptop and the broken one on a router, and `ip addr` shows nothing either way.
/// Decision 0073.
///
/// The reading of the two together is done in the observer, where both halves are
/// already in hand, and only the answer travels -- the rule every comparison in
/// this project has had to learn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAcceptRa {
	/// The sysctl itself: `0` never, `1` unless this interface forwards, `2`
	/// always. netcfgd writes only `1` and `2`, and reports whatever it finds.
	pub value: u8,
	/// Whether an advertisement would actually be acted on, which is `value`
	/// read against this interface's **IPv6** forwarding sysctl. The v4 one has
	/// nothing to do with it, so this deliberately does not use
	/// [`ObservedLink::forwarding`], which is only `Some(true)` when both
	/// families forward.
	pub effective: bool,
}

impl ObservedRfkill {
	/// Whether the radio is off, by either switch.
	#[must_use]
	pub fn blocked(&self) -> bool {
		self.soft || self.hard
	}
}

/// A macvlan's own settings, as the kernel reports them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedMacvlan {
	/// The mode, as the document spells it.
	///
	/// Named here rather than numbered, for the reason [`ObservedBond::mode`] is:
	/// the planner compares a `bridge` against a `bridge`. `None` is a mode
	/// netcfgd has no name for -- somebody else's macvlan, configured with
	/// something this build cannot express -- and nothing is corrected on one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mode: Option<String>,
}

/// A VLAN's id and tag protocol, as the kernel reports them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVlan {
	/// The VLAN id.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub id: Option<u16>,
	/// The tag protocol, as the document spells it: `dot1q` or `dot1ad`.
	///
	/// Named rather than carried as an ethertype, for the reason
	/// [`ObservedBond::mode`] is named: the planner compares what the config says
	/// against a word. `None` for a tag protocol netcfgd has no name for, which
	/// is not compared -- an interface is not deleted over a value this build
	/// cannot describe.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub protocol: Option<String>,
}

/// A tunnel's endpoints, as the kernel reports them.
///
/// One struct for seven kinds across three attribute families, because what the
/// document says about all of them is one struct too ([`crate::TunnelConfig`]).
/// The reading is per family; the comparison is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedTunnel {
	/// Local endpoint, where the kind has one netcfgd sets.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub local: Option<std::net::IpAddr>,
	/// Remote endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub remote: Option<std::net::IpAddr>,
	/// Outer TTL. Zero is the kernel's word for "inherit from the inner packet".
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ttl: Option<u8>,
	/// The GRE key, or a geneve tunnel's VNI.
	///
	/// One field for both because the document has one: a geneve tunnel needs a
	/// VNI and `key` is where it goes. `None` for the ip tunnels, which have
	/// neither.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub key: Option<u32>,
}

/// A `VXLAN`'s own settings, as the kernel reports them.
///
/// Two of these four cannot be corrected on a device that exists -- see
/// [`crate::VxlanConfig`] and decision 0058 -- and they are observed anyway,
/// because a plan that cannot fix something should still say it is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVxlan {
	/// The VXLAN network identifier.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub id: Option<u32>,
	/// Source address for the outer header.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub local: Option<std::net::IpAddr>,
	/// Remote unicast address, or the multicast group.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub remote: Option<std::net::IpAddr>,
	/// Destination UDP port.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub port: Option<u16>,
}

/// What a `WireGuard` device holds, as the kernel reports it.
///
/// The counterpart of [`crate::interface::WireGuardConfig`], and deliberately
/// not a copy of it: what the document holds is a `SecretRef` and a list sorted
/// by the operator's name for each peer, while this is what came back over
/// generic netlink. The comparison between them is decision 0054's, and it is
/// made on the fields below rather than on the structs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWireGuard {
	/// The public key the kernel derived from the private one.
	///
	/// Present exactly when a private key is loaded, which is what
	/// [`ObservedLink::private_key_loaded`] says in a boolean. It is here as
	/// well because it is the value an operator hands a peer, and `ncfg
	/// explain` having to say "yes, a key" rather than *which* key was a gap
	/// somebody had to run `wg` to fill.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub public_key: Option<crate::Key>,
	/// The port it listens on.
	///
	/// `None` where the kernel reports none. A document that names no port
	/// leaves the kernel to choose one, so a `None` here against a `None` in
	/// the document is agreement rather than a difference -- getting that
	/// backwards would reconfigure the device on every reconcile.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub listen_port: Option<u16>,
	/// The firewall mark on outgoing packets, where one is set.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmark: Option<u32>,
	/// Whether the private key the kernel holds is the one the store has now.
	///
	/// A boolean, computed in the observer, for the reason
	/// [`ObservedBackend::secret_matches`] is one: the value belongs in
	/// neither the observation nor the document, and what travels is the
	/// answer. The kernel reports the public key it derived and nothing that
	/// could be compared against a `SecretRef`, so netcfgd compares a digest of
	/// what it loaded against a digest of what the store holds -- the same
	/// trick decision 0053 plays on a file it will not read.
	///
	/// `None` means netcfgd could not tell: no record of what it loaded, a
	/// secret that cannot be resolved, or a device somebody else configured. A
	/// tunnel is not torn down over an unanswered question.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub key_matches: Option<bool>,
	/// Every peer, **sorted by public key**.
	///
	/// The kernel's own order is the order it happens to hold them in, which is
	/// not stable and is not the document's order either -- the document sorts
	/// by the operator's label, which the kernel has never heard of. Sorting by
	/// the one field both sides have is what makes the comparison a comparison
	/// rather than a diff of two arbitrary orders.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub peers: Vec<ObservedWgPeer>,
}

/// One peer of a `WireGuard` device, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWgPeer {
	/// The peer's identity, which is also the sorting key.
	pub public_key: crate::Key,
	/// Whether a preshared key is set.
	///
	/// A boolean because the kernel reports one: `WGPEER_A_PRESHARED_KEY` comes
	/// back zeroed for a peer that has one, which is the kernel refusing to
	/// hand back a secret and not an accident to work around.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub preshared_key: bool,
	/// Whether the preshared key this peer holds is the one the store has now.
	///
	/// The peer-sized twin of [`ObservedWireGuard::key_matches`], and the same
	/// digest comparison for the same reason: the kernel returns a preshared
	/// key **zeroed**, so `preshared_key` above can only say whether there is
	/// one. `None` where netcfgd has no record, where the secret will not
	/// resolve, and for every peer that has no preshared key at all.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub preshared_matches: Option<bool>,
	/// Where it is, as `host:port`, where it has an endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub endpoint: Option<String>,
	/// What is routed to it, sorted.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allowed_ips: Vec<String>,
	/// Persistent keepalive in seconds, where one is set.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub keepalive: Option<u16>,
}

/// An address as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAddress {
	/// Which interface carries it.
	pub interface: String,
	/// CIDR, as the kernel reports it.
	pub address: String,
	/// `IFA_PROTO`, where the kernel supports it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub proto: Option<u8>,
	/// Whether this is ours.
	pub ownership: Ownership,
	/// Which addressing source produced it, where that is recorded.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub origin: Option<Origin>,
}

/// A policy routing rule as the kernel reports it.
///
/// The same fields as [`crate::RoutingRule`] minus the `id`, which is
/// netcfgd's own handle and has no kernel counterpart, plus the ownership the
/// `FRA_PROTOCOL` tag establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRule {
	/// Consulted in ascending order. With the family, this is the kernel's key.
	pub priority: u32,
	/// Which family it is installed in.
	pub family: crate::RuleFamily,
	/// Source selector, in CIDR form.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub from: Option<String>,
	/// Destination selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub to: Option<String>,
	/// Incoming interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub iif: Option<String>,
	/// Outgoing interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub oif: Option<String>,
	/// Firewall mark selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmark: Option<u32>,
	/// Mask applied before comparing the mark.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmask: Option<u32>,
	/// Which table it consults.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// What it does on a match.
	pub action: crate::RuleAction,
	/// Ignore routes shorter than this.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub suppress_prefixlength: Option<u32>,
	/// Matches packets belonging to an l3mdev master.
	#[serde(default)]
	pub l3mdev: bool,
	/// Selectors are inverted.
	#[serde(default)]
	pub invert: bool,
	/// Whether this is ours.
	pub ownership: Ownership,
}

/// A route as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoute {
	/// Which interface it leaves by.
	pub interface: String,
	/// CIDR, or `default`.
	pub destination: String,
	/// Next hop.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub via: Option<IpAddr>,
	/// Metric.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub metric: Option<u32>,
	/// Table id.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// Preferred source.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub src: Option<IpAddr>,
	/// Scope.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub scope: Option<RouteScope>,
	/// `rtm_protocol`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub proto: Option<u8>,
	/// Whether this is ours.
	pub ownership: Ownership,
	/// Which addressing source produced it, where that is recorded.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub origin: Option<Origin>,
}

/// Which helper a backend entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
	/// A `DHCPv4` client.
	Dhcp4,
	/// A `DHCPv6` client, including prefix delegation.
	Dhcp6,
	/// A supplicant, for a radio or a wired 802.1X port.
	Supplicant,
	/// An access point this machine runs, rather than joins.
	AccessPoint,
	/// A `WireGuard` device.
	WireGuard,
	/// A `PPPoE` session.
	Pppoe,
	/// An `OpenVPN` tunnel.
	OpenVpn,
	/// A DNS delivery backend.
	Dns,
	/// A router advertisement daemon.
	RouterAdvert,
}

/// One VLAN the kernel holds on one interface.
///
/// No ownership field, unlike an address. There is no protocol tag for a
/// bridge VLAN, and unlike a link there is no useful `/run` record either --
/// the kernel creates VLAN 1 by itself, so "netcfgd did not add this" does not
/// mean "somebody else did". Authority comes from the document instead: see
/// [`crate::Interface::bridge_vlans`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBridgeVlan {
	/// Which interface carries it.
	pub index: u32,
	/// The VLAN id.
	pub vid: u16,
	/// Untagged ingress joins this VLAN.
	pub pvid: bool,
	/// Egress leaves untagged.
	pub untagged: bool,
}

/// What a `DHCPv6` client obtained by prefix delegation.
///
/// Not read from the kernel: a delegated prefix is not kernel state at all
/// until something derives an address from it. It comes from the client, which
/// netcfgd does not implement (decision 0004) and therefore has to be told by
/// -- through a file the client's hook writes and the observer reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
	/// The interface whose lease carries them.
	pub interface: String,
	/// The prefixes, in the order the lease listed them.
	///
	/// A list rather than one, because a lease may carry several and
	/// `PrefixRef::index` selects between them. Most connections deliver
	/// exactly one.
	pub prefixes: Vec<String>,
}

/// What something that is not netcfgd reported about one interface.
///
/// Not kernel state, and not netcfgd's own record either: the configuration a
/// cellular bearer or a tunnel comes up with is known to whatever negotiated it,
/// and netcfgd is told through a file (`docs/interface-report.md`). The same
/// shape and the same reason as [`Delegation`] -- decision 0004 delegates the
/// client and design section 9.2 keeps the arrow pointing inward.
///
/// Named for what it is rather than for the first thing that wrote one. A modem
/// helper was, and decision 0047 says why that name had to stop being the
/// contract's: the writer is anything that knows an interface's addressing and
/// is not netcfgd.
///
/// Every field is what the *network* assigned, not what the document asked for.
/// An empty report is a link that is down, which is different from no report at
/// all only in that somebody said so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedReport {
	/// The interface reported on, which is the report's filename.
	pub interface: String,
	/// Addresses the network assigned, in CIDR form, in the order reported.
	pub addresses: Vec<String>,
	/// Next hops for a default route, in the order reported. Both families on a
	/// dual-stack bearer.
	pub gateways: Vec<String>,
	/// Nameservers, in the order reported.
	pub nameservers: Vec<String>,
	/// Suffixes to complete an unqualified name with, as the far end offered them.
	///
	/// **Not routing domains, and netcfgd will never make them into any.** A search
	/// suffix says what to append to a bare name; a routing domain says which
	/// resolver answers for a zone, and
	/// [0049](../../../docs/decisions/0049-a-server-may-name-resolvers-not-where-queries-go.md)
	/// refuses one from a report and has no key for it. These land in
	/// [`crate::DnsPolicy::search`] and nowhere else (0067).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub search: Vec<String>,
	/// Routes beyond the default one, in the order reported.
	///
	/// A cellular bearer usually names none -- it gives a way off the link, not
	/// a topology -- but a VPN server routinely pushes a handful, and those are
	/// the routes decision 0047 says are netcfgd's to install rather than the
	/// daemon's. Absent by default so a report written before this existed still
	/// parses.
	#[serde(default)]
	pub routes: Vec<ReportedRoute>,
}

/// One route a report names.
///
/// Both parts stay text, as every other address in a report does: parsing them
/// in the reader would put the refusal where the operator cannot see which line
/// of whose file was wrong. What the reader *does* own is the line's syntax,
/// because the file format is its business.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedRoute {
	/// Where it goes: CIDR, or `default`.
	pub destination: String,
	/// The next hop, where the report names one. A point-to-point link has
	/// none, and a route down one needs none.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub via: Option<String>,
}

/// A backend process as netcfgd currently believes it to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBackend {
	/// Which kind.
	pub kind: BackendKind,
	/// Which interface it serves.
	pub interface: String,
	/// Whether it is running.
	pub running: bool,
	/// Whether it answered when netcfgd last asked it something.
	///
	/// A different question from `running`, and kept separate for the reason
	/// 0078 exists: `running` is now a fact about a *process* -- something is
	/// there under that pid -- and a process being there is not the same as a
	/// daemon doing its job. A wedged hostapd holds its socket, holds its pid,
	/// serves nobody, and answers `running: true` to every question netcfgd had
	/// until this field.
	///
	/// **`None` is not `false`**, the same rule the liveness pass turns on.
	/// `None` means netcfgd cannot ask: the kind has no control socket, or it is
	/// not running, or nothing tried. Reading that as "not answering" would put
	/// a warning on every dhcpcd on every machine.
	///
	/// Absent when it serialises, so the `/run` record of what netcfgd started
	/// is byte-for-byte what it was before this field existed, and a file
	/// written by an older netcfgd still parses.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub answering: Option<bool>,
	/// What a running access point's access control lists actually hold.
	///
	/// Only ever present for [`BackendKind::AccessPoint`], and only while it is
	/// running -- a list read out of a process that has exited is not an
	/// observation of anything. Absent everywhere else, which is why this is an
	/// `Option` rather than an empty [`ObservedAccessControl`]: "netcfgd could
	/// not ask" and "hostapd denies nobody" are different answers, and only the
	/// second one may be reconciled against.
	///
	/// Unlike the rest of this struct it is read live rather than recorded.
	/// Absent when it serialises, so the `/run` record of what netcfgd started
	/// is byte-for-byte what it was before this field existed, and a file
	/// written by an older netcfgd still parses.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub access_control: Option<ObservedAccessControl>,
	/// What a running access point was started with, as netcfgd names it.
	///
	/// The second half of the question [`ObservedAccessControl`] answers. That
	/// one says what hostapd's station lists hold *now*, read over the control
	/// socket; this says what its SSID, band and channel were when netcfgd
	/// started it, read back from the configuration netcfgd generated. hostapd
	/// reads that file once, at startup (decision 0026), so nothing else can
	/// say whether it is still what the document asks for.
	///
	/// **The passphrase is deliberately not here.** A secret does not belong in
	/// an observation that goes over the socket and into `/run` (constraint 5),
	/// and the planner could not compare one anyway: it is pure, and what the
	/// document holds is a `SecretRef`. An edited passphrase is still noticed --
	/// by [`ObservedBackend::secret_matches`], which carries the *answer* and
	/// never the value, computed where both halves are already in hand. This
	/// field and that one are the two halves of decision 0052, and neither of
	/// them is a place a secret may appear.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub started_with: Option<ObservedAccessPoint>,
	/// Whether the secret a running daemon holds is still the one the secret
	/// store has.
	///
	/// A boolean rather than a value, and that is the whole design (decision
	/// 0052). The passphrase is in the file netcfgd generated because hostapd
	/// has no indirection for one, and an observation goes over the control
	/// socket, into `/run` and out of `ncfg status --json` -- so what travels is
	/// the *answer*, computed where both halves are already in hand, and never
	/// the secret. The same shape as [`ObservedLink::private_key_loaded`], which
	/// reports the presence of a key without carrying one.
	///
	/// `None` means netcfgd could not tell: no document to compare against, no
	/// secret in the store, or a file it could not read. Nothing is restarted on
	/// that, because a restart deauthenticates every station and "I could not
	/// check" is not a reason to.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub secret_matches: Option<bool>,
	/// Whether a running tunnel's configuration file is still the one it was
	/// started from.
	///
	/// The same shape as [`ObservedBackend::secret_matches`] and for the same
	/// reason: the comparison needs a file the planner may not read, so it is
	/// made where the file is and only the answer travels. netcfgd hashes the
	/// `.ovpn` it started a tunnel from and hashes it again on the next
	/// observation -- it never reads the file for meaning, which is what
	/// decision 0046 protects, and a hook's `sha256` is the same trick on a
	/// script netcfgd equally does not interpret.
	///
	/// `None` means netcfgd could not tell: no record, or a file it could not
	/// read. Restarting a working tunnel on that would be a VPN dropped for a
	/// question nobody answered.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub config_matches: Option<bool>,
	/// The prefixes a running router advertisement daemon was last given.
	///
	/// Only ever present for [`BackendKind::RouterAdvert`], and read from the
	/// configuration netcfgd generated -- which is netcfgd's own record of what
	/// it started the daemon with, exactly as [`ObservedPolicy`] is for an
	/// access point's ACL policy.
	///
	/// It exists because a prefix is the one value in the document that arrives
	/// after the document does: an ISP renumbers, the LAN's address moves, and a
	/// daemon still announcing the old block is telling every host on the wire
	/// to use an address the upstream will not route. Without this the planner
	/// sees a backend that is running and has nothing to compare.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub advertised: Vec<String>,
}

/// The identity a running access point was started with.
///
/// In netcfgd's own vocabulary rather than hostapd's: the observer maps
/// `hw_mode` back to the band the document spells, so the planner compares
/// model values against model values and can name the field that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAccessPoint {
	/// The SSID it is announcing.
	pub ssid: crate::Ssid,
	/// The band, as the document spells it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub band: Option<String>,
	/// The channel, or `None` where hostapd was told to choose one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub channel: Option<u16>,
}

/// hostapd's in-memory station lists, and the policy it is running under.
///
/// Both lists, because hostapd holds both regardless of which one `macaddr_acl`
/// selects. The document names only one (decision 0039), so the other has to be
/// observed to notice that it is not empty -- which is the only way to see, from
/// outside, that an operator flipped the policy under a running access point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAccessControl {
	/// Which policy the running hostapd was started with.
	pub policy: ObservedPolicy,
	/// Addresses in hostapd's `deny_mac` list, normalised and sorted.
	pub denied: Vec<String>,
	/// Addresses in hostapd's `accept_mac` list, normalised and sorted.
	pub accepted: Vec<String>,
}

impl ObservedAccessControl {
	/// The list one policy reads.
	#[must_use]
	pub fn list(&self, policy: crate::AclPolicy) -> &[String] {
		match policy {
			crate::AclPolicy::Deny => &self.denied,
			crate::AclPolicy::Allow => &self.accepted,
		}
	}
}

/// Which policy a running access point is enforcing.
///
/// Three answers rather than an `Option`, because the two ways of having no
/// policy lead to opposite actions. `macaddr_acl` is not readable over the
/// control socket -- `GET_CONFIG` reports the SSID, the BSSID and the ciphers
/// and says nothing about it -- so this comes from netcfgd's own record of what
/// it started hostapd with, and the record's *absence* is itself informative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPolicy {
	/// Started with no `access_control` block, so `macaddr_acl` was never set.
	///
	/// Both of hostapd's lists exist and neither is consulted for admission the
	/// way a configured one is -- which is exactly why anything in them is worth
	/// reporting rather than converging away as though it were inert.
	Unset,
	/// Started with this policy, and still enforcing it.
	Set(crate::AclPolicy),
	/// netcfgd has no record and cannot tell.
	///
	/// An access point started by a netcfgd too old to write one, or a `/run`
	/// cleared underneath a running one. Nothing may be converged from here:
	/// emptying a list without knowing which one hostapd reads either opens a
	/// network or closes it, and there is no way to know which.
	Unknown,
}

/// A DNS scope netcfgd last delivered, and what it delivered.
///
/// Read back from `/run/netcfgd/dns/`. Without it a plan could not tell an
/// already-applied policy from an unapplied one, and every run would emit a
/// `dns.apply` -- which would fail the plan-idempotence gate in section 6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedDns {
	/// Which scope: an interface name, or `globals`.
	pub scope: String,
	/// What was delivered.
	pub policy: crate::DnsPolicy,
}

/// Everything netcfgd can currently see.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Observed {
	/// Links, sorted by name.
	pub links: Vec<ObservedLink>,
	/// Addresses, sorted by interface then address.
	pub addresses: Vec<ObservedAddress>,
	/// Routes, sorted canonically.
	pub routes: Vec<ObservedRoute>,
	/// Backends, sorted by interface then kind.
	pub backends: Vec<ObservedBackend>,
	/// DNS scopes already delivered, sorted by scope.
	pub dns: Vec<AppliedDns>,
	/// Policy routing rules, sorted by family then priority.
	#[serde(default)]
	pub rules: Vec<ObservedRule>,
	/// Bridge VLANs the kernel currently holds, sorted by interface then id.
	#[serde(default)]
	pub bridge_vlans: Vec<ObservedBridgeVlan>,
	/// Prefixes delegated to this host, sorted by interface.
	#[serde(default)]
	pub delegations: Vec<Delegation>,
	/// What helpers and daemons reported about interfaces, sorted by interface.
	#[serde(default)]
	pub reports: Vec<ObservedReport>,
	/// Interfaces netcfgd set the root qdisc on, sorted.
	///
	/// Recorded for the same reason as [`Observed::forwarding_applied`]: a
	/// qdisc carries no owner, and every interface has one whether or not
	/// anybody chose it. An interface already running `cake` when netcfgd
	/// first started is not netcfgd's to reset.
	#[serde(default)]
	pub qdisc_applied: Vec<String>,
	/// Interfaces netcfgd installed an ingress redirect on, sorted.
	#[serde(default)]
	pub ingress_applied: Vec<String>,
	/// Interfaces netcfgd turned temporary addresses on for, sorted.
	///
	/// Recorded for the reason [`Observed::forwarding_applied`] is: the sysctl
	/// carries no owner, and a machine that had `use_tempaddr` set globally before
	/// netcfgd existed is not netcfgd's to undo.
	#[serde(default)]
	pub privacy_applied: Vec<String>,
	/// How many times netcfgd has started each backend without it staying up.
	///
	/// `(kind, interface, count)`, reset the moment the backend is observed
	/// running. A daemon that dies as fast as it is started would otherwise be
	/// started again on every reconcile forever -- measured at 181 starts in
	/// twelve seconds on an interface set to `reconcile`, which is what made
	/// this necessary rather than tidy. Decision 0079.
	#[serde(default)]
	pub backend_restarts: Vec<(BackendKind, String, u32)>,
	/// Interfaces netcfgd wrote the `accept_ra` sysctl for.
	///
	/// The same record `privacy_applied` is, and for the same reason: an
	/// interface that stops asking for SLAAC is put back only where netcfgd is
	/// what changed it. Without it this would be a one-way door.
	#[serde(default)]
	pub accept_ra_applied: Vec<String>,
	/// Interfaces netcfgd turned forwarding on for, sorted.
	///
	/// Recorded rather than inferred, because a sysctl carries no owner. An
	/// interface that was already forwarding when netcfgd first ran is not in
	/// here and never gets turned off -- somebody else's `sysctl.conf` is not
	/// netcfgd's to undo. One that netcfgd switched on is, which is what makes
	/// deleting `forwarding` from the document mean something.
	#[serde(default)]
	pub forwarding_applied: Vec<String>,
	/// Interfaces netcfgd's own nftables table currently masquerades, sorted.
	///
	/// Empty where the table does not exist, and also where the kernel has no
	/// `nf_tables` at all -- the two are indistinguishable from here and the
	/// planner treats them the same, because "no NAT is installed" is the true
	/// statement in both cases. What separates them is what happens on apply:
	/// a missing subsystem fails loudly there.
	#[serde(default)]
	pub nat: Vec<String>,
	/// Tables other than netcfgd's that translate source addresses, sorted.
	///
	/// Decision 0022 refuses to delete these and reports them instead: a
	/// second source-NAT chain on the same hook translates the same packets
	/// twice, and the table it lives in almost certainly holds filtering
	/// netcfgd cannot evaluate.
	#[serde(default)]
	pub nat_conflicts: Vec<String>,
	/// What each event hook was last told, per interface and per phase.
	///
	/// netcfgd's own memory rather than kernel state, like
	/// [`Observed::forwarding_applied`] -- and named carefully for that reason: this
	/// is not what is true now, it is what a hook has already been told about. The
	/// comparison between the two is what makes an event hook fire once per event
	/// instead of once per reconcile.
	///
	/// One list for every phase rather than one per phase. It was
	/// `lease_hooks: Vec<ObservedLease>` for two commits, until `carrier` arrived
	/// wanting exactly the same thing with a different value in it (0064, 0068).
	#[serde(default)]
	pub hook_state: Vec<ObservedHookState>,
	/// The running hostname, as the kernel reports it.
	///
	/// `None` where it could not be read, which is a container with no
	/// `/proc/sys`. Nothing is planned on a `None`: a hostname netcfgd cannot see
	/// is one it cannot tell whether it has already set.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub hostname: Option<String>,
	/// Whether address ownership came from `IFA_PROTO` or from the weaker
	/// `/run` fallback.
	///
	/// `ncfg explain` reports this, because an operator deciding whether to
	/// trust a drift report needs to know which mechanism produced it
	/// (`docs/decisions/0002`).
	pub address_proto_supported: bool,
}

impl Observed {
	/// The prefixes delegated on an interface.
	#[must_use]
	pub fn delegation(&self, interface: &str) -> Option<&Delegation> {
		self.delegations
			.iter()
			.find(|entry| entry.interface == interface)
	}

	/// The link of this name, if the kernel has one.
	#[must_use]
	pub fn link(&self, name: &str) -> Option<&ObservedLink> {
		self.links.iter().find(|link| link.name == name)
	}

	/// Every address on an interface.
	pub fn addresses_on<'a>(
		&'a self,
		interface: &'a str,
	) -> impl Iterator<Item = &'a ObservedAddress> {
		self.addresses
			.iter()
			.filter(move |address| address.interface == interface)
	}

	/// Every route leaving an interface.
	pub fn routes_on<'a>(&'a self, interface: &'a str) -> impl Iterator<Item = &'a ObservedRoute> {
		self.routes
			.iter()
			.filter(move |route| route.interface == interface)
	}

	/// What was last delivered for a DNS scope.
	#[must_use]
	pub fn dns_for(&self, scope: &str) -> Option<&crate::DnsPolicy> {
		self.dns
			.iter()
			.find(|applied| applied.scope == scope)
			.map(|applied| &applied.policy)
	}

	/// How many times netcfgd has started this backend without it staying up.
	#[must_use]
	pub fn backend_restarts(&self, kind: BackendKind, interface: &str) -> u32 {
		self.backend_restarts
			.iter()
			.find(|(recorded, name, _)| *recorded == kind && name == interface)
			.map_or(0, |(_, _, count)| *count)
	}

	/// Whether a backend of this kind is running on an interface.
	#[must_use]
	pub fn backend_running(&self, kind: BackendKind, interface: &str) -> bool {
		self.backends
			.iter()
			.any(|b| b.kind == kind && b.interface == interface && b.running)
	}

	/// Put every list in a stable order, so two observations of one system
	/// compare equal regardless of the order netlink dumped them in.
	pub fn canonicalize(&mut self) {
		self.links.sort_by(|a, b| a.name.cmp(&b.name));
		self.addresses.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.address.cmp(&b.address))
		});
		self.routes.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.destination.cmp(&b.destination))
				.then_with(|| a.metric.cmp(&b.metric))
		});
		self.backends.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.kind.cmp(&b.kind))
		});
		self.dns.sort_by(|a, b| a.scope.cmp(&b.scope));
	}
}
