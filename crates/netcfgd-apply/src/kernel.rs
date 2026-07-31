//! The executor that talks to the kernel.

use crate::Executor;
use netcfgd_model::route::NETCFGD_PROTO;
use netcfgd_model::{InterfaceKind, Origin};
use netcfgd_plan::{net, Op};
use netcfgd_sys::ops::RT_TABLE_MAIN;
use netcfgd_sys::{parse_mac, Netlink, NewLink, RouteSpec};
use std::process::Command;

/// What the executor did that the next observation cannot work out for itself.
///
/// The kernel does not record which link netcfgd created or which source
/// produced an address, so the executor reports it and the caller folds it
/// into `/run`. Without this, `PriorState` would be guesswork and decision
/// 0006 rule 7 could not be implemented.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effects {
	/// Links created.
	pub created_links: Vec<String>,
	/// Links deleted.
	pub deleted_links: Vec<String>,
	/// `(interface, cidr, origin)` for each address added.
	pub added_addresses: Vec<(String, String, Origin)>,
	/// `(interface, cidr)` for each address removed.
	pub removed_addresses: Vec<(String, String)>,
	/// `(interface, destination, origin)` for each route added.
	pub added_routes: Vec<(String, String, Origin)>,
	/// `(interface, destination)` for each route removed.
	pub removed_routes: Vec<(String, String)>,
	/// Backends started, as `(kind, interface)`.
	pub started_backends: Vec<(netcfgd_model::BackendKind, String)>,
	/// Backends stopped.
	pub stopped_backends: Vec<(netcfgd_model::BackendKind, String)>,
	/// DNS scopes delivered.
	pub applied_dns: Vec<netcfgd_model::AppliedDns>,
	/// `(interface, enabled)` for each forwarding sysctl written.
	pub forwarding: Vec<(String, bool)>,
	/// `(interface, set)` for each root qdisc changed. `false` is a reset.
	pub qdisc: Vec<(String, bool)>,
	/// `(interface, set)` for each ingress redirect changed.
	pub ingress: Vec<(String, bool)>,
}

/// Executes actions against rtnetlink and the backend helpers.
pub struct KernelExecutor {
	socket: Netlink,
	/// The ethtool connection, opened the first time an offload is changed.
	///
	/// Lazy for the same reason as the netfilter socket: most machines never
	/// touch an offload, and resolving the family is a round trip.
	ethtool: Option<netcfgd_sys::ethtool::Ethtool>,
	/// The netfilter socket, opened the first time NAT is actually changed.
	///
	/// Lazy because most machines are not routers: opening it eagerly would
	/// make every netcfgd hold a `NETLINK_NETFILTER` socket, and would turn a
	/// kernel built without `nf_tables` into a startup failure for a daemon
	/// that was never going to write a rule.
	nft: Option<netcfgd_sys::nft::Nft>,
	indices: Vec<(String, u32)>,
	/// Every DNS scope the document declares.
	///
	/// A flat mode has exactly one artifact -- `/etc/resolv.conf` -- so
	/// delivering one scope at a time would have each action overwrite the
	/// last, and the file would end up holding whichever scope the plan
	/// happened to order last. The per-scope action still says *what changed*,
	/// which is what the plan is for; the delivery is whole-host because the
	/// file is. Decision 0007's point restated: a flat resolver cannot express
	/// scopes, so netcfgd flattens once, deliberately, rather than repeatedly
	/// and by accident.
	dns_scopes: Vec<netcfgd_model::AppliedDns>,
	/// The wired 802.1X profile for each interface that has one.
	dot1x: Vec<(String, netcfgd_model::EapConfig)>,
	/// The MAC policy for each radio the document describes one for.
	mac_policy: Vec<(String, netcfgd_model::MacPolicy)>,
	/// The `PPPoE` session on each interface that has one.
	pppoe: Vec<(String, netcfgd_model::interface::PppoeConfig)>,
	/// The route preference of each interface that declares one.
	preferences: Vec<(String, u32)>,
	/// Every wifi profile the document describes.
	///
	/// Carried here because a supplicant that has just been started holds
	/// nothing (decision 0015), and the thing that starts it is the thing that
	/// has to fill it.
	networks: Vec<netcfgd_model::WifiNetwork>,
	/// Every access point the document describes.
	///
	/// Carried for the same reason as `networks` and one more: hostapd is
	/// configured by a file rather than over a socket, so the whole access
	/// point has to be in hand at the moment it starts. The plan carries only
	/// the device (decision 0026).
	access_points: Vec<netcfgd_model::AccessPoint>,
	/// `(path, sha256)` for every hook the document references.
	///
	/// Carried here because the op does not include the hash and the executor
	/// has no document. Supplied by the caller through
	/// [`KernelExecutor::with_hooks`].
	hook_hashes: Vec<(String, String)>,
	/// Where `/run` is, for the DNS backend's record.
	run_dir: std::path::PathBuf,
	/// Where `resolv.conf` is.
	///
	/// Configurable rather than fixed because netcfgd is expected to run in a
	/// container or a chroot, and because section 10.4's read-only root means
	/// the real file may be a symlink into a writable overlay. It is also what
	/// makes the delivery testable without touching the host's resolver
	/// configuration -- which a test very nearly did.
	resolv_conf: std::path::PathBuf,
	/// What happened, for the caller to record.
	pub effects: Effects,
}

impl KernelExecutor {
	/// Open a socket and learn the current interface indices.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`.
	pub fn new() -> std::io::Result<Self> {
		let mut socket = Netlink::open()?;
		socket.set_timeout(5)?;
		let snapshot = netcfgd_sys::snapshot_with(&mut socket)?;
		Ok(Self {
			socket,
			ethtool: None,
			nft: None,
			indices: snapshot
				.links
				.iter()
				.map(|link| (link.name.clone(), link.index))
				.collect(),
			dns_scopes: Vec::new(),
			dot1x: Vec::new(),
			mac_policy: Vec::new(),
			pppoe: Vec::new(),
			preferences: Vec::new(),
			networks: Vec::new(),
			access_points: Vec::new(),
			hook_hashes: Vec::new(),
			run_dir: std::path::PathBuf::from("/run/netcfgd"),
			resolv_conf: resolv_conf_path(),
			effects: Effects::default(),
		})
	}

	/// Tell the executor where `/run` is and what the document's hooks hash to.
	#[must_use]
	pub fn with_context(
		mut self,
		run_dir: impl Into<std::path::PathBuf>,
		document: &netcfgd_model::Document,
	) -> Self {
		self.run_dir = run_dir.into();
		self.dns_scopes = netcfgd_dns::scopes_of(document)
			.into_iter()
			.map(|scope| netcfgd_model::AppliedDns {
				scope: scope.name.to_owned(),
				policy: scope.policy.clone(),
			})
			.collect();
		self.hook_hashes = document
			.interfaces
			.iter()
			.flat_map(|interface| interface.hooks.iter())
			.map(|hook| (hook.path.clone(), hook.sha256.clone()))
			.collect();
		self.dot1x = document
			.interfaces
			.iter()
			.filter_map(|interface| {
				interface
					.dot1x
					.clone()
					.map(|config| (interface.name.clone(), config))
			})
			.collect();
		self.networks.clone_from(&document.networks);
		self.access_points.clone_from(&document.access_points);
		self.preferences = document
			.interfaces
			.iter()
			.filter_map(|interface| {
				interface
					.preference
					.map(|preference| (interface.name.clone(), preference))
			})
			.collect();
		self.pppoe = document
			.interfaces
			.iter()
			.filter_map(|interface| match &interface.kind {
				InterfaceKind::Pppoe(config) => Some((interface.name.clone(), config.clone())),
				_ => None,
			})
			.collect();
		self.mac_policy = document
			.devices
			.iter()
			.filter_map(|device| {
				device
					.wifi
					.as_ref()
					.map(|wifi| (device.name.clone(), wifi.mac_policy))
			})
			.collect();
		self
	}

	/// The preference the document gives an interface, if any.
	fn preference_of(&self, iface: &str) -> Option<u32> {
		self.preferences
			.iter()
			.find(|(name, _)| name == iface)
			.map(|(_, preference)| *preference)
	}

	/// Dial a `PPPoE` session.
	///
	/// pppd is told to install neither a route nor a resolver. Both would be
	/// somebody else configuring the network behind netcfgd's back, which
	/// constraint 1 exists to prevent -- and the drift report would be right
	/// but useless, since the operator did not ask for either.
	///
	/// What a DSL user needs instead is `routes = "default"` on the ppp
	/// interface. A point-to-point link needs no gateway, so that is a
	/// device route netcfgd owns and can explain, rather than a dynamic one
	/// nobody wrote down.
	fn start_pppoe(&self, iface: &str) -> Result<(), String> {
		let Some((_, config)) = self.pppoe.iter().find(|(name, _)| name == iface) else {
			return Err(format!("no pppoe configuration for {iface}"));
		};
		let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());
		let password = resolver
			.resolve(&config.password)
			.map_err(|error| format!("{iface}: {error}"))?;

		let path = write_ppp_options(iface, config, password.expose())?;

		let program = ["/usr/sbin/pppd", "/sbin/pppd", "/usr/bin/pppd"]
			.into_iter()
			.map(std::path::PathBuf::from)
			.find(|path| path.is_file())
			.ok_or_else(|| {
				format!("no pppd found for {iface}; a pppoe session needs the ppp package")
			})?;

		let status = Command::new(&program)
			.arg("file")
			.arg(&path)
			.status()
			.map_err(|error| format!("could not run {}: {error}", program.display()))?;
		if !status.success() {
			return Err(format!(
				"pppd exited with {status} for {iface}; its log will say why, and the \
				 usual causes are a wrong username, a parent interface that is down, or \
				 no access concentrator answering"
			));
		}
		Ok(())
	}

	/// Run the access point the document puts on this radio.
	///
	/// The plan says which device, not which access point, so the lookup is
	/// here. Where a document puts two on one radio the first in name order
	/// wins, which is the same answer the plan warned about -- one radio is one
	/// BSS in this build, and the two have to agree on which one, or the plan
	/// would name one access point and the executor start another.
	fn start_access_point(&self, iface: &str) -> Result<(), String> {
		let Some(access_point) = self
			.access_points
			.iter()
			.find(|access_point| access_point.device == iface)
		else {
			return Err(format!("no access point configuration for {iface}"));
		};
		let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());
		netcfgd_hostapd::start(&self.run_dir, access_point, &resolver)
	}

	/// Give a freshly started supplicant the networks the document describes.
	///
	/// Wired and wireless are different populations, not different amounts of
	/// the same one: a wired port has exactly one profile and it uses
	/// `IEEE8021X`, while a radio gets every network in the document and picks
	/// among them.
	fn populate_supplicant(&self, iface: &str) -> Result<(), String> {
		let dir = ctrl_dir();
		let client = netcfgd_supplicant::Client::connect(&dir, iface).map_err(|error| {
			format!("started a supplicant on {iface} but cannot reach it: {error}")
		})?;

		// Explicit, not assumed. Decision 0015: a silent default is not a
		// control, and this is the property that keeps the document the only
		// authority.
		client
			.command("SET update_config 0")
			.map_err(|error| format!("could not pin update_config on {iface}: {error}"))?;

		let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());

		if let Some((_, eap)) = self.dot1x.iter().find(|(name, _)| name == iface) {
			netcfgd_supplicant::configure_wired(&client, eap, &resolver)
				.map_err(|error| format!("could not configure 802.1X on {iface}: {error}"))?;
			return Ok(());
		}

		// Wireless. Clear first, so a supplicant that survived a crash does
		// not contribute networks nobody can account for.
		netcfgd_supplicant::clear_networks(&client)
			.map_err(|error| format!("could not clear {iface}: {error}"))?;
		let policy = self
			.mac_policy
			.iter()
			.find(|(name, _)| name == iface)
			.map_or(netcfgd_model::MacPolicy::Permanent, |(_, policy)| *policy);
		for network in &self.networks {
			netcfgd_supplicant::add_network(&client, network, policy, &resolver)
				.map_err(|error| format!("could not give `{}` to {iface}: {error}", network.id))?;
		}
		Ok(())
	}

	/// Give a freshly created `WireGuard` device its keys and peers.
	fn configure_wireguard(
		name: &str,
		config: &netcfgd_model::interface::WireGuardConfig,
	) -> Result<(), String> {
		let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());
		let private = resolve_key(&resolver, &config.private_key)
			.map_err(|error| format!("{name}: private key: {error}"))?;

		let mut peers = Vec::new();
		for peer in &config.peers {
			let preshared = match &peer.preshared_key {
				Some(reference) => Some(
					resolve_key(&resolver, reference)
						.map_err(|error| format!("{name}: peer `{}`: {error}", peer.name))?,
				),
				None => None,
			};
			// Resolved here rather than at compile time: a hostname endpoint
			// is the normal case for a roaming peer, and resolving it when the
			// config is read would pin whatever the answer was then.
			let endpoint = match &peer.endpoint {
				Some(text) => Some(
					resolve_endpoint(text)
						.map_err(|error| format!("{name}: peer `{}`: {error}", peer.name))?,
				),
				None => None,
			};
			peers.push(netcfgd_sys::wg::Peer {
				public_key: *peer.public_key.as_bytes(),
				preshared_key: preshared,
				endpoint,
				allowed_ips: peer
					.allowed_ips
					.iter()
					.filter_map(|prefix| parse_prefix(prefix))
					.collect(),
				keepalive: peer.keepalive,
			});
		}

		let mut genl = netcfgd_sys::Genl::open()
			.map_err(|error| format!("cannot open a generic netlink socket: {error}"))?;
		netcfgd_sys::wg::set_device(
			&mut genl,
			&netcfgd_sys::wg::Device {
				name: name.to_owned(),
				private_key: private,
				listen_port: config.listen_port,
				fwmark: config.fwmark,
				peers,
			},
		)
		.map_err(|error| {
			if error.kind() == std::io::ErrorKind::NotFound {
				format!(
					"{name} was created but cannot be configured: the kernel has no \
					 `wireguard` generic netlink family, so the module is not loaded"
				)
			} else {
				format!("cannot configure {name}: {error}")
			}
		})
	}

	/// The index of an interface, refreshing once if it is not known.
	///
	/// A link created earlier in this very plan will not be in the map built
	/// at startup, so a miss triggers one re-dump rather than failing. Without
	/// it, every plan that creates a link then addresses it would fail on the
	/// second action.
	fn index_of(&mut self, name: &str) -> Result<u32, String> {
		if let Some((_, index)) = self.indices.iter().find(|(iface, _)| iface == name) {
			return Ok(*index);
		}
		let snapshot = netcfgd_sys::snapshot_with(&mut self.socket)
			.map_err(|error| format!("could not re-read interfaces: {error}"))?;
		self.indices = snapshot
			.links
			.iter()
			.map(|link| (link.name.clone(), link.index))
			.collect();
		self.indices
			.iter()
			.find(|(iface, _)| iface == name)
			.map(|(_, index)| *index)
			.ok_or_else(|| format!("no interface named {name}"))
	}

	fn route_spec(
		&mut self,
		iface: &str,
		route: &netcfgd_model::Route,
	) -> Result<RouteSpec, String> {
		let index = self.index_of(iface)?;
		let (destination, dst_len) = if route.destination == "default" {
			(None, 0)
		} else {
			let (address, prefix) = net::parse_cidr(&route.destination)
				.ok_or_else(|| format!("{} is not a route destination", route.destination))?;
			(Some(address), prefix)
		};
		Ok(RouteSpec {
			index,
			destination,
			dst_len,
			gateway: route.via,
			metric: route.metric,
			table: route.table.unwrap_or(RT_TABLE_MAIN),
			source: route.src,
			proto: route.proto.unwrap_or(NETCFGD_PROTO),
			onlink: route.onlink,
		})
	}
}

impl Executor for KernelExecutor {
	#[allow(clippy::too_many_lines)]
	fn execute(&mut self, op: &Op) -> Result<(), String> {
		match op {
			Op::LinkCreate { name, kind } => {
				let new = new_link(name, kind, self)?;
				self.socket
					.create_link(name, &new)
					.map_err(|error| format!("could not create {name}: {error}"))?;
				self.effects.created_links.push(name.clone());
				// The index map is stale the moment a link appears.
				self.indices.clear();

				// A bridge's own settings cannot ride along with creation: the
				// kernel takes IFLA_INFO_DATA there, but changing them later
				// has to be a separate RTM_NEWLINK anyway, and having one path
				// rather than two means the create case and the correct-an-
				// existing-bridge case cannot drift apart.
				// Everything that makes a `WireGuard` device a tunnel goes over
				// generic netlink, after the link exists. A link created and
				// left unconfigured is up, addressed, and silently carrying
				// nothing -- so this is part of creating it rather than a
				// separate action.
				if let InterfaceKind::WireGuard(config) = &**kind {
					Self::configure_wireguard(name, config)?;
				}
				if let InterfaceKind::Bridge(bridge) = &**kind {
					let index = self.index_of(name)?;
					self.socket
						.set_bridge_attrs(
							index,
							netcfgd_sys::ops::BridgeAttrs {
								stp: bridge.stp,
								forward_delay: bridge.forward_delay,
								hello_time: bridge.hello_time,
								ageing_time: bridge.ageing_time,
								priority: bridge.priority,
								vlan_filtering: bridge.vlan_filtering,
							},
						)
						.map_err(|error| {
							format!("created {name} but could not set its attributes: {error}")
						})?;
				}
				Ok(())
			}
			Op::LinkDelete { name } => {
				let index = self.index_of(name)?;
				self.socket
					.delete_link(index)
					.map_err(|error| format!("could not delete {name}: {error}"))?;
				self.effects.deleted_links.push(name.clone());
				Ok(())
			}
			Op::LinkSetMtu { name, mtu } => {
				let index = self.index_of(name)?;
				self.socket
					.set_link_mtu(index, *mtu)
					.map_err(|error| format!("could not set mtu on {name}: {error}"))
			}
			Op::LinkSetMac { name, mac } => {
				let index = self.index_of(name)?;
				let parsed = parse_mac(mac).map_err(|error| format!("{mac}: {error}"))?;
				self.socket
					.set_link_mac(index, parsed)
					.map_err(|error| format!("could not set mac on {name}: {error}"))
			}
			Op::LinkSetMaster { name, master } => {
				let index = self.index_of(name)?;
				let master_index = self.index_of(master)?;
				self.socket
					.set_link_master(index, Some(master_index))
					.map_err(|error| format!("could not enslave {name} to {master}: {error}"))
			}
			Op::LinkUnsetMaster { name } => {
				let index = self.index_of(name)?;
				self.socket
					.set_link_master(index, None)
					.map_err(|error| format!("could not release {name}: {error}"))
			}
			Op::LinkUp { name } => {
				let index = self.index_of(name)?;
				self.socket
					.set_link_up(index, true)
					.map_err(|error| format!("could not bring {name} up: {error}"))
			}
			Op::LinkDown { name } => {
				let index = self.index_of(name)?;
				self.socket
					.set_link_up(index, false)
					.map_err(|error| format!("could not take {name} down: {error}"))
			}
			Op::AddrAdd { iface, addr, .. } => {
				let index = self.index_of(iface)?;
				let (address, prefix) = net::parse_cidr(addr)
					.ok_or_else(|| format!("{addr} is not an address with a prefix length"))?;
				self.socket
					.add_address(index, address, prefix, NETCFGD_PROTO)
					.map_err(|error| format!("could not add {addr} to {iface}: {error}"))?;
				self.effects
					.added_addresses
					.push((iface.clone(), addr.clone(), Origin::Static));
				Ok(())
			}
			Op::AddrDel { iface, addr } => {
				let index = self.index_of(iface)?;
				let (address, prefix) = net::parse_cidr(addr)
					.ok_or_else(|| format!("{addr} is not an address with a prefix length"))?;
				self.socket
					.del_address(index, address, prefix)
					.map_err(|error| format!("could not remove {addr} from {iface}: {error}"))?;
				self.effects
					.removed_addresses
					.push((iface.clone(), addr.clone()));
				Ok(())
			}
			Op::RouteAdd { iface, route } => {
				let spec = self.route_spec(iface, route)?;
				self.socket.add_route(&spec).map_err(|error| {
					format!(
						"could not add route {} on {iface}: {error}",
						route.destination
					)
				})?;
				self.effects.added_routes.push((
					iface.clone(),
					route.destination.clone(),
					Origin::Static,
				));
				Ok(())
			}
			Op::RouteDel { iface, route } => {
				let spec = self.route_spec(iface, route)?;
				self.socket.del_route(&spec).map_err(|error| {
					format!(
						"could not remove route {} on {iface}: {error}",
						route.destination
					)
				})?;
				self.effects
					.removed_routes
					.push((iface.clone(), route.destination.clone()));
				Ok(())
			}
			Op::BackendStart { kind, iface } => {
				// PPPoE and hostapd first, and before `start_backend`: both are
				// configured from parts of the document the op does not carry
				// -- a session's credentials, an access point's whole block --
				// so these are the backends the executor starts from its own
				// context rather than from the op alone.
				if *kind == netcfgd_model::BackendKind::Pppoe {
					self.start_pppoe(iface)?;
					self.effects.started_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				if *kind == netcfgd_model::BackendKind::AccessPoint {
					self.start_access_point(iface)?;
					self.effects.started_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				start_backend(*kind, iface, self.preference_of(iface))?;
				self.effects.started_backends.push((*kind, iface.clone()));
				if *kind == netcfgd_model::BackendKind::Supplicant {
					// A supplicant that has just started knows nothing, by
					// design. Filling it is part of starting it: a plan that
					// reported success while leaving an empty supplicant would
					// be reporting that the port is authenticated when it is
					// not.
					self.populate_supplicant(iface)?;
				}
				Ok(())
			}
			Op::BridgeVlanAdd {
				iface,
				vid,
				pvid,
				untagged,
				on_self,
			} => {
				let index = self.index_of(iface)?;
				self.socket
					.set_bridge_vlan(
						index,
						netcfgd_sys::ops::VlanChange {
							vid: *vid,
							pvid: *pvid,
							untagged: *untagged,
							on_self: *on_self,
							add: true,
						},
					)
					.map_err(|error| {
						// EOPNOTSUPP here almost always means the bridge has
						// no vlan_filtering, in which case per-port VLANs are
						// not a thing it has -- and the errno alone says
						// nothing about that.
						if error.raw_os_error() == Some(95) {
							format!(
								"cannot put vlan {vid} on {iface}: the bridge does not have \
								 `vlan_filtering = true`, so it has no per-port vlans"
							)
						} else {
							format!("cannot put vlan {vid} on {iface}: {error}")
						}
					})?;
				Ok(())
			}
			Op::BridgeVlanDel {
				iface,
				vid,
				on_self,
			} => {
				let index = self.index_of(iface)?;
				self.socket
					.set_bridge_vlan(
						index,
						netcfgd_sys::ops::VlanChange {
							vid: *vid,
							pvid: false,
							untagged: false,
							on_self: *on_self,
							add: false,
						},
					)
					.map_err(|error| format!("cannot remove vlan {vid} from {iface}: {error}"))
			}
			Op::AccessControlAdd {
				iface,
				list,
				station,
			} => netcfgd_hostapd::acl::add(&self.run_dir, iface, *list, station),
			Op::AccessControlDel {
				iface,
				list,
				station,
			} => netcfgd_hostapd::acl::remove(&self.run_dir, iface, *list, station),
			Op::BackendStop { kind, iface } => {
				if *kind == netcfgd_model::BackendKind::AccessPoint {
					// Where `/run` is, which `stop_backend` has no access to --
					// it is a free function, and the control socket for an
					// access point lives under netcfgd's own run directory
					// rather than in a fixed place.
					netcfgd_hostapd::stop(&self.run_dir, iface)?;
					self.effects.stopped_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				stop_backend(*kind, iface)?;
				self.effects.stopped_backends.push((*kind, iface.clone()));
				Ok(())
			}
			Op::DnsApply { scope, policy } => {
				// Deliver every scope, not just this one, for the reason
				// `dns_scopes` documents. Where the executor was given no
				// document -- a caller that did not use `with_context` -- fall
				// back to the single scope rather than delivering nothing.
				let owned: Vec<netcfgd_model::AppliedDns> = if self.dns_scopes.is_empty() {
					vec![netcfgd_model::AppliedDns {
						scope: scope.clone(),
						policy: (**policy).clone(),
					}]
				} else {
					self.dns_scopes.clone()
				};
				let scopes: Vec<netcfgd_dns::Scope<'_>> = owned
					.iter()
					.map(|entry| netcfgd_dns::Scope {
						name: &entry.scope,
						policy: &entry.policy,
					})
					.collect();
				let delivered = netcfgd_dns::deliver(&scopes, &self.resolv_conf, &self.run_dir)?;
				self.effects.applied_dns.extend(delivered);
				Ok(())
			}
			Op::HookRun { iface, phase, path } => {
				// The sha256 is not in the op, so it is looked up in the
				// document the plan came from -- which the executor does not
				// have. Until the op carries it (an additive change, M4),
				// verify against the file as materialised and report a
				// mismatch as a failure of the phase rather than silently
				// running whatever is there now.
				let reference = netcfgd_model::HookRef {
					phase: *phase,
					path: path.clone(),
					sha256: self
						.hook_hashes
						.iter()
						.find(|(known, _)| known == path)
						.map_or_else(String::new, |(_, hash)| hash.clone()),
					run_as: None,
					timeout: None,
				};
				let env = crate::hooks::HookEnv::for_interface(iface);
				match crate::hooks::run(&reference, &env) {
					crate::hooks::Outcome::Ok => Ok(()),
					// A pre_* veto stops the plan, which is section 5.2's
					// whole point: you can refuse a bring-up.
					crate::hooks::Outcome::Vetoed(message) => Err(message),
					// A post_* or event hook failing is reported and does not
					// roll anything back. Failing the plan here would leave
					// the rest of the machine unconfigured because a logging
					// script exited 1.
					crate::hooks::Outcome::Noted(message) => {
						eprintln!("netcfgd: {message}");
						Ok(())
					}
				}
			}
			Op::LinkSetOffloads { name, features } => {
				let ethtool = match &mut self.ethtool {
					Some(ethtool) => ethtool,
					slot => {
						slot.insert(netcfgd_sys::ethtool::Ethtool::open().map_err(|error| {
							format!(
								"cannot reach ethtool: {error}. Offloads need the \
								 `ethtool` generic netlink family, which is Linux 5.6 \
								 or newer"
							)
						})?)
					}
				};
				let wanted: Vec<(&str, bool)> = features
					.iter()
					.map(|(feature, on)| (feature.as_str(), *on))
					.collect();
				ethtool.set_features(name, &wanted).map_err(|error| {
					format!(
						"cannot set offloads on {name}: {error}. A driver that does not \
						 know a feature refuses the whole request, so nothing changed."
					)
				})?;
				Ok(())
			}
			Op::LinkSetIpv6Token { name, token } => {
				let index = self.index_of(name)?;
				let address: std::net::IpAddr = token
					.parse()
					.map_err(|_| format!("`{token}` is not an IPv6 address"))?;
				self.socket
					.set_ipv6_token(index, address)
					.map_err(|error| {
						if error.kind() == std::io::ErrorKind::InvalidInput {
							// The kernel returns a bare EINVAL for four different
							// preconditions, so the message has to name them.
							// "Invalid argument" on its own sends an operator
							// looking at the address, which is the one thing that
							// is usually right.
							format!(
								"cannot set an IPv6 token on {name}: the kernel refused it. A \
							 token needs a device that does neighbour discovery -- not a \
							 dummy or any other NOARP device -- which is up, accepts \
							 router advertisements, and sends router solicitations. \
							 Forwarding turns RA acceptance off, so a router interface \
							 cannot have one."
							)
						} else {
							format!("cannot set an IPv6 token on {name}: {error}")
						}
					})?;
				Ok(())
			}
			Op::RuleAdd { rule } => {
				let record = rule_record(rule)?;
				self.socket
					.add_rule(&record)
					.map_err(|error| format!("could not install rule `{}`: {error}", rule.id))?;
				Ok(())
			}
			Op::RuleDel { rule } => {
				let record = rule_record(rule)?;
				self.socket
					.del_rule(&record)
					.map_err(|error| format!("could not remove rule `{}`: {error}", rule.id))?;
				Ok(())
			}
			Op::QdiscSet {
				iface,
				kind,
				bandwidth_bits,
				ingress,
			} => {
				let index = self.index_of(iface)?;
				netcfgd_sys::qdisc::Qdisc::new(&mut self.socket)
					.set_root(
						index,
						&netcfgd_sys::qdisc::RootQdisc {
							kind,
							bandwidth_bits: *bandwidth_bits,
							ingress: *ingress,
						},
					)
					.map_err(|error| {
						if error.kind() == std::io::ErrorKind::NotFound {
							format!(
								"cannot set {kind} on {iface}: this kernel has no such \
								 scheduler, and the module could not be loaded"
							)
						} else {
							format!("cannot set {kind} on {iface}: {error}")
						}
					})?;
				self.effects.qdisc.push((iface.clone(), true));
				Ok(())
			}
			Op::QdiscReset { iface } => {
				let index = self.index_of(iface)?;
				netcfgd_sys::qdisc::Qdisc::new(&mut self.socket)
					.delete_root(index)
					.map_err(|error| {
						format!("cannot restore the default qdisc on {iface}: {error}")
					})?;
				self.effects.qdisc.push((iface.clone(), false));
				Ok(())
			}
			Op::IngressRedirect { iface, target } => {
				let index = self.index_of(iface)?;
				let target_index = self.index_of(target)?;
				let mut tc = netcfgd_sys::qdisc::Qdisc::new(&mut self.socket);
				// The hook first, then the filter that hangs off it: the
				// kernel has nowhere to put a classifier until the ingress
				// qdisc exists, and the error for that says only EINVAL.
				tc.add_ingress(index).map_err(|error| {
					format!("cannot attach the ingress hook to {iface}: {error}")
				})?;
				tc.redirect_ingress(index, target_index).map_err(|error| {
					if error.kind() == std::io::ErrorKind::NotFound {
						format!(
							"cannot redirect {iface} to {target}: this kernel is \
							 missing `cls_matchall` or `act_mirred`"
						)
					} else {
						format!("cannot redirect {iface} to {target}: {error}")
					}
				})?;
				self.effects.ingress.push((iface.clone(), true));
				Ok(())
			}
			Op::IngressRedirectClear { iface } => {
				let index = self.index_of(iface)?;
				// Removing the hook takes every filter on it, so there is
				// nothing to delete separately.
				netcfgd_sys::qdisc::Qdisc::new(&mut self.socket)
					.delete_ingress(index)
					.map_err(|error| {
						format!("cannot remove the ingress hook from {iface}: {error}")
					})?;
				self.effects.ingress.push((iface.clone(), false));
				Ok(())
			}
			Op::SysctlSetForwarding { iface, enabled } => {
				set_forwarding(iface, *enabled)?;
				self.effects.forwarding.push((iface.clone(), *enabled));
				Ok(())
			}
			Op::NatReplace { uplinks } => {
				let nft = match &mut self.nft {
					Some(nft) => nft,
					slot => slot.insert(netcfgd_sys::nft::Nft::open().map_err(|error| {
						format!(
							"cannot reach nftables: {error}. NAT needs `nf_tables` in the \
							 kernel and CAP_NET_ADMIN in this namespace"
						)
					})?),
				};
				nft.replace_nat(uplinks).map_err(|error| {
					format!(
						"could not replace the `{}` table: {error}",
						netcfgd_sys::nft::TABLE
					)
				})
			}
			// The commit family is a marker in the plan rather than something
			// the kernel does. The window lives in the daemon, which opens it
			// after the apply succeeds and owns the timer, so the executor's
			// correct behaviour is to do nothing -- not to fail the very plan
			// it is bracketing, which is what an unhandled op would do.
			Op::CommitArm { .. } | Op::CommitConfirm | Op::CommitRevert { .. } => Ok(()),
			other => Err(format!("{} is not implemented in this build", other.name())),
		}
	}
}

/// A model rule as the wire wants it.
///
/// The `FRA_PROTOCOL` tag is applied here rather than carried in the model,
/// for the reason decision 0002 gives about routes: ownership is netcfgd's own
/// bookkeeping, not something the operator writes or should be able to forge
/// by copying a config.
fn rule_record(rule: &netcfgd_model::RoutingRule) -> Result<netcfgd_sys::rule::RuleRecord, String> {
	let selector = |cidr: &Option<String>| -> Result<Option<(std::net::IpAddr, u8)>, String> {
		match cidr {
			None => Ok(None),
			Some(text) => net::parse_cidr(text)
				.map(Some)
				.ok_or_else(|| format!("`{text}` is not a prefix")),
		}
	};
	Ok(netcfgd_sys::rule::RuleRecord {
		// `AF_INET` and `AF_INET6`.
		family: match rule.family {
			netcfgd_model::RuleFamily::Inet => 2,
			netcfgd_model::RuleFamily::Inet6 => 10,
		},
		priority: rule.priority,
		table: rule.table.unwrap_or(0),
		action: match rule.action {
			netcfgd_model::RuleAction::Lookup => netcfgd_sys::rule::FR_ACT_TO_TBL,
			netcfgd_model::RuleAction::Blackhole => netcfgd_sys::rule::FR_ACT_BLACKHOLE,
			netcfgd_model::RuleAction::Unreachable => netcfgd_sys::rule::FR_ACT_UNREACHABLE,
			netcfgd_model::RuleAction::Prohibit => netcfgd_sys::rule::FR_ACT_PROHIBIT,
		},
		from: selector(&rule.from)?,
		to: selector(&rule.to)?,
		iif: rule.iif.clone(),
		oif: rule.oif.clone(),
		fwmark: rule.fwmark,
		fwmask: rule.fwmask,
		suppress_prefixlength: rule.suppress_prefixlength,
		l3mdev: rule.l3mdev,
		invert: rule.invert,
		protocol: NETCFGD_PROTO,
	})
}

/// Turn forwarding on or off for one interface, in both families.
///
/// Writes the per-device sysctl rather than the global `net.ipv4.ip_forward`,
/// which would set every interface on the machine -- including the ones the
/// document says nothing about.
///
/// An IPv6 failure is reported and an IPv4 one is fatal, which is deliberate
/// asymmetry: a kernel built with `ipv6.disable=1` has no IPv6 sysctl at all
/// and refusing there would make netcfgd unable to configure an IPv4 router.
/// The IPv4 path has no such excuse.
fn set_forwarding(iface: &str, enabled: bool) -> Result<(), String> {
	let root = std::env::var_os("NCFG_PROC_ROOT").map_or_else(
		|| std::path::PathBuf::from("/proc"),
		std::path::PathBuf::from,
	);
	let value = if enabled { "1" } else { "0" };

	let write = |family: &str| -> std::io::Result<()> {
		std::fs::write(
			root.join(format!("sys/net/{family}/conf/{iface}/forwarding")),
			value,
		)
	};

	write("ipv4").map_err(|error| format!("cannot set IPv4 forwarding on {iface}: {error}"))?;
	if let Err(error) = write("ipv6") {
		eprintln!(
			"netcfgd: cannot set IPv6 forwarding on {iface}: {error}; IPv4 is set and IPv6 \
			 traffic will not be routed"
		);
	}
	Ok(())
}

/// Where `resolv.conf` is: the environment, or the usual place.
fn resolv_conf_path() -> std::path::PathBuf {
	std::env::var("NCFG_RESOLV_CONF").map_or_else(
		|_| std::path::PathBuf::from(netcfgd_dns::RESOLV_CONF),
		std::path::PathBuf::from,
	)
}

fn new_link(
	name: &str,
	kind: &InterfaceKind,
	executor: &mut KernelExecutor,
) -> Result<NewLink, String> {
	match kind {
		InterfaceKind::Bridge(_) => Ok(NewLink::Bridge),
		InterfaceKind::Dummy => Ok(NewLink::Dummy),
		InterfaceKind::Vlan(vlan) => Ok(NewLink::Vlan {
			parent: executor.index_of(&vlan.parent)?,
			id: vlan.id,
			protocol: vlan.protocol.ethertype(),
		}),
		InterfaceKind::Bond(bond) => Ok(NewLink::Bond {
			mode: bond.mode.number(),
			miimon: bond.miimon,
		}),
		InterfaceKind::Vxlan(vxlan) => Ok(NewLink::Vxlan {
			id: vxlan.id,
			// Resolved here rather than carried as a name, because the kernel
			// wants an index and the interface may have been created earlier
			// in this same plan.
			parent: match &vxlan.parent {
				Some(parent) => Some(executor.index_of(parent)?),
				None => None,
			},
			local: vxlan.local,
			remote: vxlan.remote,
			port: vxlan.port,
		}),
		InterfaceKind::Veth(veth) => Ok(NewLink::Veth {
			peer: veth.peer.clone(),
		}),
		InterfaceKind::WireGuard(_) => Ok(NewLink::WireGuard),
		InterfaceKind::Vrf(vrf) => Ok(NewLink::Vrf { table: vrf.table }),
		InterfaceKind::Macvlan(macvlan) => Ok(NewLink::Macvlan {
			parent: executor.index_of(&macvlan.parent)?,
			mode: match macvlan.mode {
				netcfgd_model::MacvlanMode::Private => 1,
				netcfgd_model::MacvlanMode::Vepa => 2,
				netcfgd_model::MacvlanMode::Bridge => 4,
				netcfgd_model::MacvlanMode::Passthru => 8,
			},
		}),
		InterfaceKind::Tunnel(tunnel) => Ok(NewLink::Tunnel {
			kind: tunnel.mode.name(),
			parent: match &tunnel.parent {
				Some(parent) => Some(executor.index_of(parent)?),
				None => None,
			},
			local: tunnel.local,
			remote: tunnel.remote,
			ttl: tunnel.ttl,
			key: tunnel.key,
		}),
		InterfaceKind::Ifb => Ok(NewLink::Ifb),
		InterfaceKind::Tun(_) => Err(format!(
			"{name} is a tun/tap device, which this build cannot create: they come from a \
			 TUNSETIFF ioctl on /dev/net/tun rather than from netlink, and that is outside \
			 the one crate permitted unsafe. Create it with `ip tuntap add` and netcfgd will \
			 address it."
		)),
		other => Err(format!(
			"creating a {} link ({name}) is not implemented in this build",
			kind_name(other)
		)),
	}
}

fn kind_name(kind: &InterfaceKind) -> &'static str {
	match kind {
		InterfaceKind::Physical => "physical",
		InterfaceKind::Bridge(_) => "bridge",
		InterfaceKind::Bond(_) => "bond",
		InterfaceKind::Vlan(_) => "vlan",
		InterfaceKind::Vxlan(_) => "vxlan",
		InterfaceKind::WireGuard(_) => "wireguard",
		InterfaceKind::Pppoe(_) => "pppoe",
		InterfaceKind::Dummy => "dummy",
		InterfaceKind::Veth(_) => "veth",
		InterfaceKind::Vrf(_) => "vrf",
		InterfaceKind::Macvlan(_) => "macvlan",
		InterfaceKind::Tunnel(tunnel) => tunnel.mode.name(),
		InterfaceKind::Tun(_) => "tun",
		InterfaceKind::Ifb => "ifb",
	}
}

/// Start a helper.
///
/// Decision 0004 delegates DHCP rather than implementing it, so this looks for
/// a client and reports honestly when there is none. The lease-to-model
/// handoff -- which turns a fresh lease into observed state -- lands with
/// `netcfgd-dhcp` in M2; until then the client configures the interface and
/// netcfgd sees the result as somebody else's, which is the safe direction.
fn start_backend(
	kind: netcfgd_model::BackendKind,
	iface: &str,
	metric: Option<u32>,
) -> Result<(), String> {
	use netcfgd_model::BackendKind;
	match kind {
		BackendKind::Dhcp4 => {
			// The metric matters as much as the address on a machine with two
			// uplinks: the lease's default route has to lose to the wired one
			// or win over the wifi, and the client is what installs it. This
			// was a field in the model that reached nothing until carrier
			// switching needed it.
			let metric = metric.map(|value| value.to_string());
			let mut dhcpcd = vec!["-b".to_owned(), "-4".to_owned()];
			let udhcpc = vec!["-b".to_owned(), "-i".to_owned(), iface.to_owned()];
			if let Some(metric) = &metric {
				dhcpcd.push("-m".to_owned());
				dhcpcd.push(metric.clone());
				// busybox udhcpc has no metric option; its script does the
				// routing. Saying so beats passing a flag it would reject.
			}
			dhcpcd.push(iface.to_owned());

			for (program, args) in [("dhcpcd", dhcpcd), ("udhcpc", udhcpc)] {
				match Command::new(program).args(&args).status() {
					Ok(status) if status.success() => return Ok(()),
					Ok(status) => return Err(format!("{program} on {iface} exited with {status}")),
					// Not installed: try the next one.
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(format!("could not run {program}: {error}")),
				}
			}
			Err(format!(
				"no DHCPv4 client found for {iface}; install dhcpcd or busybox udhcpc"
			))
		}
		BackendKind::Dhcp6 => start_dhcp6(iface),
		BackendKind::Pppoe => Err(format!(
			"a pppoe session on {iface} needs its configuration, which the plain \
			 backend path does not carry"
		)),
		BackendKind::Supplicant => start_supplicant(iface),
		other => Err(format!(
			"the {other:?} backend is not implemented in this build"
		)),
	}
}

/// Start a `DHCPv6` client, with the hook that reports a delegated prefix.
///
/// Decision 0004 delegates DHCP, so netcfgd does not learn the prefix by
/// speaking the protocol -- it learns it because the client tells it. The
/// mechanism is a script netcfgd writes and the client runs: the client
/// exports the delegation in the environment, the script writes it to a file
/// under `/run`, and the observer reads that file.
///
/// A file rather than a socket callback, deliberately. Design section 5.2 says
/// hooks never need to call back into netcfgd, and a delegated prefix arriving
/// through the same greppable-file route as everything else in `/run` means an
/// operator can see what the client reported without netcfgd running.
fn start_dhcp6(iface: &str) -> Result<(), String> {
	let hook = write_pd_hook(iface)?;

	for (program, args) in [
		// odhcp6c takes the script as an argument, which is the shape this
		// wants: no global hook directory to share with other clients.
		(
			"odhcp6c",
			vec![
				"-d".to_owned(),
				"-P".to_owned(),
				"0".to_owned(),
				"-s".to_owned(),
				hook.display().to_string(),
				iface.to_owned(),
			],
		),
		// dhcpcd reads hooks from a directory rather than an argument, so the
		// script is installed there by `write_pd_hook` and this only asks for
		// prefix delegation.
		(
			"dhcpcd",
			vec!["-b".to_owned(), "-6".to_owned(), iface.to_owned()],
		),
	] {
		match Command::new(program).args(&args).status() {
			Ok(status) if status.success() => return Ok(()),
			Ok(status) => return Err(format!("{program} on {iface} exited with {status}")),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(format!("could not run {program}: {error}")),
		}
	}
	Err(format!(
		"no DHCPv6 client found for {iface}; install odhcp6c or dhcpcd"
	))
}

/// Write the script a `DHCPv6` client runs when a lease changes.
///
/// One script, handling both clients, because they differ only in which
/// environment variable carries the prefix. Writing two would mean two places
/// for the file format to drift from what the observer reads.
fn write_pd_hook(iface: &str) -> Result<std::path::PathBuf, String> {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let run_dir = run_dir_path();
	let hooks = run_dir.join("hooks");
	let prefixes = run_dir.join("prefixes");
	std::fs::create_dir_all(&hooks).map_err(|error| format!("{}: {error}", hooks.display()))?;
	std::fs::create_dir_all(&prefixes)
		.map_err(|error| format!("{}: {error}", prefixes.display()))?;

	let path = hooks.join(format!("pd-{iface}"));
	let script = pd_hook_script(iface, &prefixes.join(iface));

	let mut file = std::fs::File::create(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	file.write_all(script.as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
		.map_err(|error| format!("cannot make {} executable: {error}", path.display()))?;
	Ok(path)
}

/// Write pppd's options file.
///
/// The parent interface goes in as `nic-<name>`, the option the pppoe plugin
/// registers, rather than as a bare device argument. Both are accepted and the
/// difference could not be settled on the machine this was written on -- pppd
/// gives up at `/dev/ppp` before it validates a device name, so neither form
/// could be shown wrong. `nic-` is the unambiguous one: it cannot be mistaken
/// for something else and it needs no quoting, where a quoted device argument
/// leaves open whether the quotes end up in the name. Removing the question
/// beats answering it from memory.
///
/// A file rather than command-line arguments, and mode 0600, because the
/// password is in it: pppd takes a `password` option and anything on a command
/// line is readable by every process on the machine through `ps`. The file is
/// under `/run` so it does not survive a reboot and does not collide with
/// whatever else on the host uses `/etc/ppp`.
fn write_ppp_options(
	iface: &str,
	config: &netcfgd_model::interface::PppoeConfig,
	password: &str,
) -> Result<std::path::PathBuf, String> {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let dir = run_dir_path().join("ppp");
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	let path = dir.join(iface);
	let text = ppp_options(iface, config, password);

	let mut file = std::fs::File::create(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	// Before the content, not after: a window where the password is readable
	// is a window, however short.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
		.map_err(|error| format!("cannot secure {}: {error}", path.display()))?;
	file.write_all(text.as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	Ok(path)
}

/// The options file's text.
///
/// Pure, so what pppd is told can be checked without a filesystem -- and the
/// two things most worth checking are that the password survives quoting and
/// that pppd is told to leave routes and DNS alone.
#[must_use]
pub fn ppp_options(
	iface: &str,
	config: &netcfgd_model::interface::PppoeConfig,
	password: &str,
) -> String {
	// The unit number comes from the interface name, so `interface ppp0` is
	// ppp0 and not whichever unit happened to be free. Without it the document
	// stops describing the system after the second session -- the same reason
	// a routing rule's priority is mandatory.
	let unit = iface
		.strip_prefix("ppp")
		.and_then(|rest| rest.parse::<u32>().ok());

	let mut text = format!(
		"# Written by netcfgd for {iface}. Do not edit; it is rewritten on apply.\n\
		 plugin pppoe.so\n\
		 nic-{parent}\n\
		 user {user}\n\
		 password {password}\n\
		 noauth\n\
		 persist\n\
		 maxfail 0\n\
		 # netcfgd owns routes and resolvers. `defaultroute` here would install\n\
		 # a route nobody wrote down, and `usepeerdns` would rewrite resolv.conf\n\
		 # underneath the dns backend. A ppp link needs no gateway, so the\n\
		 # config says `routes = \"default\"` and netcfgd installs it.\n\
		 nodefaultroute\n\
		 noipdefault\n",
		parent = config.parent,
		user = quote_ppp(&config.username),
		password = quote_ppp(password),
	);
	if let Some(unit) = unit {
		text.push_str(&format!("unit {unit}\n"));
	}
	if let Some(service) = &config.service {
		text.push_str(&format!("rp_pppoe_service {}\n", quote_ppp(service)));
	}
	if let Some(ac) = &config.ac {
		text.push_str(&format!("rp_pppoe_ac {}\n", quote_ppp(ac)));
	}
	text
}

/// Quote a value for pppd's options file.
///
/// pppd splits on whitespace and understands double quotes with backslash
/// escapes. A DSL password with a space in it is ordinary, and one with a
/// quote would otherwise end the option and turn the rest into pppd
/// directives.
fn quote_ppp(value: &str) -> String {
	let mut out = String::with_capacity(value.len() + 2);
	out.push('"');
	for character in value.chars() {
		if character == '"' || character == '\\' {
			out.push('\\');
		}
		out.push(character);
	}
	out.push('"');
	out
}

/// The script's text.
///
/// Public and pure so it can be run the way a client runs it, with the same
/// environment, and its output compared against what
/// `netcfgd_host::state::read_delegations` parses. The two halves of this
/// feature are a shell script and a Rust reader that never call each other,
/// and the only thing holding them together is that file format.
#[must_use]
pub fn pd_hook_script(iface: &str, target: &std::path::Path) -> String {
	// `PREFIXES` is odhcp6c's and `new_dhcp6_prefix` is dhcpcd's; whichever is
	// set is the one that ran us. Written to a temporary and renamed, because
	// the observer may read at any moment and a half-written file would be
	// read as a shorter list rather than as an error. Rewritten rather than
	// appended, because a renewal that changed the prefix must not leave both.
	//
	// `${p%%,*}` strips odhcp6c's trailing lifetime fields: it reports
	// `2001:db8::/56,3600,7200`, and the prefix is everything before the first
	// comma.
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd. Reports the prefixes delegated on {iface}.\n\
		 # One per line; an empty file means the lease is gone.\n\
		 set -u\n\
		 out={}\n\
		 : > \"$out.tmp\"\n\
		 for p in ${{PREFIXES:-}} ${{new_dhcp6_prefix:-}}; do\n\
		 \tprintf '%s\\n' \"${{p%%,*}}\" >> \"$out.tmp\"\n\
		 done\n\
		 mv \"$out.tmp\" \"$out\"\n",
		target.display()
	)
}

/// Where `/run` is, for code that has no executor to hand.
fn run_dir_path() -> std::path::PathBuf {
	std::env::var_os("NCFG_RUN_DIR").map_or_else(
		|| std::path::PathBuf::from("/run/netcfgd"),
		std::path::PathBuf::from,
	)
}

/// A 32-octet key from a secret, in the base64 every `WireGuard` tool prints.
fn resolve_key(
	resolver: &netcfgd_secret::Resolver,
	reference: &netcfgd_model::SecretRef,
) -> Result<[u8; 32], String> {
	let secret = resolver
		.resolve(reference)
		.map_err(|error| error.to_string())?;
	// The error deliberately does not quote the value: a private key that
	// failed to parse is still a private key.
	netcfgd_model::Key::parse(secret.expose())
		.map(|key| *key.as_bytes())
		.map_err(|error| error.to_string())
}

/// `host:port`, resolved now rather than at compile time.
fn resolve_endpoint(text: &str) -> Result<std::net::SocketAddr, String> {
	use std::net::ToSocketAddrs;
	text.to_socket_addrs()
		.map_err(|error| format!("cannot resolve endpoint `{text}`: {error}"))?
		.next()
		.ok_or_else(|| format!("`{text}` resolved to no address"))
}

/// `address/length`.
fn parse_prefix(text: &str) -> Option<(std::net::IpAddr, u8)> {
	let (address, length) = text.split_once('/')?;
	Some((address.parse().ok()?, length.parse().ok()?))
}

/// Where `file` secrets live.
///
/// Derived from the config directory rather than passed in, because the
/// executor is handed a run directory and a document, and a secret is neither.
fn secrets_dir() -> std::path::PathBuf {
	std::env::var_os("NCFG_CONFIG_DIR").map_or_else(
		|| std::path::PathBuf::from(netcfgd_secret::DEFAULT_SECRETS_DIR),
		|dir| std::path::PathBuf::from(dir).join("secrets"),
	)
}

/// Where the supplicant's control sockets live.
///
/// Overridable so a test can point at a directory that is not the real one --
/// a network namespace is not a mount namespace, so without this a test would
/// share `/run/wpa_supplicant` with whatever the host is running.
fn ctrl_dir() -> std::path::PathBuf {
	std::env::var_os("NCFG_WPA_CTRL_DIR").map_or_else(
		|| std::path::PathBuf::from(netcfgd_supplicant::DEFAULT_CTRL_DIR),
		std::path::PathBuf::from,
	)
}

/// Start a `wpa_supplicant` that holds no state.
///
/// Decision 0015, as command-line arguments:
///
/// - No config file. Not an empty one, none -- `-C` supplies the control
///   interface, so there is nothing a file would be needed for, and a file
///   that does not exist cannot be edited by anything else.
/// - `update_config=0`, set explicitly through `-o`... except there is no such
///   flag, so it is set on the running instance below. It is the default, and
///   relying on a default for the property that keeps constraint 1 true is how
///   the property quietly stops holding after a distribution patches a
///   template.
/// - Networks arrive over the control socket afterwards, from the document.
///
/// The driver depends on what the interface is. A wired port authenticating
/// with 802.1X needs `-Dwired`; a radio needs `nl80211`. Guessing wrong
/// produces a supplicant that starts and never associates, so the wireless
/// case is detected rather than assumed.
fn start_supplicant(iface: &str) -> Result<(), String> {
	let dir = ctrl_dir();
	std::fs::create_dir_all(&dir)
		.map_err(|error| format!("cannot create {}: {error}", dir.display()))?;

	if dir.join(iface).exists() {
		// Already running -- started by a previous apply, or surviving a
		// netcfgd restart. Decision 0015 makes that harmless: whoever
		// populates it calls REMOVE_NETWORK all first, so it holds nothing
		// nobody can account for.
		return Ok(());
	}

	// `/sys/class/net/<iface>/wireless` exists for a radio and does not for
	// anything else. Cheaper and more reliable than asking nl80211, and it
	// needs no privilege.
	let wireless = std::path::Path::new("/sys/class/net")
		.join(iface)
		.join("wireless")
		.exists();
	let driver = if wireless { "nl80211,wext" } else { "wired" };

	let program = supplicant_binary().ok_or_else(|| {
		format!(
			"no wpa_supplicant found for {iface}; install wpa_supplicant, or set \
			 `backend` on the device to say which supplicant to use"
		)
	})?;

	let status = Command::new(&program)
		.arg("-B")
		.arg(format!("-D{driver}"))
		.arg("-i")
		.arg(iface)
		.arg("-C")
		.arg(&dir)
		.status()
		.map_err(|error| format!("could not run {}: {error}", program.display()))?;
	if !status.success() {
		return Err(format!(
			"wpa_supplicant on {iface} (driver {driver}) exited with {status}"
		));
	}
	Ok(())
}

/// Find `wpa_supplicant`.
///
/// It lives in `/usr/sbin`, which is not on a non-root `PATH` on Debian and
/// several others -- so `Command::new("wpa_supplicant")` finds nothing on a
/// machine that has it. netcfgd normally runs as root and would not notice;
/// anything running it unprivileged would, and the error would say the wrong
/// thing.
fn supplicant_binary() -> Option<std::path::PathBuf> {
	for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] {
		let path = std::path::Path::new(dir).join("wpa_supplicant");
		if path.is_file() {
			return Some(path);
		}
	}
	std::env::var_os("PATH").and_then(|paths| {
		std::env::split_paths(&paths)
			.map(|dir| dir.join("wpa_supplicant"))
			.find(|path| path.is_file())
	})
}

fn stop_backend(kind: netcfgd_model::BackendKind, iface: &str) -> Result<(), String> {
	use netcfgd_model::BackendKind;
	match kind {
		BackendKind::Dhcp4 => match Command::new("dhcpcd").args(["-k", iface]).status() {
			Ok(_) => Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(error) => Err(format!("could not stop dhcpcd on {iface}: {error}")),
		},
		BackendKind::Supplicant => {
			// Terminated through its own control socket rather than by signal:
			// the socket is the interface netcfgd already speaks, and killing
			// a process by name would reach supplicants netcfgd did not start.
			let dir = ctrl_dir();
			match netcfgd_supplicant::Client::connect(&dir, iface) {
				Ok(client) => client
					.command("TERMINATE")
					.map_err(|error| format!("could not stop the supplicant on {iface}: {error}")),
				// Nothing listening is the state this was asked to produce.
				Err(_) => Ok(()),
			}
		}
		other => Err(format!(
			"stopping the {other:?} backend is not implemented in this build"
		)),
	}
}
