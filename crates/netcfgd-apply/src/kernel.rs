//! The executor that talks to the kernel.

use crate::Executor;
use netcfgd_model::route::NETCFGD_PROTO;
use netcfgd_model::{InterfaceKind, Origin};
use netcfgd_openvpn as openvpn;
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
	/// `(interface, enabled)` for each `use_tempaddr` sysctl written.
	pub privacy: Vec<(String, bool)>,
	/// `(interface, value)` for each `accept_ra` sysctl written.
	pub accept_ra: Vec<(String, u8)>,
	/// The backends the observation this apply ran against found *running*.
	///
	/// Not something the apply did -- it is what it saw -- and it is here
	/// because this is what already travels from the executor to the recorded
	/// state. It is how a restart counter gets cleared: a backend seen alive has
	/// stayed up, whatever it did last week. Decision 0079.
	pub observed_running: Vec<(netcfgd_model::BackendKind, String)>,
	/// `(interface, phase, value)` for each event hook that was run.
	pub hook_state: Vec<(String, netcfgd_model::HookPhase, String)>,
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
	/// The bond settings for each interface that is one.
	bonds: Vec<(String, netcfgd_model::interface::BondConfig)>,
	/// The bridge settings for each interface that is one.
	bridges: Vec<(String, netcfgd_model::interface::BridgeConfig)>,
	/// The whole kind of each macvlan, tunnel and `VXLAN` the document declares.
	///
	/// The three ops that re-send a kind's own settings to a device that already
	/// exists want exactly what creation wants -- a `NewLink` -- so what is held
	/// here is the `InterfaceKind` rather than a per-kind settings struct. That
	/// is what lets one function build the nest for both paths, which is the
	/// property 0057 insisted on and 0058 kept.
	link_kinds: Vec<(String, InterfaceKind)>,
	/// The `WireGuard` configuration for each interface that is one.
	///
	/// Held for the same reason `pppoe` and `dot1x` are: `wg.set_device` and
	/// `wg.set_peers` name an interface and the field that moved, and the
	/// values come from the document the executor was given. A plan carrying a
	/// peer list would write every public key and allowed prefix into
	/// `/run/netcfgd/plan.last.json` to say what the document already says.
	wireguard: Vec<(String, netcfgd_model::interface::WireGuardConfig)>,
	/// What each interface's `dhcp6` source asks for by way of a prefix.
	delegating: Vec<(String, netcfgd_model::PdRequest)>,
	/// What each interface advertises, and the nameservers its own scope holds.
	advertising: Vec<(String, netcfgd_model::interface::RaPolicy, Vec<String>)>,
	/// The `OpenVPN` tunnel on each interface that is one.
	///
	/// Carried for the reason the `PPPoE` session above is: the op says which
	/// interface, and the configuration it needs lives in a part of the
	/// document the op does not carry.
	openvpn: Vec<(String, netcfgd_model::OpenVpnConfig)>,
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
			wireguard: Vec::new(),
			bridges: Vec::new(),
			bonds: Vec::new(),
			link_kinds: Vec::new(),
			mac_policy: Vec::new(),
			pppoe: Vec::new(),
			delegating: Vec::new(),
			advertising: Vec::new(),
			openvpn: Vec::new(),
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
		observed: &netcfgd_model::Observed,
	) -> Self {
		self.run_dir = run_dir.into();
		// The same function the planner calls, and deliberately not a second
		// reading of the document. A scope can come from an observation rather
		// than from the document -- a report's nameservers are one -- and an
		// executor that rebuilt the list from the document alone
		// delivered a `resolv.conf` with nothing in it while the plan said it
		// had applied one.
		self.dns_scopes = netcfgd_model::dns::scopes(document, observed)
			.into_iter()
			.map(|(scope, policy)| netcfgd_model::AppliedDns { scope, policy })
			.collect();
		self.effects.observed_running = running_backends(observed);
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
		self.wireguard = wireguard_configs(document);
		self.bridges = bridge_configs(document);
		self.bonds = bond_configs(document);
		self.link_kinds = comparable_kinds(document);
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
		self.openvpn = document
			.interfaces
			.iter()
			.filter_map(|interface| match &interface.kind {
				InterfaceKind::OpenVpn(config) => Some((interface.name.clone(), config.clone())),
				_ => None,
			})
			.collect();
		// Which interfaces asked for a delegated prefix. The op carries only
		// the kind and the interface, and whether a prefix was asked for
		// decides which client can serve it at all -- see `start_dhcp6`.
		self.delegating = document
			.interfaces
			.iter()
			.filter_map(|interface| {
				interface.addressing.iter().find_map(|source| match source {
					netcfgd_model::AddressSource::Dhcp6(dhcp6) => dhcp6
						.prefix_delegation
						.as_ref()
						.map(|request| (interface.name.clone(), request.clone())),
					_ => None,
				})
			})
			.collect();
		// What an interface advertises, and the servers to advertise with it.
		// The prefix *references* are carried rather than resolved here: a
		// delegation arrives after the document does, so resolving at this
		// point would freeze whatever was known when the executor was built.
		self.advertising = document
			.interfaces
			.iter()
			.filter_map(|interface| {
				interface.advertise.as_ref().map(|policy| {
					let servers = interface
						.dns
						.as_ref()
						.map(|dns| {
							dns.servers
								.iter()
								.filter(|server| server.addr.is_ipv6())
								.map(|server| server.addr.to_string())
								.collect()
						})
						.unwrap_or_default();
					(interface.name.clone(), policy.clone(), servers)
				})
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
		let resolver = resolver();
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

	/// Start advertising what this interface's document says to advertise.
	///
	/// The prefix references are resolved *here*, at the last moment, and that
	/// is the point: `@pd:wan0` names a delegation that arrives after the
	/// document did, so a router advertising it is advertising something no
	/// config file could have contained (decision 0009). Resolving at apply
	/// time is what makes the reference worth having.
	///
	/// A reference that resolves to nothing is not an error here -- the plan
	/// warned, and `netcfgd_ra::start` refuses rather than advertising a router
	/// with no prefix.
	fn start_advertising(&self, iface: &str) -> Result<(), String> {
		let Some((_, policy, servers)) = self.advertising.iter().find(|(name, _, _)| name == iface)
		else {
			return Err(format!("no advertise block for {iface}"));
		};

		let prefixes = self.resolve_advertised(policy);
		netcfgd_ra::start(&self.run_dir, iface, policy, &prefixes, servers)
	}

	/// The prefixes an `advertise` block names, as they are *now*.
	///
	/// The sub-prefix an interface advertises is the one it addressed itself out
	/// of, so this is the same arithmetic the address used -- `::/64` as the
	/// suffix, because what is advertised is the block rather than an address in
	/// it. A reference that resolves to nothing contributes nothing; the
	/// planner has already warned, and `netcfgd_ra` refuses to advertise a
	/// router with no prefix at all.
	fn resolve_advertised(&self, policy: &netcfgd_model::interface::RaPolicy) -> Vec<String> {
		let delegations = netcfgd_host_prefixes(&self.run_dir);
		policy
			.prefixes
			.iter()
			.filter_map(|reference| {
				let (_, available) = delegations
					.iter()
					.find(|(source, _)| source == &reference.source)?;
				let prefix = available.get(reference.index as usize)?;
				netcfgd_model::derive_from_delegation(prefix, reference, "::/64").ok()
			})
			.collect()
	}

	/// Rewrite what an interface advertises and tell radvd to re-read it.
	///
	/// The prefixes are resolved here for the same reason `start_advertising`
	/// resolves them here: the delegation arrives after the document, and a
	/// reload exists precisely because it can arrive *again* as something else.
	fn reload_advertising(&self, iface: &str) -> Result<(), String> {
		let Some((_, policy, servers)) = self.advertising.iter().find(|(name, _, _)| name == iface)
		else {
			return Err(format!("no advertise block for {iface}"));
		};
		let prefixes = self.resolve_advertised(policy);
		netcfgd_ra::reload(&self.run_dir, iface, policy, &prefixes, servers)
	}

	/// Hang up the `PPPoE` session netcfgd dialled.
	///
	/// Until this existed, netcfgd could dial and not hang up: `stop_backend`
	/// answered "not implemented in this build", so deleting the block from the
	/// config failed the apply and left `pppd` holding the line -- with
	/// `persist` and `maxfail 0` in its options file, forever. Found by dialling
	/// a real session against a real access concentrator, which is the first
	/// thing here that ever could have found it.
	///
	/// **`pppd` has no control socket**, which is what every other daemon here
	/// is stopped through (decision 0014). What it has is a pid file it writes
	/// itself, named for the interface. That is a record of this session rather
	/// than a search for something that looks like one -- but a pid file
	/// outlives the process it names and pids are recycled, so the pid is
	/// checked against `/proc/<pid>/cmdline` before anything is signalled: it
	/// has to be a `pppd` running *the options file netcfgd wrote for this
	/// interface*. An operator's own `pppd` cannot match that, which is a
	/// stronger claim than "not by name" rather than an approximation of it.
	fn stop_pppoe(&self, iface: &str) -> Result<(), String> {
		// The report first, and whether or not anything is listening: it is a
		// claim about resolvers that a session is providing, and the session is
		// going either way. pppd's own ip-down script may write an empty one
		// afterwards, which means the same thing.
		let _ = std::fs::remove_file(report_path(&self.run_dir, iface));

		let Some((pid, path)) = Self::pppd_pid(iface) else {
			// Nothing netcfgd can identify as its own is running, which is the
			// state this was asked to produce. Deliberately not an error: an
			// apply that has already been run once, or a session that died on
			// its own, both land here.
			return Ok(());
		};
		netcfgd_sys::process::terminate(pid).map_err(|error| {
			format!("could not stop the pppoe session on {iface} (pid {pid} from {path}): {error}")
		})
	}

	/// The pid of the `pppd` netcfgd started for this interface, if it is
	/// running.
	///
	/// The directory is not fixed. Debian's `pppd` 2.5.2 writes `/run/ppp0.pid`
	/// and upstream's default is `${runstatedir}/pppd/`, so both are looked in
	/// rather than one being hardcoded -- a wrong guess here would silently stop
	/// nothing.
	fn pppd_pid(iface: &str) -> Option<(i32, String)> {
		let options = run_dir_path().join("ppp").join(iface);
		let options = options.to_string_lossy().into_owned();
		for dir in ["/run", "/run/pppd", "/var/run", "/var/run/pppd"] {
			let path = std::path::Path::new(dir).join(format!("{iface}.pid"));
			// The options file netcfgd generated is the marker: a path netcfgd
			// chose, unique to this session. The rule itself is in
			// `netcfgd_sys::process::pid_of`.
			if let Some(pid) = netcfgd_sys::process::pid_of(&path, &options) {
				return Some((pid, path.display().to_string()));
			}
		}
		None
	}

	/// Start the `OpenVPN` tunnel the document puts on this interface.
	///
	/// netcfgd hands over the operator's `.ovpn` and reads none of it (decision
	/// 0046). What it adds is the three things that make the daemon netcfgd's
	/// to manage rather than one that merely happens to be running: a
	/// management socket to stop it through, `--daemon` so the apply does not
	/// block on a tunnel that may take seconds to come up, and a log to quote
	/// when it will not start.
	fn start_openvpn(&self, iface: &str) -> Result<(), String> {
		let Some((_, config)) = self.openvpn.iter().find(|(name, _)| name == iface) else {
			return Err(format!("no openvpn configuration for {iface}"));
		};
		// Resolved here and nowhere earlier: the document carries a `SecretRef`
		// and the plan carries an interface name, so this is the first point at
		// which a password exists at all -- and it exists only long enough to
		// reach a 0600 file. The compiler has already refused a username
		// without a password, so one being present implies the other.
		let resolved = match (&config.username, &config.password) {
			(Some(username), Some(reference)) => {
				let resolver = resolver();
				let password = resolver
					.resolve(reference)
					.map_err(|error| format!("{iface}: {error}"))?;
				Some((username.clone(), password))
			}
			_ => None,
		};
		openvpn::start(
			&self.run_dir,
			iface,
			&config.config,
			resolved
				.as_ref()
				.map(|(user, password)| (user.as_str(), password.expose())),
			&report_path(&self.run_dir, iface),
		)
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
		let resolver = resolver();
		netcfgd_hostapd::start(&self.run_dir, access_point, &resolver)
	}

	/// Give a freshly started supplicant the networks the document describes.
	///
	/// Wired and wireless are different populations, not different amounts of
	/// the same one: a wired port has exactly one profile and it uses
	/// `IEEE8021X`, while a radio gets every network in the document and picks
	/// among them.
	fn populate_supplicant(&self, iface: &str) -> Result<(), String> {
		let dir = netcfgd_supplicant::ctrl_dir();
		// Impatiently, and the deadline matters *after* the connect rather than
		// during it. `connect_within` sets the timeout on the connection it
		// returns as well as on its opening `PING`, which is the half that
		// counts here: a supplicant can answer the `PING` and wedge before the
		// first `SET`, and this runs inside `start_backend` on the apply path,
		// so the reconcile loop is what waits. Measured on the default: ten
		// seconds flat, per command, against a fake that answered `PING` and
		// then nothing. Against a real one every command below answers in
		// 0.07-0.13ms. Decision 0114.
		let client =
			netcfgd_supplicant::Client::connect_within(&dir, iface, netcfgd_supplicant::IMPATIENT)
				.map_err(|error| {
					format!("started a supplicant on {iface} but cannot reach it: {error}")
				})?;

		// Explicit, not assumed. Decision 0015: a silent default is not a
		// control, and this is the property that keeps the document the only
		// authority.
		client
			.command("SET update_config 0")
			.map_err(|error| format!("could not pin update_config on {iface}: {error}"))?;

		let resolver = resolver();

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

	/// Send a bridge's own settings, whether it was just made or already was.
	///
	/// One function for both, which is what the comment above `link.create` has
	/// claimed since bridges arrived: the kernel takes these as an
	/// `RTM_NEWLINK` either way, so a second copy would be two paths that can
	/// disagree about what a forward delay is. Until decision 0057 only one
	/// caller existed, and an edited `stp` reached nothing.
	fn apply_bridge_attrs(
		&mut self,
		name: &str,
		bridge: &netcfgd_model::interface::BridgeConfig,
	) -> Result<(), String> {
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
			.map_err(|error| format!("could not set the attributes of {name}: {error}"))
	}

	/// The document's `WireGuard` configuration for one interface.
	///
	/// An executor built without a document has none of these, which is the
	/// failure `make executor-policy` exists to prevent -- so this says what
	/// happened rather than silently configuring a device with nothing.
	/// The document's settings for one bond.
	fn bond_config(&self, name: &str) -> Result<netcfgd_model::interface::BondConfig, String> {
		self.bonds
			.iter()
			.find(|(bond, _)| bond == name)
			.map(|(_, config)| config.clone())
			.ok_or_else(|| format!("{name}: no bond settings in the document being applied"))
	}

	/// The document's kind for one macvlan, tunnel or `VXLAN`.
	fn link_kind(&self, name: &str) -> Result<InterfaceKind, String> {
		self.link_kinds
			.iter()
			.find(|(iface, _)| iface == name)
			.map(|(_, kind)| kind.clone())
			.ok_or_else(|| format!("{name}: no link settings in the document being applied"))
	}

	/// The document's settings for one bridge.
	fn bridge_config(&self, name: &str) -> Result<netcfgd_model::interface::BridgeConfig, String> {
		self.bridges
			.iter()
			.find(|(bridge, _)| bridge == name)
			.map(|(_, config)| config.clone())
			.ok_or_else(|| format!("{name}: no bridge settings in the document being applied"))
	}

	fn wireguard_config(
		&self,
		iface: &str,
	) -> Result<netcfgd_model::interface::WireGuardConfig, String> {
		self.wireguard
			.iter()
			.find(|(name, _)| name == iface)
			.map(|(_, config)| config.clone())
			.ok_or_else(|| {
				format!("{iface}: no wireguard configuration in the document being applied")
			})
	}

	/// Give a `WireGuard` device its keys and peers.
	///
	/// Called when the link is created and again by `wg.set_device` and
	/// `wg.set_peers` when the document has moved under a device that already
	/// exists (decision 0054). One function rather than three: the peer list a
	/// revocation depends on is built here, and a second copy of this loop is
	/// how the create path and the correct-an-existing-device path come to
	/// disagree about what a peer is.
	///
	/// `parts` says which half is meant. The whole thing at creation; the
	/// device's own fields or its peer list on their own afterwards, because
	/// the kernel takes them separately and a plan that says `wg.set_device`
	/// should not quietly replace peers.
	fn configure_wireguard(
		&self,
		name: &str,
		config: &netcfgd_model::interface::WireGuardConfig,
		parts: WgParts,
	) -> Result<(), String> {
		let resolver = resolver();
		let private = match parts {
			WgParts::Peers => None,
			WgParts::Whole | WgParts::DeviceOnly => Some(
				resolve_key(&resolver, &config.private_key)
					.map_err(|error| format!("{name}: private key: {error}"))?,
			),
		};

		let mut peers = Vec::new();
		// One line per peer that has a preshared key: its public key, which is
		// how the observation finds it again, and a digest of the secret. The
		// device's own key record and this one answer the same question about
		// two different secrets (0055, 0056).
		let mut presets: Vec<String> = Vec::new();
		// Built only where they are meant, so a `wg.set_device` does not
		// resolve a preshared key or a hostname it has no use for -- either of
		// which can fail, and failing over something the op was not about is
		// how an unrelated change stops a port being set.
		let wanted = match parts {
			WgParts::DeviceOnly => &[][..],
			WgParts::Whole | WgParts::Peers => &config.peers[..],
		};
		for peer in wanted {
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
			if let Some(secret) = &preshared {
				presets.push(format!(
					"{} {}",
					peer.public_key.render(),
					netcfgd_model::hash::sha256_hex(secret)
				));
			}
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
				// A `wg.set_peers` says nothing about the device's own fields,
				// so it sends neither -- and the kernel leaves what it has.
				listen_port: match parts {
					WgParts::Peers => None,
					WgParts::Whole | WgParts::DeviceOnly => config.listen_port,
				},
				fwmark: match parts {
					WgParts::Peers => None,
					WgParts::Whole | WgParts::DeviceOnly => config.fwmark,
				},
				peers,
				replace_peers: matches!(parts, WgParts::Whole | WgParts::Peers),
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
		})?;

		// What key the kernel was given, so that a *rotated* one is something
		// the next reconcile can notice. Written after the kernel took it, for
		// the reason a `.ovpn` hash is written after openvpn accepted the file:
		// a record of a configuration that was refused is a record of nothing.
		if let Some(private) = private {
			record_key(&self.run_dir, name, &private);
		}
		// Only where the peer list was actually sent. A `wg.set_device` leaves
		// the kernel's peers alone, so rewriting this record from an empty list
		// would say every preshared key had gone.
		if matches!(parts, WgParts::Whole | WgParts::Peers) {
			record_presets(&self.run_dir, name, &presets);
		}
		Ok(())
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

				// Mark it as netcfgd's in the kernel, so that ownership does
				// not live only in `/run` -- which a restart deletes (0136).
				//
				// **Deliberately not fatal.** Alternative names share the
				// lookup namespace with real ones, so a machine that already
				// has an interface by this name refuses it with EEXIST; and a
				// kernel that does not know `RTM_NEWLINKPROP` refuses it too.
				// Neither is a reason to fail creating a link that was created
				// perfectly well. An unmarked link falls back to the recorded
				// state, which is exactly where every link was before this.
				if let Some(altname) = netcfgd_model::route::netcfgd_altname(name) {
					if let Ok(index) = self.index_of(name) {
						if let Err(error) = self.socket.add_altname(index, &altname) {
							// Said rather than swallowed: the link works, and
							// the thing that was lost is only visible later,
							// as a restart that fails to reconcile it.
							eprintln!(
								"netcfgd: could not mark {name} as netcfgd's with the alternative name {altname}: {error}"
							);
							eprintln!(
								"netcfgd:   its ownership is recorded in /run instead, which a restart loses"
							);
						}
					}
				}

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
					self.configure_wireguard(name, config, WgParts::Whole)?;
				}
				if let InterfaceKind::Bridge(bridge) = &**kind {
					self.apply_bridge_attrs(name, bridge)
						.map_err(|error| format!("created {name} but {error}"))?;
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
				if *kind == netcfgd_model::BackendKind::RouterAdvert {
					self.start_advertising(iface)?;
					self.effects.started_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				if *kind == netcfgd_model::BackendKind::Dhcp6 {
					let request = self
						.delegating
						.iter()
						.find(|(name, _)| name == iface)
						.map(|(_, request)| request);
					start_dhcp6(iface, request)?;
					self.effects.started_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				if *kind == netcfgd_model::BackendKind::OpenVpn {
					self.start_openvpn(iface)?;
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
			Op::BackendReload { kind, iface } => {
				// radvd re-reads its configuration on SIGHUP, so a changed
				// prefix costs nothing on the wire -- unlike an access point,
				// where the same question means a restart and a deauthenticated
				// LAN (decision 0026). Rewriting first and signalling second is
				// the order that matters: the daemon reads the file when it is
				// told to, not when it is signalled.
				if *kind == netcfgd_model::BackendKind::RouterAdvert {
					self.reload_advertising(iface)?;
					return Ok(());
				}
				// Every other backend falls to the catch-all below, which says
				// so by name. Nothing else here has a reload: hostapd's would
				// be a restart (0026), a DHCP client's is the client's own
				// business, and inventing one that stopped and started would
				// hide that difference behind a word.
				Err(format!(
					"reloading the {kind:?} backend on {iface} is not implemented in \
					 this build"
				))
			}
			Op::BackendStop { kind, iface } => {
				if *kind == netcfgd_model::BackendKind::RouterAdvert {
					netcfgd_ra::stop(&self.run_dir, iface)?;
					self.effects.stopped_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				if *kind == netcfgd_model::BackendKind::Pppoe {
					self.stop_pppoe(iface)?;
					self.effects.stopped_backends.push((*kind, iface.clone()));
					return Ok(());
				}
				if *kind == netcfgd_model::BackendKind::OpenVpn {
					// Through its own management socket, never by signalling a
					// process found by name: an operator's own OpenVPN tunnels
					// are common, and decision 0014's sentence about the
					// supplicant applies here without changing a word.
					openvpn::stop(&self.run_dir, iface, &report_path(&self.run_dir, iface))?;
					self.effects.stopped_backends.push((*kind, iface.clone()));
					return Ok(());
				}
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
			Op::HookRun {
				iface,
				phase,
				path,
				value,
			} => {
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
				let mut env = crate::hooks::HookEnv::for_interface(iface);
				// One field on the op, and the phase says which variable a script
				// should see it in: a `lease` script reads `NCFG_ADDR` because the
				// value is an address, and a `carrier` script reads `NCFG_REASON`
				// because the value is `up` or `down`. Putting both variables on
				// both phases would tell a script to look in a place its own phase
				// never fills.
				match (*phase, value) {
					(netcfgd_model::HookPhase::Lease, Some(value)) => {
						env.addr = Some(value.clone());
					}
					(netcfgd_model::HookPhase::Carrier, Some(value)) => {
						env.reason = Some(value.clone());
					}
					_ => {}
				}
				// Recorded before the hook runs rather than after, and on purpose: an
				// event hook that failed and was retried on every reconcile would be
				// a plan that never converges, which section 4 promises against. What
				// went wrong is in the journal instead (0064).
				if let Some(value) = value {
					self.effects
						.hook_state
						.push((iface.clone(), *phase, value.clone()));
				}
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
			Op::HostnameSet { name } => set_hostname(name),
			Op::SysctlSetPrivacy {
				iface,
				prefer_temporary,
			} => {
				set_privacy(iface, *prefer_temporary)?;
				self.effects
					.privacy
					.push((iface.clone(), *prefer_temporary));
				Ok(())
			}
			Op::SysctlSetAcceptRa { iface, value } => {
				set_accept_ra(iface, *value)?;
				self.effects.accept_ra.push((iface.clone(), *value));
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
			// Both of these were declared in the action taxonomy, pinned by the
			// plan witness, and reached the arm below saying they were not
			// implemented in this build -- because nothing emitted them. A
			// WireGuard device was configured when its link was created and
			// never again, so an edited listen port did nothing and a deleted
			// peer kept its access (decision 0054).
			//
			// The document is found by name rather than carried in the op: the
			// op names the interface and the fields that moved, and the
			// executor already holds the document it is applying. Putting a
			// peer list in the plan would put public keys and every allowed
			// prefix into `/run/netcfgd/plan.last.json` for no gain.
			Op::LinkSetBond { name, mode } => {
				let bond = self.bond_config(name)?;
				let index = self.index_of(name)?;
				self.socket
					.set_bond_attrs(
						index,
						// Only where the plan says it is meant. A mode the
						// kernel will not take fails the whole message, taking
						// the monitoring interval with it.
						mode.then(|| bond.mode.number()),
						bond.miimon,
					)
					.map_err(|error| format!("could not set the attributes of {name}: {error}"))
			}
			Op::LinkSetBridge { name } => {
				let bridge = self.bridge_config(name)?;
				self.apply_bridge_attrs(name, &bridge)
			}
			// One arm for three kinds, because what each of them needs is the
			// nest its own creation would build. The op says which interface and
			// the reason says which field moved; the values come from the
			// document, as they do for a bridge and for a `WireGuard` device.
			Op::LinkSetMacvlan { name }
			| Op::LinkSetTunnel { name }
			| Op::LinkSetVxlan { name } => {
				let kind = self.link_kind(name)?;
				let link = new_link(name, &kind, self)?;
				let index = self.index_of(name)?;
				self.socket
					.set_link_kind(index, &link, name)
					.map_err(|error| format!("could not set the settings of {name}: {error}"))
			}
			Op::WgSetDevice { iface, .. } => {
				let config = self.wireguard_config(iface)?;
				self.configure_wireguard(iface, &config, WgParts::DeviceOnly)
			}
			Op::WgSetPeers { iface, .. } => {
				let config = self.wireguard_config(iface)?;
				self.configure_wireguard(iface, &config, WgParts::Peers)
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

/// Where netcfgd records which key it loaded into a `WireGuard` device.
///
/// Under `/run`, like every other record netcfgd keeps of its own past.
#[must_use]
pub fn key_record_path(run: &std::path::Path, iface: &str) -> std::path::PathBuf {
	run.join("wireguard").join(format!("{iface}.key.sha256"))
}

/// Record which key a device was given, as a digest and never as a value.
///
/// The question this answers is one nothing else could: an operator rotates the
/// secret, and the kernel goes on using the key it was handed. The kernel
/// reports the *public* key it derived, and matching that against the store
/// would mean deriving one -- which is curve25519, and was written down here as
/// the reason this could not be done.
///
/// It is not the reason. Decision 0053 hashes a file netcfgd will not read to
/// find out whether it changed; this hashes a secret netcfgd must not carry, to
/// answer exactly the same question. No arithmetic beyond the SHA-256 the model
/// already has for hooks.
///
/// **A digest of a `WireGuard` private key is not a way back to one.** It is 32
/// octets of kernel randomness, so there is no dictionary and no structure to
/// attack -- unlike a passphrase, which is why this technique would be a poor
/// answer for one. The file is 0600 under `/run`, nothing reads it but the
/// observer, and what leaves the observer is a boolean.
fn record_key(run: &std::path::Path, iface: &str, private: &[u8; 32]) {
	let path = key_record_path(run, iface);
	if let Some(parent) = path.parent() {
		let _ = std::fs::create_dir_all(parent);
	}
	let digest = netcfgd_model::hash::sha256_hex(private);
	if std::fs::write(&path, &digest).is_ok() {
		let _ =
			std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
	}
}

/// Where netcfgd records which preshared key each peer was given.
#[must_use]
pub fn preset_record_path(run: &std::path::Path, iface: &str) -> std::path::PathBuf {
	run.join("wireguard").join(format!("{iface}.psk.sha256"))
}

/// Record the peers' preshared keys, as digests keyed by public key.
///
/// The same technique as [`record_key`] and the same argument for it: a
/// preshared key is 32 octets a `wg genpsk` produced, so a digest is not a route
/// back, and the alternative is a rotation that changes nothing. Keyed by the
/// peer's public key because that is what both sides have -- the kernel has
/// never heard the operator's label for a peer.
///
/// Written whole every time the peer list is sent, so a peer that lost its
/// preshared key loses its line rather than keeping a stale one.
fn record_presets(run: &std::path::Path, iface: &str, presets: &[String]) {
	let path = preset_record_path(run, iface);
	if let Some(parent) = path.parent() {
		let _ = std::fs::create_dir_all(parent);
	}
	if presets.is_empty() {
		let _ = std::fs::remove_file(&path);
		return;
	}
	if std::fs::write(&path, presets.join("\n")).is_ok() {
		let _ =
			std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
	}
}

/// Every interface whose kind's own settings are corrected on a live device.
///
/// The whole kind rather than a settings struct, unlike [`bond_configs`] and
/// [`bridge_configs`]: what `link.set_macvlan`, `link.set_tunnel` and
/// `link.set_vxlan` need is the same `NewLink` the create path builds, so what
/// they are given is what `new_link` takes.
fn comparable_kinds(document: &netcfgd_model::Document) -> Vec<(String, InterfaceKind)> {
	document
		.interfaces
		.iter()
		.filter(|interface| {
			matches!(
				interface.kind,
				InterfaceKind::Macvlan(_) | InterfaceKind::Tunnel(_) | InterfaceKind::Vxlan(_)
			)
		})
		.map(|interface| (interface.name.clone(), interface.kind.clone()))
		.collect()
}

/// Every interface that is a bond, with its settings.
fn bond_configs(
	document: &netcfgd_model::Document,
) -> Vec<(String, netcfgd_model::interface::BondConfig)> {
	document
		.interfaces
		.iter()
		.filter_map(|interface| match &interface.kind {
			netcfgd_model::InterfaceKind::Bond(bond) => {
				Some((interface.name.clone(), bond.clone()))
			}
			_ => None,
		})
		.collect()
}

/// Every interface that is a bridge, with its settings.
fn bridge_configs(
	document: &netcfgd_model::Document,
) -> Vec<(String, netcfgd_model::interface::BridgeConfig)> {
	document
		.interfaces
		.iter()
		.filter_map(|interface| match &interface.kind {
			netcfgd_model::InterfaceKind::Bridge(bridge) => {
				Some((interface.name.clone(), bridge.clone()))
			}
			_ => None,
		})
		.collect()
}

/// Every interface that is a `WireGuard` device, with its configuration.
///
/// A free function rather than a block inside `with_context`, which is at the
/// hundred-line limit clippy enforces -- and is a list of one-liners for a
/// reason, being the one place that decides what the executor knows.
fn wireguard_configs(
	document: &netcfgd_model::Document,
) -> Vec<(String, netcfgd_model::interface::WireGuardConfig)> {
	document
		.interfaces
		.iter()
		.filter_map(|interface| match &interface.kind {
			netcfgd_model::InterfaceKind::WireGuard(config) => {
				Some((interface.name.clone(), config.clone()))
			}
			_ => None,
		})
		.collect()
}

/// Which half of a `WireGuard` device a call is about.
///
/// The kernel takes the device's own fields and its peer list separately, and
/// the action taxonomy has an op for each. Naming the three cases here rather
/// than passing two booleans is what stops "device only, but also replace the
/// peers with the empty list I did not fill in" being expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WgParts {
	/// Everything, which is what a newly created device needs.
	Whole,
	/// The private key, listen port and firewall mark. `wg.set_device`.
	DeviceOnly,
	/// The peer list, replacing what the device holds. `wg.set_peers`.
	Peers,
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

/// Set the running hostname.
///
/// `/proc/sys/kernel/hostname`, not `sethostname(2)`: the syscall would be an
/// `unsafe` FFI call, and this crate forbids `unsafe` -- the file is the same
/// value and needs no exception. Not `/etc/hostname` either, which is what the
/// init system reads at boot and is not netcfgd's to write (constraint 1 makes
/// `/etc/netcfgd` the authority, and the DNS artifacts are the only files netcfgd
/// puts anywhere else in `/etc`).
///
/// So this does not survive a reboot on its own, and that is the honest
/// behaviour: netcfgd sets the name on every apply, and the first apply after
/// boot is what puts it back.
fn set_hostname(name: &str) -> Result<(), String> {
	let root = std::env::var_os("NCFG_PROC_ROOT").map_or_else(
		|| std::path::PathBuf::from("/proc"),
		std::path::PathBuf::from,
	);
	std::fs::write(root.join("sys/kernel/hostname"), name)
		.map_err(|error| format!("cannot set the hostname to `{name}`: {error}"))
}

/// Turn RFC 4941 temporary addresses on or off for one interface.
///
/// `2` prefers the temporary address for outgoing connections and `0` turns the
/// mechanism off; the kernel's `1` -- generate one but prefer the stable address
/// -- has no spelling in the document and is never written here.
///
/// **This only decides what happens to prefixes from now on.** The kernel builds
/// a temporary address when it processes a router advertisement, so an interface
/// that is already configured gains one at the next RA rather than at the moment
/// this is written. Nothing here waits for that: the sysctl is the state the
/// document asks for, and the address is the kernel's to produce.
///
/// Fatal on failure, unlike the IPv6 half of `set_forwarding`. There is no IPv4
/// equivalent to fall back to -- a machine whose kernel has no IPv6 has no
/// temporary addresses to configure, and the planner never asks, because the
/// observation of an absent sysctl is `None` and nothing is planned on one.
fn set_privacy(iface: &str, prefer_temporary: bool) -> Result<(), String> {
	let root = std::env::var_os("NCFG_PROC_ROOT").map_or_else(
		|| std::path::PathBuf::from("/proc"),
		std::path::PathBuf::from,
	);
	let value = if prefer_temporary { "2" } else { "0" };
	std::fs::write(
		root.join(format!("sys/net/ipv6/conf/{iface}/use_tempaddr")),
		value,
	)
	.map_err(|error| format!("cannot set temporary addresses on {iface}: {error}"))
}

/// Whether the kernel acts on a router advertisement here.
///
/// Fatal on failure, as `set_privacy` is and for the same reason: the
/// observation of an absent sysctl is `None` and nothing is planned on one, so
/// reaching this means the file was there when it was read.
///
/// netcfgd writes only `2` -- accept even while forwarding -- and `1`, which is
/// the kernel's own default and is what an interface that stops asking for SLAAC
/// gets back. It never writes `0`: switching advertisements off is a thing an
/// operator may have chosen and no document here asks for. Decision 0073.
fn set_accept_ra(iface: &str, value: u8) -> Result<(), String> {
	let root = std::env::var_os("NCFG_PROC_ROOT").map_or_else(
		|| std::path::PathBuf::from("/proc"),
		std::path::PathBuf::from,
	);
	std::fs::write(
		root.join(format!("sys/net/ipv6/conf/{iface}/accept_ra")),
		value.to_string(),
	)
	.map_err(|error| format!("cannot set accept_ra on {iface}: {error}"))
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
			// The model's own function, not a second copy of the kernel's
			// numbering: the observer reads these back through
			// `MacvlanMode::from_number`, and two lists of four numbers in two
			// crates is how a mode comes to mean one thing on the way out and
			// another on the way in.
			mode: macvlan.mode.number(),
		}),
		InterfaceKind::Tunnel(tunnel) => Ok(NewLink::Tunnel(netcfgd_sys::ops::TunnelSpec {
			kind: tunnel.mode.name(),
			parent: match &tunnel.parent {
				Some(parent) => Some(executor.index_of(parent)?),
				None => None,
			},
			local: tunnel.local,
			remote: tunnel.remote,
			ttl: tunnel.ttl,
			key: tunnel.key,
		})),
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
		InterfaceKind::OpenVpn(_) => "openvpn",
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
/// What `udhcpc` is started with.
///
/// A function rather than a literal in the caller, so the argument list has
/// somewhere to be asserted -- `dhcpcd_start_args` beside it is the same shape
/// for the same reason. The one below that nothing could have caught otherwise
/// is `-O search`.
fn udhcpc_start_args(
	iface: &str,
	script: &std::path::Path,
	pidfile: &std::path::Path,
) -> Vec<String> {
	vec![
		"-b".to_owned(),
		"-i".to_owned(),
		iface.to_owned(),
		"-s".to_owned(),
		script.display().to_string(),
		"-p".to_owned(),
		pidfile.display().to_string(),
		// Release the lease on the way out, which is also what makes the script
		// run `deconfig` on a `SIGTERM`. Without it a stopped client leaves its
		// address on the interface -- measured -- where `dhcpcd -k` takes it
		// away, and two clients that disagree about what stopping means is two
		// behaviours for one `backend.stop`.
		"-R".to_owned(),
		// Ask for the search list. **udhcpc does not request option 119 by
		// default** -- its list is 1, 3, 6, 12, 15, 28, 42 -- so a server that
		// honours the request list never sends one. 0067's search suffixes
		// reached netcfgd only because the live test's server was `busybox
		// udhcpd`, which pushes every configured option whether it was asked
		// for or not; against dnsmasq, ISC dhcpd or a domestic router the
		// client asked for nothing and got nothing. Found by porting that test
		// to a second server, not by reading the code.
		//
		// Option 15 (`domain`) is in the default list and is a single name; 119
		// is the list, and is what an operator writing `dns { }` on a DHCP
		// interface expects to arrive.
		"-O".to_owned(),
		"search".to_owned(),
	]
}

fn start_backend(
	kind: netcfgd_model::BackendKind,
	iface: &str,
	metric: Option<u32>,
) -> Result<(), String> {
	use netcfgd_model::BackendKind;

	// **Adopt anything netcfgd already started, before deciding to start it.**
	//
	// 0140 recovered the supplicant this way and 0143 did dhcpcd through its
	// control socket. Doing it per backend left four that could not be
	// recovered at all -- hostapd, radvd, openvpn and the v6 client -- which is
	// what kept `KillMode=process` unshippable (0142): holding what cannot be
	// re-adopted is worse than not holding it.
	//
	// It generalises because `backend_pid_file` already answers the only
	// question that matters. The pair it returns is a pid file and **the marker
	// that proves the process is netcfgd's**, and for openvpn, radvd, hostapd
	// and the supplicant that marker is an absolute path netcfgd composed -- a
	// management socket, a generated config, a pid file -- which each of those
	// daemons carries in its own `argv`.
	//
	// **The weak markers are excluded by shape rather than by name.** The two
	// DHCP clients get `iface` as their marker, which `backend_pid_file` itself
	// calls "the weakest marker netcfgd uses": `eth0` is a short string an
	// unrelated command line could contain, and scanning `/proc` for it would
	// reach somebody else's process. So only an absolute path qualifies, and
	// Dhcp4 keeps the two specific recoveries it already has.
	// **And only what still works.** A process carrying netcfgd's marker that
	// cannot be reached is not an adoption candidate -- it is a corpse holding a
	// radio, and taking ownership of it is strictly worse than leaving the radio
	// to whoever can still use it.
	//
	// Measured, on the machine that prompted this: netcfgd adopted a supplicant
	// left alive by `KillMode=process` (0142), could not talk to it, displaced
	// NetworkManager's working one in doing so, and then declined to restart it
	// because 0141 makes that a person's decision. The radio was captured by a
	// dead process and NetworkManager was locked out too. Three defensible
	// changes composing into a trap.
	//
	// Declining to adopt costs nothing by comparison: netcfgd refuses the radio,
	// says why, and whoever can drive it keeps it.
	if let Some((pidfile, marker)) = backend_pid_file(kind, &run_dir_path(), iface) {
		if marker.starts_with('/')
			&& netcfgd_sys::process::pid_of(&pidfile, &marker).is_none()
			&& backend_is_reachable(kind, iface)
		{
			if let Some(pid) = netcfgd_sys::process::pid_by_marker(&marker) {
				if let Some(parent) = pidfile.parent() {
					std::fs::create_dir_all(parent)
						.map_err(|error| format!("{}: {error}", parent.display()))?;
				}
				std::fs::write(&pidfile, format!("{pid}\n")).map_err(|error| {
					format!("cannot record the {kind:?} backend on {iface}: {error}")
				})?;
				eprintln!(
					"netcfgd: adopted the {kind:?} backend already running on {iface} (pid {pid}); it is netcfgd's, by the `{marker}` it was started with"
				);
				return Ok(());
			}
		}
	}
	match kind {
		BackendKind::Dhcp4 => {
			// Where the metric goes, and why it is dhcpcd's alone, is on
			// `dhcpcd_start_args`. It was a field in the model that reached
			// nothing until carrier switching needed it.
			let metric = metric.map(|value| value.to_string());

			// udhcpc needs a script and a pid file, and netcfgd used to pass
			// neither: without `-s` the client obtains a lease and configures
			// nothing at all, and without `-p` there is no way to stop it.
			// Decision 0065.
			let (script, pidfile) = write_udhcpc_script(iface)?;

			// **A udhcpc netcfgd already started, whose pid file went with the
			// run directory.** 0140's case, one backend over: the client keeps
			// netcfgd's `-p` path as a whole argv element for as long as it
			// lives -- busybox does not call `setproctitle` -- while the file
			// that path names sits in `/run/netcfgd`, which
			// `RuntimeDirectory=` deletes on a stop.
			//
			// **Without this netcfgd starts a second client**, and unlike
			// dhcpcd, udhcpc has no instance lock to refuse it. Measured: both
			// run, both take the same lease (same MAC, same client id, the
			// server re-offers), and the second overwrites the pid file -- so
			// the first becomes permanently unreachable. A later
			// `backend.stop` then signals only the second, and with `-R` that
			// RELEASEs the lease and the generated script removes the address,
			// leaving the interface bare while a live client still believes it
			// holds the lease and will not re-add it until T1.
			//
			// The marker is the pid file path rather than the script path:
			// both are netcfgd's and absolute, but the script is also named in
			// the environment of every hook the client forks, while `-p` is
			// carried by the client alone.
			if netcfgd_sys::process::pid_of(&pidfile, &pidfile.to_string_lossy()).is_none() {
				if let Some(pid) = netcfgd_sys::process::pid_by_marker(&pidfile.to_string_lossy()) {
					std::fs::write(&pidfile, format!("{pid}\n")).map_err(|error| {
						format!("cannot record the dhcp client on {iface}: {error}")
					})?;
					eprintln!(
						"netcfgd: adopted the dhcp client already running on {iface} (pid {pid}); it is netcfgd's, by the `-p {}` it was started with",
						pidfile.display()
					);
					return Ok(());
				}
			}
			// dhcpcd gets one too, for the nameservers and to stop its own hooks
			// writing resolv.conf behind netcfgd's back (0066).
			let hook = write_dhcpcd_script(iface, None)?;
			let config = write_dhcpcd_config(iface, "4")?;

			// **The one backend netcfgd cannot recognise from its process
			// image.** dhcpcd's `setproctitle` destroys argv and environment
			// alike, so `pid_by_marker` -- which recovers the supplicant and
			// udhcpc -- has nothing to match. What survives is dhcpcd's own
			// memory of `-f`, recited on its control socket, so netcfgd asks
			// (0143).
			//
			// Adopting rather than starting matters more here than anywhere:
			// a second `dhcpcd -b` against a running one is a SILENT no-op --
			// measured, it prints "sending commands to dhcpcd process" and
			// exits 0 having started nothing -- so without this netcfgd would
			// report success on every reconcile while the orphan kept the
			// lease and netcfgd kept no handle on it.
			match crate::dhcpcd_control::config_file_of(&dhcpcd_run_dir(), iface, "4") {
				Some(seen) if seen == config.display().to_string() => {
					// The symlink is re-created above, which is the other half:
					// the `-f` string in dhcpcd's memory survives the wipe, but
					// a later `dhcpcd -n` reload would read a dangling path and
					// silently drop the operator's options.
					eprintln!(
						"netcfgd: adopted the dhcp client already running on {iface}; it is netcfgd's, by the `-f {}` it recites",
						config.display()
					);
					return Ok(());
				}
				// Somebody else's, or netcfgd could not tell. Neither is a
				// reason to spawn beside it, and 0141 makes the difference the
				// caller's to report rather than this function's to guess.
				Some(_) | None => {}
			}

			let dhcpcd = dhcpcd_start_args(
				DHCPCD_V4,
				iface,
				metric.as_deref(),
				&hook.display().to_string(),
				&config.display().to_string(),
			);
			let udhcpc = udhcpc_start_args(iface, &script, &pidfile);

			// Three candidates, not two. Debian packages busybox as one binary with
			// no `udhcpc` symlink beside it, so a machine that has the client at all
			// often cannot be found by that name -- which made the fallback
			// unreachable exactly where it was most likely to be wanted.
			let busybox: Vec<String> = std::iter::once("udhcpc".to_owned())
				.chain(udhcpc.iter().cloned())
				.collect();
			for (program, args) in [("dhcpcd", dhcpcd), ("udhcpc", udhcpc), ("busybox", busybox)] {
				match Command::new(program).args(&args).status() {
					Ok(status) if status.success() => return Ok(()),
					Ok(status) => return Err(format!("{program} on {iface} exited with {status}")),
					// Not installed: try the next one.
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(format!("could not run {program}: {error}")),
				}
			}
			Err(format!(
				"no DHCPv4 client found for {iface}; install dhcpcd, udhcpc or busybox"
			))
		}
		BackendKind::Dhcp6 => Err(format!(
			"a dhcp6 client on {iface} needs to know whether the document asked for \
			 a delegated prefix, which the plain backend path does not carry"
		)),
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

/// The backends an observation found running.
///
/// Carried into the effects so that the recorded restart counter can be cleared
/// for anything that has stayed up -- see `netcfgd-host`'s `absorb` and decision
/// 0079. A free function rather than a closure so that `with_context` stays
/// inside the line limit, which is a thin reason and the honest one.
fn running_backends(
	observed: &netcfgd_model::Observed,
) -> Vec<(netcfgd_model::BackendKind, String)> {
	observed
		.backends
		.iter()
		.filter(|backend| backend.running)
		.map(|backend| (backend.kind, backend.interface.clone()))
		.collect()
}

/// The family flags netcfgd runs dhcpcd with, one address family each.
///
/// Named rather than written out at four call sites, because the family is one
/// decision with two consumers: what dhcpcd does, and which pid file it does it
/// under. See [`dhcpcd_stop_args`].
/// Where dhcpcd keeps its pid files and control sockets.
///
/// **dhcpcd's, not netcfgd's**, and that is the point: it is compiled in as
/// `RUNDIR` and survives a netcfgd stop, which is why the control socket is
/// reachable when everything under `/run/netcfgd` has gone. Overridable for
/// tests, which run in a namespace with a tmpfs over `/run`.
fn dhcpcd_run_dir() -> String {
	std::env::var("NCFG_DHCPCD_RUN_DIR").unwrap_or_else(|_| "/run/dhcpcd".to_owned())
}

const DHCPCD_V4: &str = "-4";
const DHCPCD_V6: &str = "-6";

/// What the `DHCPv6` client's report fragment is called.
///
/// Sorts after the `DHCPv4` client's single file, which is what puts a v4
/// lease's nameservers before a v6 lease's without anything having to say so.
const REPORT_DHCPCD6: &str = "dhcpcd6";

/// Where netcfgd points dhcpcd's `-f`, and what it points at.
///
/// **A mark netcfgd can ask for back.** dhcpcd destroys its own argv and
/// environment with `setproctitle`, so it is the one backend whose ownership
/// cannot be read out of the process image (0143). What it does keep is the
/// `-f` string, which it recites verbatim on its control socket -- so netcfgd
/// gives it a path under netcfgd's own run directory and asks later.
///
/// **A symlink, not a file of netcfgd's own.** `-f` replaces `/etc/dhcpcd.conf`
/// outright and dhcpcd has no `include` directive, so writing netcfgd's own
/// config here would silently drop whatever the operator had -- `duid`,
/// `persistent`, `require dhcp_server_identifier` and the rest of a stock
/// Debian file. Pointing at theirs keeps it: measured, dhcpcd reads the
/// target's options through the symlink and recites the *symlink* path when
/// asked, which is exactly the pair of properties this needs.
///
/// **A dangling symlink is not a failure**, and needs no target created.
/// Measured: dhcpcd prints `read_config: ...: No such file or directory`, takes
/// a normal lease and applies its defaults -- byte for byte what it already
/// does today on a machine with no `/etc/dhcpcd.conf`. The only thing that
/// changes is the path in the message.
fn write_dhcpcd_config(iface: &str, family: &str) -> Result<std::path::PathBuf, String> {
	let dir = run_dir_path().join("dhcpcd");
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	let link = dir.join(format!("{iface}-{family}.conf"));
	// Replaced rather than left: the operator's file may have moved, and a
	// symlink netcfgd wrote is netcfgd's to rewrite.
	let _ = std::fs::remove_file(&link);
	std::os::unix::fs::symlink("/etc/dhcpcd.conf", &link).map_err(|error| {
		format!(
			"cannot point {} at the operator's config: {error}",
			link.display()
		)
	})?;
	Ok(link)
}

/// What netcfgd starts dhcpcd with.
///
/// One family at a time and never both, because netcfgd decides per address
/// source what each family does: a dhcpcd left to its own devices would do
/// `DHCPv4`, `DHCPv6` and SLAAC on one interface, which is three things
/// configuring one link and only one of them written down.
///
/// The metric matters as much as the address on a machine with two uplinks: the
/// lease's default route has to lose to the wired one or win over the wifi, and
/// the client is what installs it. busybox udhcpc has no metric option -- its
/// script does the routing -- so this is the one thing the two `DHCPv4` clients
/// cannot do the same way.
/// **Every dhcpcd netcfgd starts gets `-c`**, which replaces the hook directory
/// outright. There is no argument for the client that does not, which is the
/// point: "leave dhcpcd's own hooks alone" meant a lease rewriting
/// `/etc/resolv.conf` on a machine where netcfgd's DNS mode owns that file
/// (0072), and it was the `DHCPv6` branch for as long as that branch existed.
/// 0072 made it a two-armed type so a third caller could not pick "nothing";
/// 0086 gave the v6 client a script of its own, so there is no second arm left
/// and the parameter is a path rather than a choice. Unrepresentable beats
/// documented.
fn dhcpcd_start_args(
	family: &str,
	iface: &str,
	metric: Option<&str>,
	hook: &str,
	config: &str,
) -> Vec<String> {
	let mut args = vec!["-c".to_owned(), hook.to_owned()];
	// The mark. It has to come before the interface for the same reason `-c`
	// does -- dhcpcd parses options first -- and it is netcfgd's only handle on
	// this client after a restart (0143).
	args.push("-f".to_owned());
	args.push(config.to_owned());
	args.push("-b".to_owned());
	args.push(family.to_owned());
	if let Some(metric) = metric {
		args.push("-m".to_owned());
		args.push(metric.to_owned());
	}
	args.push(iface.to_owned());
	args
}

/// What stops it, which has to name the same family the start did.
///
/// **dhcpcd's pid file carries the family in its name.** A client started with
/// `-4` writes `<rundir>/<iface>-4.pid`, and `dhcpcd -k <iface>` looks for
/// `<iface>.pid`, finds nothing, prints "dhcpcd is not running" and exits 1 --
/// which netcfgd ignored, because that is also what a machine with no dhcpcd at
/// all says. So dropping `config = "dhcp"` from a document reported a stopped
/// backend while a real dhcpcd kept renewing the lease and holding the address.
/// Measured against dhcpcd 10.1.0 in `tests/live/dhcpcd.sh`, which is the first
/// thing here to have run a real one. Decision 0070.
fn dhcpcd_stop_args(family: &str, iface: &str) -> Vec<String> {
	vec![family.to_owned(), "-k".to_owned(), iface.to_owned()]
}

/// Which `DHCPv6` client can serve what the document asked for.
///
/// Pure and separate, because the interesting case cannot be reached from a
/// config file yet -- the model carries `PdRequest` and the DSL has no way to
/// set it (decision 0009's request half is unwritten) -- and a branch no test
/// can make fire is untested code however defensive it looks. This is the test
/// making it fire.
///
/// **Prefix delegation is odhcp6c's.** Measured against a real `kea-dhcp6` over
/// a veth pair, with decision 0050 carrying the whole of it: dhcpcd exposes a
/// delegated prefix to a script only as `$new_delegated_dhcp6_prefix`, which
/// `dhcp6.c` fills with **the addresses dhcpcd itself derived** from the
/// prefix, on an interface it delegated to. netcfgd does the deriving (0009
/// makes `PrefixRef` an indirection the document resolves), so there is no
/// interface for dhcpcd to delegate to and the variable is always empty.
///
/// So a document that asks for a prefix with only dhcpcd installed is refused,
/// rather than served by a client that would take a lease from the ISP and
/// report nothing.
fn dhcp6_client(delegating: bool, has_odhcp6c: bool, iface: &str) -> Result<&'static str, String> {
	match (delegating, has_odhcp6c) {
		(_, true) => Ok("odhcp6c"),
		(false, false) => Ok("dhcpcd"),
		(true, false) => Err(format!(
			"`{iface}` asks for a delegated prefix and only dhcpcd is installed. \
			 dhcpcd never reports the prefix itself to a script -- it reports the \
			 addresses it derived from one, and netcfgd does that deriving -- so \
			 the lease would arrive and nothing would come of it. Install odhcp6c, \
			 or drop the delegation from this interface. See doc/decision/0050"
		)),
	}
}

/// Start a `DHCPv6` client, with the hook that reports a delegated prefix.
///
/// `-P 0` asks odhcp6c for a prefix of whatever length the server offers, and
/// is passed **only when the document asked for one**. It used to be
/// unconditional, so every `config = "dhcp6"` solicited a delegation nobody had
/// written down and an ISP handed one out that nothing would ever use.
fn start_dhcp6(iface: &str, delegating: Option<&netcfgd_model::PdRequest>) -> Result<(), String> {
	let hook = write_pd_hook(iface)?;
	let has_odhcp6c = which("odhcp6c");

	let mut arguments: Vec<String> = Vec::new();
	match dhcp6_client(delegating.is_some(), has_odhcp6c, iface)? {
		"odhcp6c" => {
			arguments.push("-d".to_owned());
			// Where it will write its pid, which is the only handle there is:
			// odhcp6c has no control socket and no `-k`, so a client netcfgd
			// cannot find is a client netcfgd cannot stop. It writes the file
			// only when it daemonises and removes it on the way out, both read
			// out of its `odhcp6c.c`. Decision 0071.
			let pidfile = client_pid_path("odhcp6c", iface)?;
			arguments.push("-p".to_owned());
			arguments.push(pidfile.display().to_string());
			if let Some(request) = delegating {
				arguments.push("-P".to_owned());
				arguments.push(prefix_request(request));
			}
			// The script as an argument, which is the shape this wants: no
			// global hook directory to share with other clients.
			arguments.push("-s".to_owned());
			arguments.push(hook.display().to_string());
			arguments.push(iface.to_owned());
			run_client("odhcp6c", &arguments, iface)
		}
		// A script of netcfgd's, reporting into a fragment of its own.
		//
		// 0072 gave this `-C` instead, silencing dhcpcd's `resolv.conf` and
		// `hostname` hooks so a `DHCPv6` lease could not rewrite the file
		// netcfgd's DNS backend owns. That was right about the contention and
		// it cost the lease its nameservers: nothing carried them, so a v6-only
		// network resolved nothing. The reason it could not have a script was
		// that the report is one file per interface and the `DHCPv4` client is
		// already writing it. It is not, any more (0086).
		//
		// Still no prefix through it: dhcpcd has nothing to report one with,
		// and 0050 refuses the pairing that would want it.
		_ => {
			let hook = write_dhcpcd_script(iface, Some(REPORT_DHCPCD6))?;
			run_client(
				"dhcpcd",
				&dhcpcd_start_args(
					DHCPCD_V6,
					iface,
					None,
					&hook.display().to_string(),
					&write_dhcpcd_config(iface, "6")?.display().to_string(),
				),
				iface,
			)
		}
	}
}

/// Where a client that has no control socket records its pid.
///
/// `/run/netcfgd/<program>/<iface>.pid`, made by netcfgd and named on the
/// client's own command line -- `udhcpc -p` and `odhcp6c -p`. Both are stopped
/// by [`stop_recorded_client`], and the two halves are here together so that a
/// third client cannot invent a third convention.
fn client_pid_path(program: &str, iface: &str) -> Result<std::path::PathBuf, String> {
	let dir = run_dir_path().join(program);
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	Ok(dir.join(format!("{iface}.pid")))
}
/// Whether a backend of this kind can actually be talked to on this interface.
///
/// **The question adoption has to ask and did not.** `backend_pid_file` says
/// whether a process is netcfgd's; this says whether it is any use. A
/// supplicant that holds its control socket and answers nothing is netcfgd's by
/// every marker and worthless to it, and adopting one takes the radio away from
/// a manager that could have driven it.
///
/// Only the supplicant is checked, because it is the only kind where netcfgd
/// has a cheap, non-destructive question to ask and where the failure is known
/// to happen. For everything else this answers `true`: the alternative is
/// inventing a liveness probe per backend on no evidence, and a probe that has
/// never seen its failure is one nobody should trust.
#[must_use]
fn backend_is_reachable(kind: netcfgd_model::BackendKind, iface: &str) -> bool {
	if kind != netcfgd_model::BackendKind::Supplicant {
		return true;
	}
	netcfgd_supplicant::answers(&netcfgd_supplicant::ctrl_dir(), iface)
}

/// Where a daemon netcfgd started records its pid, and what marks it as that
/// daemon rather than something else with the same pid.
///
/// **In the crate that starts them**, because "how do I find this daemon" and
/// "how do I start one" are the same knowledge and the second is here. The
/// observer asks this to find out whether a backend netcfgd's records call
/// running is actually still there ([`netcfgd_sys::process::pid_of`] does the
/// checking); the stop paths ask the same question in their own words.
///
/// `None` means **netcfgd has no handle on this kind**, which is not the same as
/// "it is not running" and must not be read as one:
///
/// - a `DHCPv4` client may be dhcpcd, whose pid file is in dhcpcd's own compiled
///   run directory rather than anywhere netcfgd chose -- and where netcfgd runs
///   udhcpc there *is* a file, so the same kind answers differently by machine;
/// - a supplicant and an access point are reached through control sockets, and a
///   socket that exists does not prove a process does. Asking one costs a round
///   trip in the reconcile loop, which is the thing `acl.sh` measures a deadline
///   for.
///
/// Decision 0078.
#[must_use]
pub fn backend_pid_file(
	kind: netcfgd_model::BackendKind,
	run: &std::path::Path,
	iface: &str,
) -> Option<(std::path::PathBuf, String)> {
	use netcfgd_model::BackendKind;
	match kind {
		BackendKind::OpenVpn => {
			let socket = netcfgd_openvpn::socket_path(run, iface);
			Some((
				netcfgd_openvpn::pid_path(run, iface),
				socket.to_string_lossy().into_owned(),
			))
		}
		BackendKind::RouterAdvert => {
			let config = netcfgd_ra::config_path(run, iface);
			Some((
				netcfgd_ra::pid_path(run, iface),
				config.to_string_lossy().into_owned(),
			))
		}
		// The pid file's own path is the marker, which is the strongest kind:
		// netcfgd chose it, it names the interface, and `-P` puts it in the
		// command line. Decision 0080.
		BackendKind::Supplicant => {
			let path = run.join("supplicant").join(format!("{iface}.pid"));
			let marker = path.to_string_lossy().into_owned();
			Some((path, marker))
		}
		// The same, and it was `None` until decision 0110 -- which made an
		// access point the one backend netcfgd could never notice had died.
		// Section 10 recorded that as deliberate, on the grounds that nothing
		// could test it: `ap.sh`'s hostapd never starts on a dummy and a real
		// radio wants real root. That reason stopped being true when a fake
		// hostapd was given a `--pidfile`, which is what a `-P` produces.
		BackendKind::AccessPoint => {
			let path = netcfgd_hostapd::pid_path(run, iface);
			let marker = path.to_string_lossy().into_owned();
			Some((path, marker))
		}
		// The interface name is the weakest marker netcfgd uses and is what
		// these two clients give it -- neither is invoked with a path netcfgd
		// chose that ends up in its command line.
		BackendKind::Dhcp4 => Some((
			run.join("udhcpc").join(format!("{iface}.pid")),
			iface.to_owned(),
		)),
		BackendKind::Dhcp6 => Some((
			run.join("odhcp6c").join(format!("{iface}.pid")),
			iface.to_owned(),
		)),
		_ => None,
	}
}

/// Stop a client by the pid it was told to record.
///
/// The pid is checked against `/proc/<pid>/cmdline` before anything is
/// signalled, for the reason `pppd_pid` does it: a pid file outlives the process
/// it names and pids are recycled. A stale file is removed and nothing is
/// signalled, which is the whole of the correct action.
///
/// `SIGTERM` rather than a control socket because neither client has one.
/// odhcp6c answers it by sending a RELEASE, calling its script one last time
/// with no prefixes -- which is what empties the report -- and exiting; read out
/// of its `odhcp6c.c` rather than assumed, because "does it release?" decides
/// whether an ISP still believes the prefix is ours.
fn stop_recorded_client(program: &str, iface: &str) -> Result<(), String> {
	let path = run_dir_path().join(program).join(format!("{iface}.pid"));
	// The interface name is the weakest marker netcfgd uses, and it is what
	// there is: `udhcpc -i eth0` and `odhcp6c ... eth0` name nothing else that
	// is netcfgd's. See `netcfgd_sys::process::pid_of`, which says why a path
	// would be better where there is one.
	let Some(pid) = netcfgd_sys::process::pid_of(&path, iface) else {
		let _ = std::fs::remove_file(&path);
		return Ok(());
	};
	netcfgd_sys::process::terminate(pid)
		.map_err(|error| format!("could not stop {program} on {iface} (pid {pid}): {error}"))?;
	let _ = std::fs::remove_file(&path);
	Ok(())
}

/// What the document asks the ISP for, in odhcp6c's spelling.
///
/// `-P <[pfx/]len>`, where `0` means "whatever you are giving out". Both parts
/// are a *request*: a server may hand back a different size or a different
/// block, which is why `PdRequest` carries a hint rather than a value and why
/// what arrives is read back from the report rather than assumed.
///
/// Checked against odhcp6c's own `config.c`, which splits on the `/` and parses
/// the left half with `inet_pton` -- so the hint is an address without a length
/// and the length follows the slash.
fn prefix_request(request: &netcfgd_model::PdRequest) -> String {
	let length = request.length.unwrap_or(0);
	match &request.hint {
		Some(hint) => format!("{hint}/{length}"),
		None => length.to_string(),
	}
}

/// Whether a program is on `PATH`.
fn which(program: &str) -> bool {
	std::env::var_os("PATH")
		.is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

/// Run a client, turning "not installed" into a message that names it.
fn run_client(program: &str, arguments: &[String], iface: &str) -> Result<(), String> {
	match Command::new(program).args(arguments).status() {
		Ok(status) if status.success() => Ok(()),
		Ok(status) => Err(format!("{program} on {iface} exited with {status}")),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(format!(
			"no DHCPv6 client found for {iface}; install odhcp6c or dhcpcd"
		)),
		Err(error) => Err(format!("could not run {program}: {error}")),
	}
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

/// Write the hook script dhcpcd runs, and return its path.
///
/// `source` is `None` for the `DHCPv4` client, which reports through the single
/// file the contract documents and has done since 0066, and `Some(name)` for any
/// other client on the same interface -- which reports through a fragment,
/// because two writers on one file is what silenced the `DHCPv6` client's
/// nameservers for a milestone (0086).
fn write_dhcpcd_script(iface: &str, source: Option<&str>) -> Result<std::path::PathBuf, String> {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let run = run_dir_path();
	let dir = run.join("dhcpcd");
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;

	// Where it reports, and under what name. The single file is the interface's
	// own and the fragment is the client's, which is the whole of 0086 in two
	// lines.
	let (parent, name) = match source {
		Some(source) => (report_fragment_dir(&run, iface), source),
		None => (report_dir(&run), iface),
	};
	std::fs::create_dir_all(&parent).map_err(|error| format!("{}: {error}", parent.display()))?;
	let report = parent.join(name);

	// The script is named for the client too, not the interface alone: a
	// dual-stack interface has two, and one name would mean the second apply
	// overwriting the first client's script while it was running.
	let path = match source {
		Some(source) => dir.join(format!("{iface}-{source}.script")),
		None => dir.join(format!("{iface}.script")),
	};
	let script = dhcpcd_script(iface, &report);
	let mut file = std::fs::File::create(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	file.write_all(script.as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
		.map_err(|error| format!("cannot make {} executable: {error}", path.display()))?;
	Ok(path)
}

/// Write the script udhcpc runs, and say where its pid file goes.
///
/// Both under `/run/netcfgd/udhcpc/`, which is tmpfs and regenerated on every
/// apply -- the script has no state of its own beyond the one address it records,
/// which lives beside it so that a `deconfig` after a netcfgd restart still knows
/// what to take away.
fn write_udhcpc_script(iface: &str) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let run = run_dir_path();
	let dir = run.join("udhcpc");
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	// The report the script writes its nameservers into, which netcfgd reads back
	// through the contract in `doc/interface-report.md` rather than through
	// anything specific to DHCP.
	let reported = run.join("reported");
	std::fs::create_dir_all(&reported)
		.map_err(|error| format!("{}: {error}", reported.display()))?;

	let path = dir.join(format!("{iface}.script"));
	let script = udhcpc_script(
		iface,
		&dir.join(format!("{iface}.address")),
		&reported.join(iface),
	);
	let mut file = std::fs::File::create(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	file.write_all(script.as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
		.map_err(|error| format!("cannot make {} executable: {error}", path.display()))?;

	Ok((path, dir.join(format!("{iface}.pid"))))
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
	let (up, down) = write_ppp_scripts(iface)?;
	let text = ppp_options(iface, config, password, &up, &down);

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

/// Write the two scripts pppd runs when a session comes up and goes down.
///
/// Two, not one, and that is the whole of what reading `ipcp.c` was worth here.
/// pppd hands both calls the same argv and **does not unset `IPLOCAL`, `DNS1`
/// or `DNS2` on the way down** -- it unsets `OLDIPLOCAL` and `CONNECT_TIME` and
/// leaves the rest standing. A single script testing the environment for "is
/// this a teardown" would therefore rewrite the same nameservers as the session
/// went away, and netcfgd would hold an ISP's resolvers for a line that is
/// down. There is no `script_type` here as there is for `OpenVPN`; the only
/// thing that differs between the two calls is which option named the script,
/// so which script it is has to be the answer.
///
/// # Errors
///
/// Returns a message naming the file that could not be written.
fn write_ppp_scripts(iface: &str) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let run_dir = run_dir_path();
	let dir = run_dir.join("ppp");
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	let report = report_path(&run_dir, iface);

	let mut written = Vec::new();
	for going_up in [true, false] {
		let suffix = if going_up { "up" } else { "down" };
		let path = dir.join(format!("{iface}.{suffix}"));
		let mut file = std::fs::File::create(&path)
			.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
		file.write_all(ppp_script(iface, &report, going_up).as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
			.map_err(|error| format!("cannot make {} executable: {error}", path.display()))?;
		written.push(path);
	}
	let down = written.pop().expect("two scripts");
	let up = written.pop().expect("two scripts");
	Ok((up, down))
}

/// One of those scripts: what pppd learned, in the reporting contract's format.
///
/// Pure, so what a session reports can be read without dialling one.
///
/// Generated into `/run` rather than installed, for the reason the `OpenVPN`
/// one is: nothing packages it, and it carries the interface name and the
/// report path. `doc/interface-report.md` is the format.
///
/// **Only nameservers.** A PPP link's address is IPCP's result and stays with
/// `pppd` (decision 0047: `noip` disables IP entirely, so there is no
/// "negotiate and let somebody else apply it"), and its only route is the
/// default one, which `nodefaultroute` stops and the document spells
/// `routes = "default"`. What is left is `DNS1` and `DNS2`, which nothing but
/// `pppd` ever learns -- and which decision 0049 delivers only where the
/// document gave this interface a `dns` block.
#[must_use]
pub fn ppp_script(iface: &str, report: &std::path::Path, going_up: bool) -> String {
	// Bound before the `Display` that borrows it, so the path outlives the
	// formatter rather than being a temporary in the argument list.
	let staging = staged_report(report);
	let staged = staging.display();
	let report = report.display();
	let when = if going_up { "ip-up" } else { "ip-down" };
	// Emptied on the way down rather than removed, which the contract makes
	// mean "nothing, deliberately" -- pppd running this is somebody watching.
	let body = if going_up {
		"\t[ -n \"${DNS1:-}\" ] && printf 'dns=%s\\n' \"$DNS1\"\n\
		 \t[ -n \"${DNS2:-}\" ] && printf 'dns=%s\\n' \"$DNS2\"\n"
	} else {
		"\t# Nothing. The session is gone, and pppd leaves DNS1 and DNS2 set\n\
		 \t# in the environment of this very call -- which is why this is a\n\
		 \t# separate script rather than a branch.\n"
	};
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd for {iface}. Do not edit; it is rewritten on apply,\n\
		 # and pppd is the only thing that runs it.\n\
		 #\n\
		 # pppd's {when}-script. doc/interface-report.md is the format; only the\n\
		 # nameservers are reported, because the address is IPCP's and the routes\n\
		 # are the document's.\n\
		 set -u\n\
		 \n\
		 target='{report}'\n\
		 tmp='{staged}'\n\
		 mkdir -p \"$(dirname \"$target\")\" || exit 1\n\
		 \n\
		 {{\n\
		 \tprintf '# %s, written by netcfgd from pppd {when}\\n' '{iface}'\n\
		 {body}\
		 }} > \"$tmp\" || exit 1\n\
		 mv \"$tmp\" \"$target\"\n"
	)
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
	up: &std::path::Path,
	down: &std::path::Path,
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
		 # netcfgd owns routes. `defaultroute` here would install one nobody\n\
		 # wrote down; a ppp link needs no gateway, so the config says\n\
		 # `routes = \"default\"` and netcfgd installs it.\n\
		 nodefaultroute\n\
		 noipdefault\n\
		 # And the ISP's resolvers, which are the one thing only pppd learns.\n\
		 # `usepeerdns` sets DNS1 and DNS2 for the scripts below; it also writes\n\
		 # /etc/ppp/resolv.conf, which is pppd's own file and not the system\n\
		 # one -- checked in ipcp.c rather than assumed, because this option was\n\
		 # left out for years on the belief that it rewrote /etc/resolv.conf.\n\
		 usepeerdns\n\
		 # Two scripts rather than one told apart by its environment: pppd\n\
		 # leaves DNS1 and DNS2 set for the ip-down call as well, so a single\n\
		 # script would report the same servers as the session went away.\n\
		 ip-up-script {up}\n\
		 ip-down-script {down}\n",
		up = up.display(),
		down = down.display(),
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

/// The hook script dhcpcd runs, replacing its own.
///
/// dhcpcd configures the interface itself, so unlike udhcpc's this script does no
/// addressing at all. What it is for is the half netcfgd cannot get any other way:
/// **the nameservers the lease carried**, written into the interface report.
///
/// **And what it stops is a fight.** dhcpcd's own `20-resolv.conf` hook writes
/// `/etc/resolv.conf`, directly or through `resolvconf` -- so on a machine where
/// netcfgd's DNS mode owns that file, both were writing it and whichever ran last
/// won. Passing `-c` replaces the whole hook directory, which ends the contention
/// and is the reason this is not simply a file dropped in beside dhcpcd's own
/// hooks. Decision 0066.
///
/// Two things dhcpcd's default hooks did that this deliberately does not:
///
/// - **Write `resolv.conf`**, per above.
/// - **Set the hostname.** `30-hostname` sets it from the lease when the current
///   one is blank or `localhost`. netcfgd refuses `hostname = "dhcp"` by name
///   (0061) on the grounds that a machine's identity is not a remote server's to
///   change, and leaving dhcpcd to do it anyway would have been that decision
///   holding in the config and not in fact.
///
/// The variable names are dhcpcd's and were read out of its own
/// `20-resolv.conf`, not remembered: `$new_domain_name_servers`,
/// `$new_domain_name`, and `$reason` -- which is `BOUND`, `RENEW`, `REBIND`,
/// `REBOOT` or `INFORM` for a lease and their `6` suffixed forms for `DHCPv6`,
/// where the servers arrive in `$new_dhcp6_name_servers` instead. 0050 is the scar
/// that makes this worth reading rather than assuming: `$new_dhcp6_prefix` is not
/// a dhcpcd variable at all and netcfgd's hook read it for years.
#[must_use]
pub fn dhcpcd_script(iface: &str, report: &std::path::Path) -> String {
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd for dhcpcd on {iface}. Regenerated on every apply.\n\
		 #\n\
		 # This replaces dhcpcd's own hook directory (-c), so nothing here writes\n\
		 # /etc/resolv.conf -- netcfgd's DNS backend owns that file, and dhcpcd's\n\
		 # 20-resolv.conf hook was writing it too. dhcpcd installs the address and\n\
		 # the routes itself; this only reports what netcfgd cannot otherwise see.\n\
		 set -u\n\
		 report={report}\n\
		 iface=${{interface:-{iface}}}\n\
		 \n\
		 servers=${{new_domain_name_servers:-}}\n\
		 # Option 119 where the server sent one, option 15 otherwise, which is the\n\
		 # precedence dhcpcd's own 20-resolv.conf uses.\n\
		 search=${{new_domain_search:-${{new_domain_name:-}}}}\n\
		 case \"${{reason:-}}\" in\n\
		 *6)\n\
		 \t# The DHCPv6 names for the same two things.\n\
		 \tservers=${{new_dhcp6_name_servers:-}}\n\
		 \tsearch=${{new_dhcp6_domain_search:-}}\n\
		 \t;;\n\
		 esac\n\
		 \n\
		 case \"${{reason:-}}\" in\n\
		 BOUND*|RENEW*|REBIND*|REBOOT*|INFORM*)\n\
		 \t{{\n\
		 \t\tprintf '# %s, from a dhcpcd lease. Written by netcfgd.\\n' \"$iface\"\n\
		 \t\tfor server in $servers; do\n\
		 \t\t\tprintf 'dns=%s\\n' \"$server\"\n\
		 \t\tdone\n\
		 \t\t# A suffix to complete a bare name with, and never a routing domain:\n\
		 \t\t# 0049 refuses one from a server and 0067 says why a suffix is not one.\n\
		 \t\tfor suffix in $search; do\n\
		 \t\t\tprintf 'search=%s\\n' \"$suffix\"\n\
		 \t\tdone\n\
		 \t}} > '{staged}'\n\
		 \tmv '{staged}' \"$report\"\n\
		 \t;;\n\
		 EXPIRE*|FAIL*|NAK*|STOP*|RELEASE*|NOCARRIER*)\n\
		 \trm -f \"$report\"\n\
		 \t;;\n\
		 esac\n\
		 exit 0\n",
		iface = iface,
		staged = staged_report(report).display(),
		report = report.display()
	)
}

/// The script busybox `udhcpc` runs when its lease changes.
///
/// **udhcpc does nothing at all without one.** It has no built-in configuration
/// step: it obtains a lease, runs `$1` of the script with the lease in the
/// environment, and that script is what puts the address on the interface. netcfgd
/// invoked it with no `-s` for as long as the udhcpc fallback has existed, and
/// Debian ships no `/usr/share/udhcpc/default.script` to fall back on -- so on a
/// machine with busybox and no dhcpcd, `config = "dhcp"` got a lease and configured
/// nothing. Decision 0065.
///
/// **What it does is what dhcpcd does, and no more.** The address and the default
/// route, untagged, so the lease belongs to the client exactly as dhcpcd's does
/// (0004) and netcfgd treats both the same way -- including the `lease` hook, which
/// fires off an address netcfgd did not install (0064) and therefore needs no case
/// for either client.
///
/// Three things it deliberately leaves alone:
///
/// - **The MTU**, which the document owns. A lease that lowered it would have
///   netcfgd fighting its own `mtu` field on every renewal.
/// - **`/etc/resolv.conf`**, which netcfgd's DNS backends own. A client writing it
///   behind netcfgd's back is the contention this project exists to avoid; what to
///   do with a lease's nameservers is one decision for both clients and is not
///   this one.
/// - **Every address it did not add itself.** `deconfig` in a stock script flushes
///   the interface, which would delete a static address netcfgd had installed
///   beside the lease. This one records what it added and removes exactly that.
///
/// `$mask` is a prefix length and `$subnet` is the dotted form; both arrive, and
/// this uses the one `ip` takes. Measured against a real busybox 1.37 client and a
/// real busybox `udhcpd`, which is also what `tests/live/dhcp.sh` does.
#[must_use]
pub fn udhcpc_script(iface: &str, state: &std::path::Path, report: &std::path::Path) -> String {
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd for udhcpc on {iface}. Regenerated on every apply.\n\
		 #\n\
		 # udhcpc has no configuration step of its own: without a script it obtains a\n\
		 # lease and does nothing with it. This installs the address and the default\n\
		 # route and touches nothing else -- not the MTU, which the config owns, and\n\
		 # not resolv.conf, which netcfgd's DNS backend owns.\n\
		 set -u\n\
		 state={state}\n\
		 report={report}\n\
		 iface=${{interface:?udhcpc did not say which interface}}\n\
		 \n\
		 # What this script added last time, so `deconfig` removes exactly that and\n\
		 # leaves any address netcfgd itself put on the interface alone.\n\
		 held=\n\
		 [ -r \"$state\" ] && held=$(cat \"$state\")\n\
		 \n\
		 withdraw() {{\n\
		 \t[ -n \"$held\" ] || return 0\n\
		 \tip -4 route del default dev \"$iface\" 2>/dev/null || true\n\
		 \tip -4 addr del \"$held\" dev \"$iface\" 2>/dev/null || true\n\
		 \trm -f \"$state\"\n\
		 \trm -f \"$report\"\n\
		 }}\n\
		 \n\
		 # What the server offered, for netcfgd to read: the nameservers, and the\n\
		 # domain as a comment. doc/interface-report.md is the format and decision\n\
		 # 0049 is why a domain is a comment -- a server may name resolvers, and\n\
		 # which names use them is the operator's to write down.\n\
		 #\n\
		 # Written to a temporary and renamed, because netcfgd may read at any moment\n\
		 # and a half-written file would be read as a shorter list rather than as an\n\
		 # error. Rewritten rather than appended, so a renewal that dropped a server\n\
		 # does not leave it behind.\n\
		 report() {{\n\
		 \t{{\n\
		 \t\tprintf '# %s, from a DHCPv4 lease. Written by netcfgd.\\n' \"$iface\"\n\
		 \t\tfor server in ${{dns:-}}; do\n\
		 \t\t\tprintf 'dns=%s\\n' \"$server\"\n\
		 \t\tdone\n\
		 \t\t# The search list, which is option 119 where the server sent one and\n\
		 \t\t# option 15 otherwise -- the same precedence dhcpcd's own hook uses.\n\
		 \t\t# A suffix, never a routing domain: 0067 says which is which.\n\
		 \t\tfor suffix in ${{search:-${{domain:-}}}}; do\n\
		 \t\t\tprintf 'search=%s\\n' \"$suffix\"\n\
		 \t\tdone\n\
		 \t}} > '{staged}'\n\
		 \tmv '{staged}' \"$report\"\n\
		 }}\n\
		 \n\
		 case \"${{1:-}}\" in\n\
		 bound|renew)\n\
		 \t: \"${{ip:?udhcpc reported no address}}\"\n\
		 \t# A prefix length, which is `$mask`. `$subnet` carries the same thing in\n\
		 \t# dotted form and `ip` will not take it, so an old client that sets only\n\
		 \t# `subnet` is refused by name rather than guessed at.\n\
		 \t: \"${{mask:?this udhcpc does not set \\$mask; netcfgd needs a prefix length}}\"\n\
		 \tnew=\"$ip/$mask\"\n\
		 \t[ \"$new\" = \"$held\" ] || withdraw\n\
		 \tip -4 addr replace \"$new\" dev \"$iface\"\n\
		 \tprintf '%s' \"$new\" > \"$state\"\n\
		 \tif [ -n \"${{router:-}}\" ]; then\n\
		 \t\tfor gateway in $router; do\n\
		 \t\t\tip -4 route replace default via \"$gateway\" dev \"$iface\" && break\n\
		 \t\tdone\n\
		 \tfi\n\
		 \treport\n\
		 \t;;\n\
		 deconfig|nak|leasefail)\n\
		 \t# The lease is gone or was never obtained. `deconfig` also arrives once\n\
		 \t# before the first lease, when there is nothing recorded and this is a\n\
		 \t# no-op.\n\
		 \twithdraw\n\
		 \t;;\n\
		 esac\n\
		 exit 0\n",
		iface = iface,
		state = state.display(),
		staged = staged_report(report).display(),
		report = report.display()
	)
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
	// `PREFIXES` is odhcp6c's, and there is deliberately no second variable
	// beside it. This used to also read `$new_dhcp6_prefix` "for dhcpcd",
	// which is not a variable dhcpcd sets -- the nearest thing it has is
	// `$new_delegated_dhcp6_prefix`, which carries the addresses dhcpcd
	// derived rather than the prefix, and only where dhcpcd did the deriving.
	// `start_dhcp6` refuses that combination outright now, so this script is
	// odhcp6c's and says so (decision 0050).
	//
	// Written to a temporary and renamed, because the observer may read at any
	// moment and a half-written file would be read as a shorter list rather
	// than as an error. Rewritten rather than appended, because a renewal that
	// changed the prefix must not leave both.
	//
	// `${p%%,*}` strips odhcp6c's trailing lifetime fields: it reports
	// `2001:db8::/56,3600,7200`, and the prefix is everything before the first
	// comma.
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd. Reports the prefixes delegated on {iface}.\n\
		 # One per line; an empty file means the lease is gone.\n\
		 #\n\
		 # Run by odhcp6c. dhcpcd cannot report a delegated prefix to a script\n\
		 # at all -- see doc/decision/0050 -- so netcfgd refuses that pairing\n\
		 # rather than leaving a variable here that would never be set.\n\
		 set -u\n\
		 out={}\n\
		 : > '{staged}'\n\
		 for p in ${{PREFIXES:-}}; do\n\
		 \tprintf '%s\\n' \"${{p%%,*}}\" >> '{staged}'\n\
		 done\n\
		 mv '{staged}' \"$out\"\n",
		target.display(),
		staged = staged_report(target).display()
	)
}

/// The delegations a `DHCPv6` client has reported, read from `/run`.
///
/// The same files `netcfgd-host` reads and a separate reader, because that
/// crate is *above* this one in the graph -- it depends on this. The format is
/// one prefix per line and the hook that writes it lives here, which is what
/// keeps the two in step: `pd_hook_script` and this function are the two ends
/// of one file, twenty lines apart.
fn netcfgd_host_prefixes(run_dir: &std::path::Path) -> Vec<(String, Vec<String>)> {
	let Ok(entries) = std::fs::read_dir(run_dir.join("prefixes")) else {
		return Vec::new();
	};
	entries
		.flatten()
		.filter_map(|entry| {
			let interface = entry.file_name().to_str()?.to_owned();
			let body = std::fs::read_to_string(entry.path()).ok()?;
			let prefixes: Vec<String> = body
				.lines()
				.map(str::trim)
				.filter(|line| !line.is_empty() && !line.starts_with('#'))
				.map(ToOwned::to_owned)
				.collect();
			Some((interface, prefixes))
		})
		.collect()
}

/// Where something that is not netcfgd writes what an interface was given.
///
/// The one definition of this path. `netcfgd-host` reads reports and this crate
/// hands the path to whatever writes one, and the two crates cannot be allowed
/// to spell it differently -- so the reader calls this rather than joining
/// `reported` for itself. `doc/interface-report.md` is the contract, and this
/// is the sentence in it that says *where*.
#[must_use]
pub fn report_dir(run_dir: &std::path::Path) -> std::path::PathBuf {
	run_dir.join("reported")
}

/// One interface's report.
#[must_use]
pub fn report_path(run_dir: &std::path::Path, iface: &str) -> std::path::PathBuf {
	report_dir(run_dir).join(iface)
}

/// Where a writer stages a report before renaming it into place.
///
/// The contract tells every writer to write a temporary file *in the same
/// directory* and `rename(2)` it over the target, because a rename is the only
/// way to publish a file whole and it has to be on the same filesystem. It did
/// not say what to call it, and the reader took every entry in that directory
/// as an interface name -- so the half-written file the contract exists to hide
/// was read as a report for an interface named after the temporary file.
///
/// Not a hypothetical about careless third parties: netcfgd's own three
/// generated writers staged at `<report>.tmp`, so netcfgd created the artefact
/// its own reader misread, on every lease renewal. Measured -- a report
/// appeared for an interface called `.eth0.tmp.1234`, carrying a nameserver out
/// of a file that was still being written. Decision 0113.
///
/// **A leading dot**, and the reason is collision rather than convention. Dots
/// are ordinary *inside* an interface name -- a VLAN is `eth0.100` -- so a rule
/// about the `.tmp` suffix would silently drop the report of an interface
/// somebody legitimately named that way. A name that *begins* with a dot is
/// pathological as an interface and universally understood as "not content".
#[must_use]
pub fn staged_report(target: &std::path::Path) -> std::path::PathBuf {
	let name = target.file_name().map_or_else(
		|| "report".to_owned(),
		|name| name.to_string_lossy().into_owned(),
	);
	target
		.parent()
		.unwrap_or_else(|| std::path::Path::new("."))
		.join(format!(".{name}.tmp"))
}

/// Is this directory entry a writer's staging file rather than a report?
///
/// The other half of [`staged_report`], and it is deliberately broader than
/// that function's own output: it skips *anything* beginning with a dot, not
/// just the `.tmp` names netcfgd generates. A third-party writer that stages
/// under some other dotted name is then safe by following the contract's
/// wording rather than by matching netcfgd's spelling exactly, and `.` and
/// `..` are excluded for free.
#[must_use]
pub fn is_staging(name: &str) -> bool {
	name.starts_with('.')
}

/// Where netcfgd's own writers report, one file each.
///
/// `/run/netcfgd/reported.d/<interface>/<source>`, read together with the single
/// file above and after it.
///
/// **The single file is the contract** (`doc/interface-report.md`) and stays
/// exactly what it was: one file, one interface, written by something that is
/// not netcfgd. It has one writer by construction, because the thing writing it
/// is the thing that brought the interface up.
///
/// netcfgd starting *two* clients on one interface is what breaks that, and it
/// is not hypothetical: a dual-stack interface gets a `DHCPv4` client and a
/// `DHCPv6` client, both with nameservers to report, and one file means the
/// second clobbers the first on every renewal. 0072 chose to silence the v6
/// client rather than let that happen, which cost every `DHCPv6` lease its
/// nameservers -- a v6-only network resolving nothing. This is the directory
/// that decision named and did not build.
///
/// A separate tree rather than `reported/<iface>.d`, because an interface may
/// have a dot in its name: `eth0.d` is a legal VLAN interface, and its report
/// would be indistinguishable from a fragment directory belonging to `eth0`.
#[must_use]
pub fn report_fragment_dir(run_dir: &std::path::Path, iface: &str) -> std::path::PathBuf {
	run_dir.join("reported.d").join(iface)
}

/// One fragment, named for what writes it.
#[must_use]
pub fn report_fragment_path(
	run_dir: &std::path::Path,
	iface: &str,
	source: &str,
) -> std::path::PathBuf {
	report_fragment_dir(run_dir, iface).join(source)
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
///
/// Public because the observer needs the same answer: it resolves an access
/// point's passphrase to say whether the running daemon still holds it
/// (decision 0052), and two crates deciding separately where this directory is
/// would work until one of them moved.
#[must_use]
pub fn secrets_dir() -> std::path::PathBuf {
	std::env::var_os("NCFG_CONFIG_DIR").map_or_else(
		|| std::path::PathBuf::from(netcfgd_secret::DEFAULT_SECRETS_DIR),
		|dir| std::path::PathBuf::from(dir).join("secrets"),
	)
}

/// Where a stored certificate is materialised for a supplicant to open.
///
/// Under `/run` and not `/etc`: it is derived from the secret store and
/// disposable, so it belongs where the rest of netcfgd's runtime state does --
/// which also means a reboot clears it, and a certificate that was rotated is
/// not left behind on a machine that stopped using it.
#[must_use]
pub fn certs_dir() -> std::path::PathBuf {
	run_dir_path().join("certs")
}

/// A resolver that can both read secrets and materialise certificates.
///
/// One constructor rather than six call sites remembering to add the second
/// half. A resolver without it refuses a stored certificate rather than
/// guessing a directory, so forgetting would not be silent -- but it would be
/// six different opportunities to forget.
#[must_use]
pub fn resolver() -> netcfgd_secret::Resolver {
	netcfgd_secret::Resolver::with_secrets_dir(secrets_dir()).materialising_into(certs_dir())
}
/// The command line netcfgd starts `wpa_supplicant` with.
///
/// A function rather than a chain of `.arg()` calls so that the flags can be
/// asserted on. The udhcpc path already worked this way and already carries a
/// test pinning the flags it cannot lose; this one did not, and lost one.
fn supplicant_arguments(
	driver: &str,
	interface: &str,
	dir: &std::path::Path,
	pidfile: &std::path::Path,
) -> Vec<String> {
	vec![
		"-B".to_owned(),
		format!("-D{driver}"),
		// **Without this the supplicant logs nowhere at all.** `-B` daemonises,
		// and a daemonised `wpa_supplicant` that was not told to use syslog
		// writes to a stdout nothing is reading. Every association failure,
		// authentication error, disconnect reason and roaming decision is simply
		// gone -- on the one component whose faults an operator most needs to
		// read.
		//
		// Found the expensive way: an hour of a real wifi outage was diagnosed
		// with dhcpcd's log and netcfgd's, because the supplicant had none, and
		// a `journalctl -t wpa_supplicant` over the outage returned "no entries"
		// -- which reads exactly like a supplicant that had nothing to say.
		"-s".to_owned(),
		"-i".to_owned(),
		interface.to_owned(),
		"-C".to_owned(),
		dir.display().to_string(),
		// So that a supplicant which died can be told from one that is running,
		// which the control socket alone cannot say: a socket outlives the
		// process that bound it. The path is its own marker -- it names the
		// interface and netcfgd chose it, so no other command line has it.
		// Decision 0080.
		"-P".to_owned(),
		pidfile.display().to_string(),
	]
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
	// **Ask who claims the interface, not just who left a socket behind.**
	//
	// 0125 says netcfgd will not take a radio from a manager that is still
	// running, and the guard below implements that by looking for a control
	// socket in `/run/wpa_supplicant`. That is an inadequate way to ask.
	// NetworkManager drives wpa_supplicant over **D-Bus**, so on a machine where
	// NM owns the radio there is no per-interface socket file at all -- the
	// directory is empty, the guard concludes the radio is free, and netcfgd
	// starts a second supplicant on an interface NM is actively using.
	//
	// Measured, and it is the whole reported fault: netcfgd logged "Successfully
	// initialized wpa_supplicant", the association collapsed one second later
	// ("carrier lost"), dhcpcd deleted the address and the default route, and
	// the machine lost the network. netcfgd had *already printed* that
	// NetworkManager manages the interface, and started anyway -- the finding
	// was there and nothing acted on it.
	//
	// The socket the guard used to find was netcfgd's own, from an earlier run,
	// which is why this looked guarded while it was not.
	// The index rather than the name, because every daemon whose state
	// `contention` reads keys by index -- an interface can be renamed and the
	// index cannot. Read from sysfs, through the same root the rest of netcfgd
	// uses, so a test can point it somewhere else.
	let claimed: Vec<(String, u32)> =
		std::fs::read_to_string(netcfgd_sys::radio::class_net().join(iface).join("ifindex"))
			.ok()
			.and_then(|text| text.trim().parse::<u32>().ok())
			.map(|index| vec![(iface.to_owned(), index)])
			.unwrap_or_default();
	if let Some(contender) = crate::contention::contenders(&claimed).into_iter().next() {
		return Err(format!(
			"{} is already managing `{iface}`, so netcfgd will not start a second \
			 supplicant on it: two on one radio drop the association, which takes the \
			 address and the default route with it. {}",
			contender.name,
			crate::contention::describe(&contender)
		));
	}

	let dir = netcfgd_supplicant::ctrl_dir();
	std::fs::create_dir_all(&dir)
		.map_err(|error| format!("cannot create {}: {error}", dir.display()))?;

	let pidfile = client_pid_path("supplicant", iface)?;
	if dir.join(iface).exists() {
		// Already running -- started by a previous apply, or surviving a
		// netcfgd restart. Decision 0015 makes that harmless: whoever
		// populates it calls REMOVE_NETWORK all first, so it holds nothing
		// nobody can account for.
		//
		// **Unless it is not running.** A supplicant that died leaves its
		// socket behind, and this used to read that as "already running" and
		// return -- so a plan that had correctly decided to start one did
		// nothing, twice over. The pid file settles it, and a socket with no
		// process behind it is removed rather than bound around: the next
		// supplicant would fail to bind it. Decision 0080.
		if netcfgd_sys::process::pid_of(&pidfile, &pidfile.to_string_lossy()).is_some() {
			return Ok(());
		}
		// **The pid file is an index into a fact, not the fact.** netcfgd
		// starts its supplicant with `-P <pidfile>`, so the process carries
		// that path in its own argv for as long as it lives -- but the file
		// sits in `/run/netcfgd`, which `RuntimeDirectory=` deletes on a real
		// stop while the supplicant netcfgd deliberately did not stop (0134)
		// keeps running. Without this branch netcfgd loses the handle to its
		// own child, falls through to the refusal below, and blames
		// NetworkManager for a process it started itself -- for ever, on every
		// reconcile, because the error is returned before the restart counter
		// is touched so 0079 never gives up either. Decision 0140.
		//
		// Adopting means rewriting the file, because the file is what the
		// observer and `stop_backend` key on. Nothing is restarted: the
		// association the orphan is holding is exactly what 0134 wanted kept.
		// Reachable, as the generic branch above requires for the same reason: a
		// supplicant that holds its socket and answers nothing is netcfgd's by
		// every marker and no use to it, and adopting one takes the radio from a
		// manager that could still drive it.
		if let Some(pid) = netcfgd_sys::process::pid_by_marker(&pidfile.to_string_lossy())
			.filter(|_| netcfgd_supplicant::answers(&dir, iface))
		{
			if let Some(parent) = pidfile.parent() {
				std::fs::create_dir_all(parent)
					.map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
			}
			std::fs::write(&pidfile, format!("{pid}\n"))
				.map_err(|error| format!("cannot record the supplicant on {iface}: {error}"))?;
			eprintln!(
				"netcfgd: adopted the supplicant already running on {iface} (pid {pid}); it is netcfgd's, by the `-P {}` it was started with"
			, pidfile.display());
			return Ok(());
		}
		// **A socket with no netcfgd pid file behind it is not automatically
		// stale.** It is stale only if nothing answers it. If something does,
		// another manager is running a supplicant on this radio --
		// `NetworkManager` is the one that will -- and removing the file would
		// take away the rendezvous point every one of its clients uses while
		// leaving the process running, then bind a second supplicant to the
		// same path. Two supplicants on one radio is worse than either.
		//
		// So netcfgd declines the interface and says so. That keeps 0080
		// intact, because the case 0080 is about is a supplicant that *died*:
		// a dead one does not answer, falls through, and is cleared exactly as
		// before. It also makes displacement the honest thing it claims to be
		// (0125) -- netcfgd takes a radio over when the other manager stops,
		// not by pulling it out from under a running one.
		if netcfgd_supplicant::answers(&dir, iface) {
			return Err(format!(
				"a supplicant netcfgd did not start is answering on `{iface}` -- \
				 its control socket at {} answers, and no process on this machine \
				 carries `-P {}`, which is how netcfgd marks its own. netcfgd will \
				 not take a radio from a manager that is still running: stop the \
				 other one and netcfgd will pick the radio up on the next reconcile. \
				 On Debian that is usually BOTH `systemctl stop NetworkManager` and \
				 `systemctl stop wpa_supplicant` -- the second runs independently of \
				 the first and keeps this socket answering on its own. Or set \
				 `managed = false` on this device to leave it alone for good",
				dir.join(iface).display(),
				pidfile.display()
			));
		}
		let _ = std::fs::remove_file(dir.join(iface));
		let _ = std::fs::remove_file(&pidfile);
	}

	// The same predicate the observer fills `ObservedLink::wireless` from,
	// shared rather than repeated.
	let wireless = netcfgd_sys::radio::is_wireless(&netcfgd_sys::radio::class_net(), iface);
	let driver = if wireless { "nl80211,wext" } else { "wired" };

	let program = supplicant_binary().ok_or_else(|| {
		format!(
			"no wpa_supplicant found for {iface}; install wpa_supplicant, or set \
			 `backend` on the device to say which supplicant to use"
		)
	})?;

	let status = Command::new(&program)
		.args(supplicant_arguments(driver, iface, &dir, &pidfile))
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
	// **The seam a test needs, and it was not reachable.** The fixed
	// directories are searched before `PATH`, so on any machine that has
	// wpa_supplicant installed -- which is every machine this runs on -- a
	// test could not put a stand-in in front of it. That is why the one thing
	// this function does was only ever exercised by hand: `tests/live` can
	// fake a radio and fake a supplicant's control socket, and could not fake
	// the supplicant netcfgd *starts*.
	//
	// Named like `NCFG_WPA_CTRL_DIR` and `NCFG_SYS_CLASS_NET`, and for the
	// same reason: the alternative is a test that reorders production search
	// paths to make itself possible.
	if let Some(named) = std::env::var_os("NCFG_WPA_SUPPLICANT") {
		let path = std::path::PathBuf::from(named);
		return path.is_file().then_some(path);
	}
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
		BackendKind::Dhcp4 => {
			// Whichever client is running. `dhcpcd -4 -k` stops a dhcpcd and does
			// nothing to a udhcpc, which netcfgd used to leave running forever --
			// there was no pid file to find it by. Now there is, and the pid is
			// checked against `/proc/<pid>/cmdline` before anything is signalled,
			// for the reason `pppd_pid` does it: a pid file outlives the process it
			// names and pids are recycled. Decision 0065.
			//
			// The status is deliberately not checked: "dhcpcd is not running" is
			// exit 1, and that is the ordinary answer on every machine where the
			// client is udhcpc. Which is why the missing `-4` was invisible --
			// see `dhcpcd_stop_args` and decision 0070.
			match Command::new("dhcpcd")
				.args(dhcpcd_stop_args(DHCPCD_V4, iface))
				.status()
			{
				Ok(_) => {}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(format!("could not stop dhcpcd on {iface}: {error}")),
			}
			stop_recorded_client("udhcpc", iface)
		}
		BackendKind::Dhcp6 => {
			// The same two shapes as `Dhcp4`, and for the same reason: which
			// client is running is a property of the machine, not of the
			// document, so stopping asks both. dhcpcd names the family here too
			// -- its pid file is `<iface>-6.pid` -- and odhcp6c is stopped by the
			// pid it was told to write, because it has no control socket and no
			// `-k` of its own. Decision 0071.
			match Command::new("dhcpcd")
				.args(dhcpcd_stop_args(DHCPCD_V6, iface))
				.status()
			{
				Ok(_) => {}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(format!("could not stop dhcpcd on {iface}: {error}")),
			}
			stop_recorded_client("odhcp6c", iface)
		}
		BackendKind::Supplicant => {
			// Terminated through its own control socket rather than by signal:
			// the socket is the interface netcfgd already speaks, and killing
			// a process by name would reach supplicants netcfgd did not start.
			//
			// Nothing listening is taken as nothing running, which is safe here
			// because `wpa_supplicant -B` returns only after the control socket
			// exists -- measured with the invocation above against a real one.
			// openvpn's `--daemon` returns at the fork and needed a pid file
			// for exactly that reason (0074).
			//
			// A supplicant that is there and silent is a different state and
			// gets a different answer, for the reasons decision 0109 records
			// against the identical shape in `netcfgd-hostapd`. The two are
			// kept in step deliberately: they are one mechanism, and fixing
			// one of them would leave the other saying a daemon had stopped
			// while it was still holding the radio.
			let dir = netcfgd_supplicant::ctrl_dir();
			let outcome = match netcfgd_supplicant::Client::connect_within(
				&dir,
				iface,
				netcfgd_supplicant::IMPATIENT,
			) {
				Ok(client) => client
					.command("TERMINATE")
					.map_err(|error| format!("could not stop the supplicant on {iface}: {error}")),
				// Nothing listening is the state this was asked to produce.
				Err(error) if netcfgd_supplicant::nothing_is_listening(&error) => Ok(()),
				Err(error) => Err(format!(
					"could not stop the supplicant on {iface}: it is running and \
					 did not answer its control socket: {error}"
				)),
			};
			// The pid file goes either way. wpa_supplicant removes its own on a
			// clean exit; one that was killed leaves it, and a stale file would
			// have the next observation asking about a pid that is somebody
			// else's by then. Decision 0080.
			let _ = std::fs::remove_file(
				run_dir_path()
					.join("supplicant")
					.join(format!("{iface}.pid")),
			);
			outcome
		}
		other => Err(format!(
			"stopping the {other:?} backend is not implemented in this build"
		)),
	}
}

#[cfg(test)]
mod tests {
	use super::dhcp6_client;

	/// The branch no config file can reach yet, made to fire.
	///
	/// The model carries `PdRequest` and the DSL has no way to set it, so
	/// nothing an operator writes produces `delegating = true` today. Decision
	/// 0050 is why the branch exists all the same, and this is what stops it
	/// being untested code: whoever writes the config syntax gets the refusal
	/// already working rather than a comment saying it should.
	#[test]
	fn a_delegation_with_only_dhcpcd_is_refused_by_name() {
		let error = dhcp6_client(true, false, "wan0").expect_err("dhcpcd cannot report a prefix");
		assert!(error.contains("odhcp6c"), "got {error}");
		assert!(error.contains("0050"), "got {error}");
	}

	/// The request, in odhcp6c's spelling. `0` is "whatever you are giving
	/// out", and a hint takes the length after a slash -- which is how
	/// odhcp6c's own `config.c` splits it.
	#[test]
	fn a_prefix_request_is_rendered_the_way_odhcp6c_reads_it() {
		use netcfgd_model::PdRequest;

		assert_eq!(super::prefix_request(&PdRequest::default()), "0");
		assert_eq!(
			super::prefix_request(&PdRequest {
				length: Some(56),
				hint: None
			}),
			"56"
		);
		assert_eq!(
			super::prefix_request(&PdRequest {
				length: Some(56),
				hint: Some("2001:db8::".to_owned())
			}),
			"2001:db8::/56"
		);
		// A hint with no length asks for that block at whatever size, which is
		// the same "0" the length alone means.
		assert_eq!(
			super::prefix_request(&PdRequest {
				length: None,
				hint: Some("2001:db8::".to_owned())
			}),
			"2001:db8::/0"
		);
	}

	/// And every other combination is served rather than refused. An ordinary
	/// `DHCPv6` address is not the prefix's problem, which is the distinction the
	/// refusal above would be worthless without.
	#[test]
	fn everything_else_is_served() {
		assert_eq!(dhcp6_client(false, false, "wan0"), Ok("dhcpcd"));
		assert_eq!(dhcp6_client(false, true, "wan0"), Ok("odhcp6c"));
		assert_eq!(dhcp6_client(true, true, "wan0"), Ok("odhcp6c"));
	}

	/// Starting and stopping name the same family, because dhcpcd's pid file
	/// carries it.
	///
	/// The two argument lists are the second-list problem this repository has
	/// already been bitten by, and the answer is the one it settled on there: the
	/// test iterates one list and asserts the other agrees. A `-4` added to the
	/// start alone is a client netcfgd can no longer stop, which is what shipped
	/// until a real dhcpcd was run (0070) -- and the `DHCPv6` half was worse,
	/// because nothing stopped that client at all (0071). Both families are
	/// walked here, so neither can be the one nobody checked.
	/// **What the generic adoption in `start_backend` is allowed to scan for.**
	///
	/// That branch takes `backend_pid_file`'s marker and, when it is an absolute
	/// path, looks for a process carrying it in `argv`. The safety of that rests
	/// entirely on which markers are paths: `eth0` is a short string an
	/// unrelated command line could contain, and scanning `/proc` for it would
	/// reach an operator's process.
	///
	/// So the shape is asserted rather than described. A backend that later
	/// gains a weak marker is excluded by this test failing, not by somebody
	/// remembering the rule.
	#[test]
	fn only_a_path_marker_is_scannable() {
		use netcfgd_model::BackendKind;
		let run = std::path::Path::new("/run/netcfgd");
		for kind in [
			BackendKind::Supplicant,
			BackendKind::AccessPoint,
			BackendKind::OpenVpn,
			BackendKind::RouterAdvert,
		] {
			let (_, marker) = super::backend_pid_file(kind, run, "eth0")
				.unwrap_or_else(|| panic!("{kind:?} has no pid file"));
			assert!(
				marker.starts_with('/'),
				"{kind:?} is adopted by a /proc scan, so its marker must be a path netcfgd composed, not {marker:?}"
			);
		}
		// The two clients netcfgd cannot identify this way, and must not try to:
		// each has its own recovery instead -- udhcpc by its `-p` path, dhcpcd by
		// its control socket (0143).
		for kind in [BackendKind::Dhcp4, BackendKind::Dhcp6] {
			let (_, marker) = super::backend_pid_file(kind, run, "eth0")
				.unwrap_or_else(|| panic!("{kind:?} has no pid file"));
			assert!(
				!marker.starts_with('/'),
				"{kind:?}'s marker became a path, which would put it in the generic /proc scan -- check that is what was meant"
			);
		}
	}

	#[test]
	fn a_client_is_stopped_the_way_it_was_started() {
		for family in [super::DHCPCD_V4, super::DHCPCD_V6] {
			let start = super::dhcpcd_start_args(
				family,
				"eth0",
				Some("512"),
				"/run/netcfgd/dhcpcd/eth0.script",
				"/run/netcfgd/dhcpcd/eth0.conf",
			);
			let stop = super::dhcpcd_stop_args(family, "eth0");
			let named: Vec<&String> = start
				.iter()
				.filter(|argument| matches!(argument.as_str(), "-4" | "-6"))
				.collect();
			assert_eq!(
				named.len(),
				1,
				"the start names no family, or more than one: {start:?}"
			);
			assert_eq!(named[0], family, "the start names the wrong family");
			assert!(
				stop.contains(named[0]),
				"the stop does not name {family}, so it looks for the wrong pid file: {stop:?}"
			);
			// And both name the interface, which is the other half of the pid file.
			assert!(start.contains(&"eth0".to_owned()));
			assert!(stop.contains(&"eth0".to_owned()));
		}
		// The metric reaches the client rather than being carried and dropped,
		// and a document that named none passes no flag at all.
		let hook = "/run/netcfgd/dhcpcd/eth0.script";
		let ranked = super::dhcpcd_start_args(
			super::DHCPCD_V4,
			"eth0",
			Some("512"),
			hook,
			"/run/netcfgd/dhcpcd/eth0.conf",
		);
		assert!(ranked.windows(2).any(|pair| pair == ["-m", "512"]));
		assert!(super::dhcpcd_start_args(
			super::DHCPCD_V4,
			"eth0",
			None,
			hook,
			"/run/netcfgd/dhcpcd/eth0-4.conf"
		)
		.iter()
		.all(|argument| argument != "-m"));
	}

	/// Every dhcpcd netcfgd starts has its hooks replaced, both families.
	///
	/// "Left alone" is what the `DHCPv6` client had, and it meant a lease
	/// rewriting `/etc/resolv.conf` on a machine where netcfgd's DNS mode owns
	/// that file (0072). That was fixed by silencing two hooks by name; 0086
	/// gave the v6 client a script of its own instead, which replaces the whole
	/// directory and is strictly the stronger thing -- so this walks both
	/// families and asserts each gets `-c`, where it used to walk two arms of a
	/// type.
	#[test]
	fn dhcpcds_own_hooks_are_never_left_alone() {
		for family in [super::DHCPCD_V4, super::DHCPCD_V6] {
			let hook = format!("/run/netcfgd/dhcpcd/eth0-{family}.script");
			let args = super::dhcpcd_start_args(
				family,
				"eth0",
				None,
				&hook,
				"/run/netcfgd/dhcpcd/eth0.conf",
			);

			assert!(
				args.windows(2).any(|pair| pair == ["-c", hook.as_str()]),
				"{family} does not replace dhcpcd's hooks: {args:?}"
			);
			// Replacing the directory covers every hook, so naming one as well
			// would say something the flag does not mean.
			assert!(
				!args.iter().any(|argument| argument == "-C"),
				"{family} both replaces and silences: {args:?}"
			);
		}
	}
}

#[cfg(test)]
mod supplicant_argument_tests {
	use super::supplicant_arguments;
	use std::path::Path;

	/// The flags the supplicant cannot lose, pinned the way udhcpc's are.
	///
	/// This test exists because one of them was already missing. `-s` was never
	/// passed, so on every netcfgd machine `wpa_supplicant` daemonised and
	/// logged nowhere -- and the absence is invisible in exactly the way that
	/// matters: a journal query for the supplicant returns "no entries", which
	/// is what a healthy quiet supplicant also returns.
	#[test]
	fn the_load_bearing_flags_are_all_there() {
		let args = supplicant_arguments(
			"nl80211,wext",
			"wlan0",
			Path::new("/run/wpa_supplicant"),
			Path::new("/run/netcfgd/supplicant/wlan0.pid"),
		);

		// Without `-B` it never returns, without `-s` it logs nowhere, without
		// `-C` there is no control socket to configure it through, and without
		// `-P` netcfgd cannot tell its own supplicant from somebody else's
		// (0080).
		for flag in ["-B", "-s", "-C", "-P"] {
			assert!(
				args.iter().any(|argument| argument == flag),
				"wpa_supplicant lost {flag}: {args:?}"
			);
		}
		assert!(
			args.iter().any(|argument| argument == "-Dnl80211,wext"),
			"the driver is not named: {args:?}"
		);
		// The interface follows `-i` rather than merely appearing somewhere:
		// a list containing the right words in the wrong order is a different
		// command line.
		assert!(
			args.windows(2).any(|pair| pair == ["-i", "wlan0"]),
			"the interface does not follow -i: {args:?}"
		);
	}
}

#[cfg(test)]
mod udhcpc_tests {
	/// udhcpc is asked for the search list, which it does not request itself.
	///
	/// The client's default request list is 1, 3, 6, 12, 15, 28, 42 -- no 119 --
	/// so a server that honours it sends no search suffixes at all. That was
	/// invisible for as long as the only server this suite drove was `busybox
	/// udhcpd`, which pushes every configured option whether it was asked for
	/// or not. Against dnsmasq the same test lost four checks, and the wire
	/// showed why: `requested options: 1:netmask, 3:router, 6:dns-server,
	/// 12:hostname, 15:domain-name, 28:broadcast, 42:ntp-server`.
	#[test]
	fn the_client_asks_for_the_search_list() {
		let args = super::udhcpc_start_args(
			"eth0",
			std::path::Path::new("/run/netcfgd/udhcpc/eth0.script"),
			std::path::Path::new("/run/netcfgd/udhcpc/eth0.pid"),
		);
		assert!(
			args.windows(2).any(|pair| pair == ["-O", "search"]),
			"udhcpc is not asked for option 119: {args:?}"
		);
		// And the three that were already load-bearing, so a rewrite of this
		// list cannot quietly drop one: without `-s` the client obtains a lease
		// and configures nothing, without `-p` it cannot be stopped, and
		// without `-R` it leaves its address behind when it is.
		for flag in ["-s", "-p", "-R"] {
			assert!(
				args.iter().any(|argument| argument == flag),
				"udhcpc lost {flag}: {args:?}"
			);
		}
	}

	/// The generated script is valid shell, and says what it will not touch.
	///
	/// `sh -n` rather than an eyeball: this is a shell script written from Rust
	/// through two levels of escaping, and the failure mode is a syntax error that
	/// only appears when a lease arrives on somebody's machine.
	#[test]
	fn the_script_parses_and_leaves_what_it_should_alone() {
		let script = super::udhcpc_script(
			"cli",
			std::path::Path::new("/run/x/cli.address"),
			std::path::Path::new("/run/x/reported/cli"),
		);
		let dir = netcfgd_testdir::TestDir::new("udhcpc");
		let path = dir.join("script");
		std::fs::write(&path, &script).expect("written");
		let checked = std::process::Command::new("sh")
			.arg("-n")
			.arg(&path)
			.output()
			.expect("sh runs");
		assert!(
			checked.status.success(),
			"the generated script is not valid shell: {}",
			String::from_utf8_lossy(&checked.stderr)
		);
		// The three things it must not do. Asserted on the *code* rather than on the
		// text, because the script's own comments say it leaves resolv.conf and the
		// MTU alone -- a check that could not tell a comment from a command would
		// pass for the wrong reason, or fail for one.
		let code: String = script
			.lines()
			.filter(|line| !line.trim_start().starts_with('#'))
			.collect::<Vec<&str>>()
			.join("\n");
		assert!(
			!code.contains("resolv.conf"),
			"it writes resolv.conf: {code}"
		);
		assert!(!code.contains("mtu"), "it sets an MTU: {code}");
		assert!(!code.contains("flush"), "it flushes addresses: {code}");
		// And the two it must: the address, and a default route via the lease's
		// router. Both by the variable names busybox actually sets, measured against
		// a real client rather than taken from a manual page.
		assert!(code.contains("addr replace \"$new\""));
		assert!(code.contains("route replace default via"));
		assert!(
			code.contains("${mask:?"),
			"it does not insist on a prefix length"
		);
		// And the report, which is how a lease's nameservers reach netcfgd at all
		// (0066). The domain is a comment rather than a key, because 0049 says a
		// server may name resolvers and not where queries go.
		assert!(code.contains("dns=%s"), "it reports no nameservers");
		assert!(
			!code.contains("domain=%s"),
			"it reports a domain as a key: {code}"
		);
	}

	/// dhcpcd's script, on the same terms and with one more thing to prove: it
	/// configures nothing, because dhcpcd does that itself.
	#[test]
	fn the_dhcpcd_script_reports_and_configures_nothing() {
		let script = super::dhcpcd_script("eth0", std::path::Path::new("/run/x/reported/eth0"));
		let dir = netcfgd_testdir::TestDir::new("dhcpcd");
		let path = dir.join("script");
		std::fs::write(&path, &script).expect("written");
		let checked = std::process::Command::new("sh")
			.arg("-n")
			.arg(&path)
			.output()
			.expect("sh runs");
		assert!(
			checked.status.success(),
			"the generated script is not valid shell: {}",
			String::from_utf8_lossy(&checked.stderr)
		);
		let code: String = script
			.lines()
			.filter(|line| !line.trim_start().starts_with('#'))
			.collect::<Vec<&str>>()
			.join("\n");
		assert!(code.contains("dns=%s"), "it reports no nameservers");
		assert!(
			!code.contains("resolv.conf"),
			"it writes resolv.conf: {code}"
		);
		// dhcpcd installs the address and the routes; a script that also did would
		// be two things configuring one interface.
		assert!(
			!code.contains("ip -4 addr"),
			"it configures an address: {code}"
		);
		assert!(
			!code.contains("ip -4 route"),
			"it configures a route: {code}"
		);
		assert!(!code.contains("hostname"), "it sets the hostname: {code}");
		// The variable names are dhcpcd's own, read out of its `20-resolv.conf`.
		assert!(code.contains("new_domain_name_servers"));
		assert!(code.contains("new_dhcp6_name_servers"));
	}
}
