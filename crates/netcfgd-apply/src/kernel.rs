//! The executor that talks to the kernel.

use crate::Executor;
use netcfgd_model::route::NETCFGD_PROTO;
use netcfgd_model::{InterfaceKind, Origin};
use netcfgd_netlink::ops::RT_TABLE_MAIN;
use netcfgd_netlink::{parse_mac, Netlink, NewLink, RouteSpec};
use netcfgd_plan::{net, Op};
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
}

/// Executes actions against rtnetlink and the backend helpers.
pub struct KernelExecutor {
	socket: Netlink,
	indices: Vec<(String, u32)>,
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
		let snapshot = netcfgd_netlink::snapshot_with(&mut socket)?;
		Ok(Self {
			socket,
			indices: snapshot
				.links
				.iter()
				.map(|link| (link.name.clone(), link.index))
				.collect(),
			effects: Effects::default(),
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
		let snapshot = netcfgd_netlink::snapshot_with(&mut self.socket)
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
				start_backend(*kind, iface)?;
				self.effects.started_backends.push((*kind, iface.clone()));
				Ok(())
			}
			Op::BackendStop { kind, iface } => {
				stop_backend(*kind, iface)?;
				self.effects.stopped_backends.push((*kind, iface.clone()));
				Ok(())
			}
			Op::DnsApply { scope, policy } => {
				// The DNS backends land with the scope-capable modes in M4.
				// Recording the delivery without performing it would make the
				// next plan believe DNS is configured when it is not, so this
				// refuses instead.
				Err(format!(
					"dns delivery for scope {scope} via mode {} is not implemented in this build; \
					 it lands with M4",
					policy.mode.name()
				))
			}
			Op::HookRun { iface, phase, path } => {
				let status = Command::new(path)
					.env("NCFG_IFACE", iface)
					.env("NCFG_PHASE", format!("{phase:?}"))
					.status()
					.map_err(|error| format!("could not run {path}: {error}"))?;
				if status.success() {
					Ok(())
				} else {
					Err(format!("{path} exited with {status}"))
				}
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
		}),
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
	}
}

/// Start a helper.
///
/// Decision 0004 delegates DHCP rather than implementing it, so this looks for
/// a client and reports honestly when there is none. The lease-to-model
/// handoff -- which turns a fresh lease into observed state -- lands with
/// `netcfgd-dhcp` in M2; until then the client configures the interface and
/// netcfgd sees the result as somebody else's, which is the safe direction.
fn start_backend(kind: netcfgd_model::BackendKind, iface: &str) -> Result<(), String> {
	use netcfgd_model::BackendKind;
	match kind {
		BackendKind::Dhcp4 => {
			for (program, args) in [
				("dhcpcd", vec!["-b", "-4", iface]),
				("udhcpc", vec!["-b", "-i", iface]),
			] {
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
		other => Err(format!(
			"the {other:?} backend is not implemented in this build"
		)),
	}
}

fn stop_backend(kind: netcfgd_model::BackendKind, iface: &str) -> Result<(), String> {
	use netcfgd_model::BackendKind;
	match kind {
		BackendKind::Dhcp4 => match Command::new("dhcpcd").args(["-k", iface]).status() {
			Ok(_) => Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(error) => Err(format!("could not stop dhcpcd on {iface}: {error}")),
		},
		other => Err(format!(
			"stopping the {other:?} backend is not implemented in this build"
		)),
	}
}
