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
		let snapshot = netcfgd_netlink::snapshot_with(&mut socket)?;
		Ok(Self {
			socket,
			indices: snapshot
				.links
				.iter()
				.map(|link| (link.name.clone(), link.index))
				.collect(),
			dns_scopes: Vec::new(),
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
		self
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
