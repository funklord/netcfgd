#![forbid(unsafe_code)]

//! `diff(desired, observed)` -> an ordered plan of typed, idempotent actions.
//!
//! The third pure crate, and the one the product is named for: not being a
//! black box is what netcfgd sells, and this is where "what will change?"
//! becomes an answerable question.
//!
//! Two properties are load-bearing and are tested rather than asserted:
//!
//! - **An already-correct system produces an empty plan.** Zero actions, zero
//!   hooks, nothing touched. This is the normal case, not the edge case.
//! - **Applying a plan twice produces an empty second plan.** Section 6 makes
//!   this a CI gate, and the fixture harness in `tests/` runs every fixture
//!   through it.
//!
//! The safety property that outranks both: **nothing foreign is ever removed.**
//! Only objects carrying netcfgd's own tag may be deleted to satisfy the
//! desired state, and the single place that is decided is
//! [`netcfgd_model::Ownership::may_remove`].

pub mod action;
pub mod net;

pub use action::{Action, Op, Reason};

use netcfgd_model::{
	AddressSource, BackendKind, DnsPolicy, Document, HookPhase, Interface, InterfaceKind, Observed,
	Origin, Route,
};
use serde::{Deserialize, Serialize};

/// How to build the plan.
#[derive(Debug, Clone, Default)]
pub struct PlanOptions {
	/// Seconds before an unconfirmed change reverts. `None` disables
	/// commit-confirm for this run.
	pub confirm_window: Option<u32>,
	/// Hash of the document to revert to, precomputed at plan time.
	pub revert_to: Option<String>,
	/// Interfaces the operator has explicitly consented to disrupt.
	///
	/// Named rather than a blanket `--force`, because a blanket override is
	/// the flag people alias and stop reading, and it consents to disrupting
	/// the interfaces they had not thought about as well.
	pub allow_disruption: Vec<String>,
}

/// Something the operator should know that is not an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Warning {
	/// What to say.
	pub message: String,
	/// Which interface it concerns, where it concerns one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub interface: Option<String>,
}

/// An action netcfgd declined to plan, and why.
///
/// First-class rather than a warning string, because "what did it decline?"
/// is a question a script has to answer as well as a human, and because
/// burying it among warnings is how it gets ignored
/// (`docs/decisions/0010`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
	/// Which interface.
	pub interface: String,
	/// The op that was not planned.
	pub op: String,
	/// What the guard says depends on this interface.
	pub guard: String,
	/// Why the action existed, so the reader knows what is not happening.
	pub reason: Reason,
	/// The exact invocation that consents to it.
	pub override_with: String,
}

/// An ordered DAG of actions, plus what could not be planned.
///
/// The action list is already in a valid execution order, so an executor that
/// ignores `depends_on` entirely still behaves correctly. The edges are there
/// so an executor that wants to parallelise, or a reader who wants to know
/// *why* this comes before that, has the information.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
	/// The actions, in execution order.
	pub actions: Vec<Action>,
	/// Things worth saying that are not actions.
	#[serde(default)]
	pub warnings: Vec<Warning>,
	/// Actions a guard prevented, and how to consent to them.
	#[serde(default)]
	pub refusals: Vec<Refusal>,
}

impl Plan {
	/// Whether there is nothing to do. The normal case on a correct system.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.actions.is_empty()
	}

	/// Actions with no inverse, which commit-confirm cannot undo.
	pub fn irreversible(&self) -> impl Iterator<Item = &Action> {
		self.actions.iter().filter(|a| a.inverse.is_none())
	}

	/// Whether a guard stopped anything being planned.
	#[must_use]
	pub fn was_refused(&self) -> bool {
		!self.refusals.is_empty()
	}
}

/// Compute what would have to change for `observed` to satisfy `desired`.
#[must_use]
pub fn plan(desired: &Document, observed: &Observed, options: &PlanOptions) -> Plan {
	let mut builder = Builder {
		consented: options.allow_disruption.clone(),
		..Builder::default()
	};

	// Collected before anything is planned, because a guard on one interface
	// has to be known when an action against it is considered, whatever order
	// the interfaces sort in.
	for interface in &desired.interfaces {
		if let Some(guard) = &interface.guard {
			builder
				.guards
				.push((interface.name.clone(), guard.reason.clone()));
		}
	}

	// Rule 8: the confirm window is armed first, and the revert is computed
	// now rather than after a failure, when the network may already be
	// unreachable.
	if let Some(window) = options.confirm_window {
		let inverse = options.revert_to.as_ref().map(|hash| Op::CommitRevert {
			to_document_hash: hash.clone(),
		});
		builder.push_root(
			Op::CommitArm {
				window_seconds: window,
			},
			Reason {
				interface: None,
				field: "globals.confirm_default".to_owned(),
				desired: format!("{window}s"),
				observed: "<absent>".to_owned(),
			},
			inverse,
		);
	}

	// Three passes over the interfaces rather than one. Rule 1 wants every
	// link created before anything references it, and rule 2 wants every
	// enslavement done before the master is addressed or brought up -- and a
	// master may sort before its own members. Passing over the list three
	// times is simpler and more obviously correct than back-patching edges.
	for interface in &desired.interfaces {
		builder.plan_link_creation(interface, observed);
	}
	for interface in &desired.interfaces {
		builder.plan_link_attributes(interface, observed);
	}
	for interface in &desired.interfaces {
		builder.plan_interface_contents(interface, observed);
	}

	builder.plan_dns(desired, observed);

	// Teardown comes last, so a change to an address is make-before-break: the
	// new address is in place before the old one goes. On a machine being
	// reconfigured over the network that ordering is the difference between a
	// brief overlap and a lockout.
	builder.plan_teardown(desired, observed);

	builder.finish()
}

#[derive(Default)]
struct Builder {
	actions: Vec<Action>,
	warnings: Vec<Warning>,
	refusals: Vec<Refusal>,
	/// `(interface, reason)` for every guarded interface.
	guards: Vec<(String, String)>,
	/// Interfaces the operator consented to disrupt.
	consented: Vec<String>,
	/// Ids every later action on an interface must wait for: its creation.
	gates: Vec<(String, u32)>,
	/// `link.set_master` ids, keyed by the master they enslave to.
	enslavements: Vec<(String, u32)>,
	/// `link.up` id per interface.
	link_up: Vec<(String, u32)>,
	/// `addr.add` ids per interface, with the address each one adds.
	added: Vec<(String, String, u32)>,
	/// `hook.run(pre_up)` ids per interface.
	pre_up: Vec<(String, u32)>,
}

impl Builder {
	/// Whether a guard forbids this action, recording the refusal if it does.
	///
	/// Every action passes through here, so there is one place that decides
	/// and no planner path can route around it -- the same reasoning that puts
	/// `Ownership::may_remove` in one function.
	fn refused(&mut self, op: &Op, reason: &Reason) -> bool {
		if !op.is_disruptive() {
			return false;
		}
		let Some(interface) = op.interface() else {
			return false;
		};
		if self.consented.iter().any(|name| name == interface) {
			return false;
		}
		let Some((_, guard)) = self
			.guards
			.iter()
			.find(|(name, _)| name == interface)
			.cloned()
		else {
			return false;
		};
		self.refusals.push(Refusal {
			interface: interface.to_owned(),
			op: op.name().to_owned(),
			guard,
			reason: reason.clone(),
			override_with: format!("ncfg apply --allow-disruption {interface}"),
		});
		true
	}

	fn push(&mut self, op: Op, reason: Reason, depends_on: Vec<u32>, inverse: Option<Op>) -> u32 {
		if self.refused(&op, &reason) {
			// Nothing is emitted, so nothing downstream can depend on it. The
			// refusal carries what would have happened.
			return u32::MAX;
		}
		let id = u32::try_from(self.actions.len()).unwrap_or(u32::MAX);
		if inverse.is_none() {
			self.warnings.push(Warning {
				message: format!(
					"{} cannot be undone; commit-confirm will not revert it",
					op.name()
				),
				interface: op.interface().map(ToOwned::to_owned),
			});
		}
		self.actions.push(Action {
			id,
			op,
			reason,
			depends_on,
			inverse,
		});
		id
	}

	fn push_root(&mut self, op: Op, reason: Reason, inverse: Option<Op>) -> u32 {
		self.push(op, reason, Vec::new(), inverse)
	}

	fn warn(&mut self, interface: &str, message: impl Into<String>) {
		self.warnings.push(Warning {
			message: message.into(),
			interface: Some(interface.to_owned()),
		});
	}

	fn gate(&self, name: &str) -> Vec<u32> {
		self.gates
			.iter()
			.filter(|(iface, _)| iface == name)
			.map(|(_, id)| *id)
			.collect()
	}

	fn link_up_of(&self, name: &str) -> Option<u32> {
		self.link_up
			.iter()
			.find(|(iface, _)| iface == name)
			.map(|(_, id)| *id)
	}

	/// Rule 1: create a link before anything references it.
	fn plan_link_creation(&mut self, interface: &Interface, observed: &Observed) {
		if observed.link(&interface.name).is_some() {
			return;
		}
		if matches!(interface.kind, InterfaceKind::Physical) {
			// A physical device that is not present is not something a plan
			// can fix. Say so rather than emitting actions that must fail.
			self.warn(
				&interface.name,
				format!(
					"{} is configured but no such device is present; nothing planned for it",
					interface.name
				),
			);
			return;
		}
		let id = self.push_root(
			Op::LinkCreate {
				name: interface.name.clone(),
				kind: Box::new(interface.kind.clone()),
			},
			Reason::absent(&interface.name, "kind", kind_name(&interface.kind)),
			Some(Op::LinkDelete {
				name: interface.name.clone(),
			}),
		);
		self.gates.push((interface.name.clone(), id));
	}

	/// MTU, MAC and enslavement, all of which must precede rule 2's consumers.
	fn plan_link_attributes(&mut self, interface: &Interface, observed: &Observed) {
		let name = &interface.name;
		let link = observed.link(name);
		if link.is_none() && matches!(interface.kind, InterfaceKind::Physical) {
			return;
		}
		let gate = self.gate(name);

		if let Some(mtu) = interface.mtu {
			if link.is_none_or(|link| link.mtu != mtu) {
				let previous = link.map(|link| link.mtu);
				self.push(
					Op::LinkSetMtu {
						name: name.clone(),
						mtu,
					},
					Reason::differs(
						name,
						"mtu",
						mtu.to_string(),
						previous.map_or_else(|| "<absent>".to_owned(), |m| m.to_string()),
					),
					gate.clone(),
					previous.map(|mtu| Op::LinkSetMtu {
						name: name.clone(),
						mtu,
					}),
				);
			}
		}

		if let Some(mac) = &interface.mac {
			if link.is_none_or(|link| link.mac.as_deref() != Some(mac.as_str())) {
				let previous = link.and_then(|link| link.mac.clone());
				self.push(
					Op::LinkSetMac {
						name: name.clone(),
						mac: mac.clone(),
					},
					Reason::differs(
						name,
						"mac",
						mac.clone(),
						previous.clone().unwrap_or_else(|| "<absent>".to_owned()),
					),
					gate.clone(),
					previous.map(|mac| Op::LinkSetMac {
						name: name.clone(),
						mac,
					}),
				);
			}
		}

		match (
			&interface.master,
			link.and_then(|link| link.master.as_ref()),
		) {
			(Some(desired), current) if current != Some(desired) => {
				let id = self.push(
					Op::LinkSetMaster {
						name: name.clone(),
						master: desired.clone(),
					},
					Reason::differs(
						name,
						"master",
						desired.clone(),
						current.cloned().unwrap_or_else(|| "<absent>".to_owned()),
					),
					gate,
					Some(Op::LinkUnsetMaster { name: name.clone() }),
				);
				// Rule 2: the master waits for this.
				self.enslavements.push((desired.clone(), id));
			}
			(None, Some(current)) => {
				self.push(
					Op::LinkUnsetMaster { name: name.clone() },
					Reason::unwanted(name, "master", current.clone()),
					gate,
					Some(Op::LinkSetMaster {
						name: name.clone(),
						master: current.clone(),
					}),
				);
			}
			_ => {}
		}
	}

	/// Hooks, link state, addressing and routes.
	fn plan_interface_contents(&mut self, interface: &Interface, observed: &Observed) {
		let name = &interface.name;
		let link = observed.link(name);
		if link.is_none() && matches!(interface.kind, InterfaceKind::Physical) {
			return;
		}

		let mut base = self.gate(name);
		// Rule 2: addressing the master, and bringing it up, waits for every
		// member's enslavement.
		let enslavements: Vec<u32> = self
			.enslavements
			.iter()
			.filter(|(master, _)| master == name)
			.map(|(_, id)| *id)
			.collect();
		base.extend(enslavements);

		// Rule 6: pre_up runs before link.up. Deliberately, and not the same
		// as netifrc, which runs `up; preup; up` so that a preup hook can read
		// carrier -- the kernel returns EINVAL for carrier on a down
		// interface. Decision 0011 keeps this ordering and documents the
		// breakage; do not "fix" it to match netifrc without reading that.
		for hook in interface
			.hooks
			.iter()
			.filter(|h| h.phase == HookPhase::PreUp)
		{
			let id = self.push(
				Op::HookRun {
					iface: name.clone(),
					phase: hook.phase,
					path: hook.path.clone(),
				},
				Reason::absent(name, "hooks[pre_up]", hook.path.clone()),
				base.clone(),
				// A hook is arbitrary shell. Nothing can be said about how to
				// undo it, and claiming otherwise would make commit-confirm
				// lie about what it restores.
				None,
			);
			self.pre_up.push((name.clone(), id));
		}

		let mut up_deps = base.clone();
		up_deps.extend(
			self.pre_up
				.iter()
				.filter(|(iface, _)| iface == name)
				.map(|(_, id)| *id),
		);

		if interface.enabled && link.is_none_or(|link| !link.up) {
			let id = self.push(
				Op::LinkUp { name: name.clone() },
				Reason::differs(name, "enabled", "true", "false"),
				up_deps.clone(),
				Some(Op::LinkDown { name: name.clone() }),
			);
			self.link_up.push((name.clone(), id));
		} else if !interface.enabled && link.is_some_and(|link| link.up) {
			self.push(
				Op::LinkDown { name: name.clone() },
				Reason::differs(name, "enabled", "false", "true"),
				base.clone(),
				Some(Op::LinkUp { name: name.clone() }),
			);
		}

		let mut addressing_ids = Vec::new();
		for (index, source) in interface.addressing.iter().enumerate() {
			addressing_ids.extend(self.plan_source(interface, index, source, observed, &base));
		}

		for route in &interface.routes {
			self.plan_route(interface, route, observed, &base);
		}

		// Rule 6: post_up runs after the last addressing action completes.
		for hook in interface
			.hooks
			.iter()
			.filter(|h| h.phase == HookPhase::PostUp)
		{
			let mut deps = base.clone();
			deps.extend(addressing_ids.iter().copied());
			self.push(
				Op::HookRun {
					iface: name.clone(),
					phase: hook.phase,
					path: hook.path.clone(),
				},
				Reason::absent(name, "hooks[post_up]", hook.path.clone()),
				deps,
				None,
			);
		}
	}

	fn plan_source(
		&mut self,
		interface: &Interface,
		index: usize,
		source: &AddressSource,
		observed: &Observed,
		base: &[u32],
	) -> Vec<u32> {
		let name = &interface.name;
		let field = format!("addressing[{index}]");

		match source {
			AddressSource::Static(address) => {
				let present = observed
					.addresses_on(name)
					.any(|observed| observed.address == address.address);
				if present {
					return Vec::new();
				}
				// Rule 3, second half: addresses may be added to a link that
				// is down, so this does not wait for link.up.
				let id = self.push(
					Op::AddrAdd {
						iface: name.clone(),
						addr: address.address.clone(),
						preferred_lifetime: address.preferred_lifetime,
						valid_lifetime: address.valid_lifetime,
					},
					Reason::absent(name, field, address.address.clone()),
					base.to_vec(),
					Some(Op::AddrDel {
						iface: name.clone(),
						addr: address.address.clone(),
					}),
				);
				self.added.push((name.clone(), address.address.clone(), id));
				vec![id]
			}
			AddressSource::Dhcp4(_) => {
				self.plan_backend(interface, BackendKind::Dhcp4, &field, observed, base)
			}
			AddressSource::Dhcp6(_) => {
				self.plan_backend(interface, BackendKind::Dhcp6, &field, observed, base)
			}
			AddressSource::Slaac(_) => {
				// SLAAC is the kernel's job once accept_ra is set, which is a
				// sysctl this build does not manage yet. Say so rather than
				// silently doing nothing.
				self.warn(
					name,
					"slaac is accepted but not yet applied by this build; it lands with M4",
				);
				Vec::new()
			}
			AddressSource::LinkLocal => {
				self.warn(
					name,
					"link-local addressing is accepted but not yet applied by this build",
				);
				Vec::new()
			}
			AddressSource::Delegated(delegated) => {
				// The prefix is not known until the source interface's lease
				// arrives, so there is nothing to plan until then. Decision
				// 0009 puts the ordering edge here; the resolution lands with
				// prefix delegation in M4.
				self.warn(
					name,
					format!(
						"waiting on a delegated prefix from {}; nothing planned for {field}",
						delegated.prefix.source
					),
				);
				Vec::new()
			}
		}
	}

	fn plan_backend(
		&mut self,
		interface: &Interface,
		kind: BackendKind,
		field: &str,
		observed: &Observed,
		base: &[u32],
	) -> Vec<u32> {
		let name = &interface.name;
		if observed.backend_running(kind, name) {
			return Vec::new();
		}
		// Rule 3: a lease needs a live link, so this waits for link.up.
		let mut deps = base.to_vec();
		deps.extend(self.link_up_of(name));
		let id = self.push(
			Op::BackendStart {
				kind,
				iface: name.clone(),
			},
			Reason::absent(name, field, format!("{kind:?}")),
			deps,
			Some(Op::BackendStop {
				kind,
				iface: name.clone(),
			}),
		);
		vec![id]
	}

	fn plan_route(
		&mut self,
		interface: &Interface,
		route: &Route,
		observed: &Observed,
		base: &[u32],
	) {
		let name = &interface.name;
		if observed
			.routes_on(name)
			.any(|observed| route_matches(route, observed))
		{
			return;
		}

		let mut deps = base.to_vec();
		// Not one of the eight rules, and stated here because it is an
		// addition to them: a route on a down link is rejected by the kernel,
		// so route.add waits for link.up even though addr.add does not.
		deps.extend(self.link_up_of(name));

		// Rule 4: a route whose next hop lies in an address's subnet waits for
		// that address. An onlink route is exempt, which is what onlink means.
		if !route.onlink {
			if let Some(via) = route.via {
				let dependencies: Vec<u32> = self
					.added
					.iter()
					.filter(|(iface, address, _)| {
						iface == name
							&& net::parse_cidr(address).is_some_and(|(network, prefix)| {
								net::subnet_contains(network, prefix, via)
							})
					})
					.map(|(_, _, id)| *id)
					.collect();
				deps.extend(dependencies);
			}
		}

		self.push(
			Op::RouteAdd {
				iface: name.clone(),
				route: Box::new(route.clone()),
			},
			Reason::absent(name, "routes", render_route(route)),
			deps,
			Some(Op::RouteDel {
				iface: name.clone(),
				route: Box::new(route.clone()),
			}),
		);
	}

	fn plan_dns(&mut self, desired: &Document, observed: &Observed) {
		let mut scopes: Vec<(String, &DnsPolicy)> = Vec::new();
		if desired.globals.dns.mode != netcfgd_model::dns::DnsMode::None {
			scopes.push(("globals".to_owned(), &desired.globals.dns));
		}
		for interface in &desired.interfaces {
			if let Some(policy) = &interface.dns {
				scopes.push((interface.name.clone(), policy));
			}
		}

		for (scope, policy) in scopes {
			let previous = observed.dns_for(&scope);
			if previous == Some(policy) {
				continue;
			}
			let inverse = previous.map(|policy| Op::DnsApply {
				scope: scope.clone(),
				policy: Box::new(policy.clone()),
			});
			self.push(
				Op::DnsApply {
					scope: scope.clone(),
					policy: Box::new(policy.clone()),
				},
				Reason {
					interface: (scope != "globals").then(|| scope.clone()),
					field: "dns".to_owned(),
					desired: policy.mode.name().to_owned(),
					observed: previous
						.map_or_else(|| "<absent>".to_owned(), |p| p.mode.name().to_owned()),
				},
				Vec::new(),
				inverse,
			);
		}
	}

	/// Rule 7: teardown is the reverse of dependency order -- routes, then
	/// addresses, then backends, then links. The four steps are separate
	/// functions so that order is the only thing this one expresses.
	fn plan_teardown(&mut self, desired: &Document, observed: &Observed) {
		self.teardown_routes(desired, observed);
		self.teardown_addresses(desired, observed);
		self.teardown_backends(desired, observed);
		self.teardown_links(desired, observed);
	}

	fn teardown_routes(&mut self, desired: &Document, observed: &Observed) {
		for route in &observed.routes {
			if !route.ownership.may_remove() {
				continue;
			}
			// Only routes this build put there from config are removed. A
			// route a DHCP client installed is the backend's to withdraw, and
			// removing it here would fight the lease.
			if route.origin != Some(Origin::Static) {
				continue;
			}
			let wanted = desired
				.interfaces
				.iter()
				.filter(|interface| interface.name == route.interface)
				.any(|interface| {
					interface
						.routes
						.iter()
						.any(|desired| route_matches(desired, route))
				});
			if wanted {
				continue;
			}
			let model = Route {
				destination: route.destination.clone(),
				via: route.via,
				metric: route.metric,
				table: route.table,
				src: route.src,
				scope: route.scope,
				onlink: false,
				proto: route.proto,
			};
			self.push_root(
				Op::RouteDel {
					iface: route.interface.clone(),
					route: Box::new(model.clone()),
				},
				Reason::unwanted(&route.interface, "routes", render_route(&model)),
				Some(Op::RouteAdd {
					iface: route.interface.clone(),
					route: Box::new(model),
				}),
			);
		}
	}

	fn teardown_addresses(&mut self, desired: &Document, observed: &Observed) {
		for address in &observed.addresses {
			if !address.ownership.may_remove() {
				continue;
			}
			// Decision 0006 rule 7: a lease's address is the backend's, not
			// the planner's. Only what config put here comes out here.
			if address.origin != Some(Origin::Static) {
				continue;
			}
			let wanted = desired
				.interfaces
				.iter()
				.filter(|interface| interface.name == address.interface)
				.any(|interface| {
					interface.addressing.iter().any(|source| match source {
						AddressSource::Static(candidate) => candidate.address == address.address,
						_ => false,
					})
				});
			if wanted {
				continue;
			}
			self.push_root(
				Op::AddrDel {
					iface: address.interface.clone(),
					addr: address.address.clone(),
				},
				Reason::unwanted(&address.interface, "addressing", address.address.clone()),
				Some(Op::AddrAdd {
					iface: address.interface.clone(),
					addr: address.address.clone(),
					preferred_lifetime: None,
					valid_lifetime: None,
				}),
			);
		}
	}

	fn teardown_backends(&mut self, desired: &Document, observed: &Observed) {
		for backend in &observed.backends {
			if !backend.running {
				continue;
			}
			let wanted = desired
				.interfaces
				.iter()
				.filter(|interface| interface.name == backend.interface)
				.any(|interface| {
					interface.addressing.iter().any(|source| {
						matches!(
							(source, backend.kind),
							(AddressSource::Dhcp4(_), BackendKind::Dhcp4)
								| (AddressSource::Dhcp6(_), BackendKind::Dhcp6)
						)
					})
				});
			if wanted {
				continue;
			}
			self.push_root(
				Op::BackendStop {
					kind: backend.kind,
					iface: backend.interface.clone(),
				},
				Reason::unwanted(
					&backend.interface,
					"addressing",
					format!("{:?}", backend.kind),
				),
				Some(Op::BackendStart {
					kind: backend.kind,
					iface: backend.interface.clone(),
				}),
			);
		}
	}

	fn teardown_links(&mut self, desired: &Document, observed: &Observed) {
		for link in &observed.links {
			if !link.ownership.may_remove() {
				continue;
			}
			if desired
				.interfaces
				.iter()
				.any(|interface| interface.name == link.name)
			{
				continue;
			}
			self.push_root(
				Op::LinkDelete {
					name: link.name.clone(),
				},
				Reason::unwanted(&link.name, "kind", link.kind.clone()),
				// A deleted link cannot be recreated without knowing how it
				// was made, and the observed model records only what the
				// kernel says. Irreversible, and the warning says so.
				None,
			);
		}
	}

	fn finish(self) -> Plan {
		Plan {
			actions: self.actions,
			warnings: self.warnings,
			refusals: self.refusals,
		}
	}
}

/// Whether a desired route and an observed one are the same route.
///
/// Compared on the fields the kernel keys a route by, after normalising the
/// two places where "unset" and "the default" are the same thing. Both
/// exclusions were idempotence failures rather than theory:
///
/// - `onlink` is an instruction for installation, not a property that comes
///   back out of a dump, so comparing it makes every onlink route look absent.
/// - `table` is absent in a config that does not name one and always present
///   in a dump, so comparing them raw makes every ordinary route look absent.
///   This one got past the fixture harness and was caught by running `ncfg
///   apply` twice against a real kernel, because the simulated executor copied
///   the desired table through instead of defaulting it the way the kernel
///   does.
fn route_matches(desired: &Route, observed: &netcfgd_model::ObservedRoute) -> bool {
	let desired_table = desired.table.unwrap_or(netcfgd_model::route::MAIN_TABLE);
	let observed_table = observed.table.unwrap_or(netcfgd_model::route::MAIN_TABLE);
	desired.destination == observed.destination
		&& desired.via == observed.via
		&& desired_table == observed_table
		&& desired.src == observed.src
		&& (desired.metric.is_none() || desired.metric == observed.metric)
}

fn render_route(route: &Route) -> String {
	let mut out = route.destination.clone();
	if let Some(via) = route.via {
		out.push_str(&format!(" via {via}"));
	}
	if let Some(metric) = route.metric {
		out.push_str(&format!(" metric {metric}"));
	}
	out
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
