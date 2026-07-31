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

use netcfgd_model::{AclPolicy, RoutingRule};
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
	/// Devices the operator has explicitly consented to walk away from, keys
	/// and all.
	///
	/// Named per device for the same reason `allow_disruption` is, and kept
	/// separate from it rather than folded in: the two consent to different
	/// things, and an operator who accepted a brief outage on one interface has
	/// not thereby agreed to leave a private key on another.
	pub strand_credentials: Vec<String>,
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

/// Secret material a plan walks away from and cannot take back.
///
/// Not a [`Refusal`], which is an *action* a guard dropped and can name.
/// Nothing is dropped here: `managed = false` already means netcfgd plans
/// nothing for the device (decision 0035), and the hazard is that absence
/// continuing rather than anything being done. So this says what is being left
/// and offers the two ways of meaning it, and the exit code says a decision is
/// outstanding.
///
/// **Only for credentials that cannot be revoked from this host** -- see
/// `docs/decisions/0042` for the test and why the other secrets an unmanaged
/// device holds do not meet it. A notice that fires for everything is one
/// people learn to pass over, which would cost the one case that matters.
///
/// The credential is prose rather than an enum because there is exactly one
/// kind today. A second would make the enum worth its weight; one would make it
/// a decision dressed as a type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stranded {
	/// Which device is being walked away from.
	pub interface: String,
	/// What stays behind, and where.
	pub credential: String,
	/// Why it cannot simply be withdrawn later.
	pub irrevocable: String,
	/// The configuration change that removes it instead.
	pub remove_with: String,
	/// The exact invocation that consents to leaving it, for this run.
	pub consent_with: String,
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
	/// Credentials this plan walks away from that cannot be revoked.
	#[serde(default)]
	pub stranded: Vec<Stranded>,
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

	/// Whether this plan leaves behind a credential nobody can withdraw.
	///
	/// Separate from [`Plan::was_refused`] because the remedies are different,
	/// and a script that handled one as the other would do the wrong thing:
	/// a refusal is re-run with `--allow-disruption`, and this is answered by
	/// deciding what should happen to a key.
	#[must_use]
	pub fn strands_credentials(&self) -> bool {
		!self.stranded.is_empty()
	}
}

/// Say what the document asks for that this build does not do.
///
/// Split out of [`plan`] only for length. The failure mode these guard against
/// is not that a feature does nothing -- that is intended and recorded -- but
/// that it does nothing *silently*, so a plan reports "one action" about a
/// config that asked for several things.
///
/// The list has shrunk as the M4 freeze's inert features were built. What is
/// left is the half of the `ethtool` block that needs a physical NIC, and the
/// parts of an access point that hostapd can do and the schema cannot say.
fn warn_unapplied(builder: &mut Builder, desired: &Document) {
	warn_access_points(builder, desired);
	for interface in &desired.interfaces {
		// The offloads are applied; the rest of the `ethtool` block is not, and
		// says so field by field rather than as one blanket sentence -- an
		// operator who set only `gro` should not be told their config is
		// ignored.
		if let Some(settings) = &interface.link_settings {
			let unapplied: Vec<&str> = [
				(
					"autoneg",
					settings.autoneg != netcfgd_model::Toggle::Unmanaged,
				),
				("speed", settings.speed.is_some()),
				("duplex", settings.duplex.is_some()),
				("wol", settings.wol.is_some()),
				("rx_ring", settings.rx_ring.is_some()),
				("tx_ring", settings.tx_ring.is_some()),
			]
			.into_iter()
			.filter_map(|(name, set)| set.then_some(name))
			.collect();
			if !unapplied.is_empty() {
				builder.warnings.push(Warning {
					message: format!(
						"`{}` in the ethtool block are recognised but not applied by \
						 this build. They can only be exercised against a physical \
						 NIC, and an encoder nobody has run against one is how the \
						 last three netlink bugs here got in. The offloads are \
						 applied.",
						unapplied.join("`, `")
					),
					interface: Some(interface.name.clone()),
				});
			}
		}
	}
}

/// Say what an access point asks for that will not happen.
///
/// Three things, each of which produces an access point that looks configured
/// and is not -- which is the failure this whole function exists to prevent.
/// None of them is an error: the document is valid, and a later release or a
/// second `interface` block makes each one work.
/// Say which interfaces the configuration describes and netcfgd will not touch.
///
/// Only where a `device` block says `managed = false` *and* an `interface`
/// block describes it: an unmanaged device nobody wrote configuration for is
/// not a surprise worth reporting, while one with a full interface block is a
/// plan that will do nothing and needs to say why.
fn warn_unmanaged(builder: &mut Builder, desired: &Document) {
	for name in builder.unmanaged.clone() {
		if !desired
			.interfaces
			.iter()
			.any(|interface| interface.name == name)
		{
			continue;
		}
		// Named specifically rather than as "left as it is", because three of
		// the things left behind hold credentials: a WireGuard private key
		// stays loaded in the kernel, a supplicant netcfgd started keeps the
		// passphrases it was given, and a running hostapd keeps its generated
		// configuration under /run. Withdrawing those on the way out is not
		// implemented and is a decision rather than an oversight -- the flag
		// means "stop operating", and taking a key out is an operation.
		if builder.clearing.iter().any(|clearing| clearing == &name) {
			builder.warnings.push(Warning {
				message: format!(
					"`{name}` is `managed = false` with `on_unmanage = \"clear\"`: netcfgd \
					 removes everything it owns on it -- addresses and routes carrying its \
					 tag, backends it started, and the credentials those hold -- and then \
					 leaves it alone. Anything it did not put there is left exactly as it \
					 is. The plan above is what is left to remove; an empty one means it \
					 is done"
				),
				interface: Some(name),
			});
			continue;
		}
		builder.warnings.push(Warning {
			message: format!(
				"`{name}` is `managed = false`, so netcfgd will not touch it -- the \
				 `interface {name}` block is read and then not acted on. Whatever is \
				 already configured stays exactly as it is, and that includes \
				 credentials: a WireGuard key stays loaded, a supplicant netcfgd started \
				 keeps its passphrases, and a running hostapd keeps its generated \
				 configuration. Set `on_unmanage = \"clear\"` to have them removed first"
			),
			interface: Some(name),
		});
	}
}

fn warn_access_points(builder: &mut Builder, desired: &Document) {
	for access_point in &desired.access_points {
		let device = &access_point.device;

		// hostapd is started as an interface's prerequisite, and an interface
		// that is not in the document is never passed over.
		if !desired
			.interfaces
			.iter()
			.any(|interface| &interface.name == device)
		{
			builder.warnings.push(Warning {
				message: format!(
					"access point `{}` runs on `{device}`, which has no `interface` block, so \
					 nothing brings the radio up and nothing starts hostapd on it. Adding \
					 `interface {device} {{ }}` is enough",
					access_point.id
				),
				interface: Some(device.clone()),
			});
		}

		// An empty allow list is a legitimate thing to write -- it is how an
		// access point is closed without taking it down -- and an easy thing to
		// arrive at by deleting the last station from a list. It compiles
		// either way, because a compile diagnostic is a failure and this is
		// not one, so the difference between the two is said here.
		if let Some(acl) = &access_point.access_control {
			if matches!(acl.policy, AclPolicy::Allow) && acl.stations.is_empty() {
				builder.warnings.push(Warning {
					message: format!(
						"access point `{}` has an empty `allow` list, so no station can \
						 associate with it at all. Remove the `access_control` block to let \
						 everyone in",
						access_point.id
					),
					interface: Some(device.clone()),
				});
			}
		}

		// One radio, one BSS. Multiple would be `bss=` sections in hostapd's
		// configuration, each with its own security -- which is a real feature
		// and not one that can be written without a radio to try it on.
		//
		// Warned from the first access point on the device rather than from
		// each of them, so a radio with three gets one warning naming the two
		// that are ignored. `access_points` is sorted by id (section 2.1), so
		// "the first" is a stable answer rather than whichever the compiler
		// happened to emit first.
		let mut on_device = desired
			.access_points
			.iter()
			.filter(|other| &other.device == device);
		let first = on_device.next().map(|other| other.id.as_str());
		let ignored: Vec<&str> = on_device.map(|other| other.id.as_str()).collect();
		if first == Some(access_point.id.as_str()) && !ignored.is_empty() {
			builder.warnings.push(Warning {
				message: format!(
					"`{device}` has more than one access point and this build runs one BSS \
					 per radio, so `{}` is started and `{}` {} not",
					access_point.id,
					ignored.join("`, `"),
					if ignored.len() == 1 { "is" } else { "are" }
				),
				interface: Some(device.clone()),
			});
		}

		// Both halves of a radio at once needs two virtual interfaces on the
		// phy, which is a thing netcfgd does not create.
		if builder.radios.iter().any(|name| name == device) && builder.has_networks {
			builder.warnings.push(Warning {
				message: format!(
					"`{device}` runs the `{}` access point, so it is not also joining the \
					 configured networks -- one radio does both only with a second virtual \
					 interface, which netcfgd does not create",
					access_point.id
				),
				interface: Some(device.clone()),
			});
		}
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
	builder.appearing = desired
		.interfaces
		.iter()
		.filter_map(|interface| match &interface.kind {
			InterfaceKind::Veth(veth) => Some(veth.peer.clone()),
			_ => None,
		})
		.collect();

	builder.radios = desired
		.devices
		.iter()
		.filter(|device| device.managed && device.wifi.is_some())
		.map(|device| device.name.clone())
		.collect();
	builder.has_networks = !desired.networks.is_empty();
	builder.access_point_devices = desired
		.access_points
		.iter()
		.map(|access_point| access_point.device.clone())
		.collect();
	builder.unmanaged = desired
		.devices
		.iter()
		.filter(|device| !device.managed)
		.map(|device| device.name.clone())
		.collect();
	builder.clearing = desired
		.devices
		.iter()
		.filter(|device| !device.managed && device.on_unmanage == netcfgd_model::OnUnmanage::Clear)
		.map(|device| device.name.clone())
		.collect();

	// What the document asks for that this build does not do. Warned at plan
	// time rather than refused at compile time: the config is valid and will
	// mean something in a later release, so rejecting the document would make
	// an upgrade path into a rewrite. What must not happen is silence -- a plan
	// that omits something without saying so reports "nothing to do" about a
	// config that asked for two things.
	//
	// After the collections above, not before: it asks whether a device is a
	// radio and whether there are networks to join, and reading those while
	// they were still empty made one of its three warnings unreachable.
	warn_unapplied(&mut builder, desired);
	warn_unmanaged(&mut builder, desired);

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
	builder.plan_offloads(desired, observed);
	builder.plan_ipv6_token(desired, observed);
	builder.plan_rules(desired, observed);
	builder.plan_qdisc(desired, observed);
	builder.plan_ingress(desired, observed);
	builder.plan_forwarding(desired, observed);
	builder.plan_nat(desired, observed);
	builder.plan_access_control(desired, observed);
	builder.plan_stranded_credentials(observed, &options.strand_credentials);

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
	/// Credentials this plan walks away from and cannot take back.
	stranded: Vec<Stranded>,
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
	/// Interfaces that are radios netcfgd manages.
	///
	/// A radio needs a supplicant before it can carry anything, and whether an
	/// interface is one is a fact about the `device` block rather than the
	/// `interface` block -- so it is collected up front instead of looked up
	/// per action.
	radios: Vec<String>,
	/// Names that will exist by the end of this plan without anything
	/// creating them directly.
	///
	/// Only veth peers, so far. Creating one end of a veth creates both, so a
	/// peer that has no `interface` block of its own -- or has one and is not
	/// present yet -- is not absent hardware to be skipped. Without this the
	/// peer is configured on the *next* apply, which a daemon reaches on its
	/// own and `ncfg apply --oneshot` never does.
	appearing: Vec<String>,
	/// Whether the document has any wifi network to join.
	///
	/// A managed radio with no networks gets no supplicant. Starting one that
	/// would be given nothing is a process running for no reason, and it makes
	/// `ncfg status` report a backend nothing asked for.
	has_networks: bool,
	/// Devices that run an access point, in document order.
	///
	/// The device names rather than the access points themselves: the planner
	/// decides *that* hostapd runs on a radio, and the executor -- which has the
	/// document -- decides what it is told. A plan that carried the SSID and the
	/// channel would be a second copy of the configuration to keep in step.
	access_point_devices: Vec<String>,
	/// Devices a `device` block marks `managed = false`.
	///
	/// The model says netcfgd never touches these at all, and for a long time
	/// that was true of exactly one thing: the filter that decides which
	/// devices are radios. Everything else ignored it, so the escape hatch
	/// documented for handing an interface to another daemon planned three
	/// actions against it. Enforced in [`Builder::push`] now, which is the one
	/// place every action goes through.
	unmanaged: Vec<String>,
	/// Unmanaged devices whose policy is to be emptied first.
	///
	/// `on_unmanage = "clear"` says the desired state is that netcfgd owns
	/// nothing on the device. That is a state rather than a transition, so it
	/// needs no edge detection: teardown decides as if the interface were not
	/// in the document, removes what is tagged as ours, and finds nothing to
	/// do on every plan after that.
	clearing: Vec<String>,
	/// Whether the teardown passes are running.
	///
	/// The forward passes must not touch a clearing device -- planning an
	/// address and removing it in the same plan is a loop, not a convergence --
	/// so the exemption in [`Builder::push`] applies during teardown only.
	tearing_down: bool,
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
		// `managed = false` means netcfgd never touches the device -- including
		// not tearing down what it configured before the flag was set, which is
		// what "no further operation" was decided to mean. Dropped here rather
		// than guarded at each of the eleven passes that could emit one,
		// because a pass added later would not know to ask.
		//
		// Silently, because the warning that explains it is emitted once per
		// device up front. One warning naming the device beats three naming
		// each action it did not take.
		if let Some(interface) = op.interface() {
			let unmanaged = self.unmanaged.iter().any(|name| name == interface);
			let clearing = self.tearing_down && self.clearing.iter().any(|name| name == interface);
			if unmanaged && !clearing {
				return u32::MAX;
			}
		}
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

	/// Whether an interface currently has carrier.
	///
	/// An interface this plan is creating counts as having it: a veth or a
	/// bridge that does not exist yet reports nothing, and refusing its routes
	/// on that basis would mean they never landed on the first apply.
	fn has_carrier(name: &str, observed: &Observed) -> bool {
		observed.link(name).is_none_or(|link| link.carrier)
	}

	/// The VLANs a bridge port or bridge device carries.
	///
	/// Authoritative where the document lists any: the port has exactly those
	/// and nothing else. That includes removing the VLAN 1 the kernel adds by
	/// itself when a port joins a filtering bridge -- every real trunk setup
	/// starts by deleting it, and leaving it because the kernel put it there
	/// would mean the document does not describe the port.
	///
	/// A port the document says nothing about is left alone entirely. The
	/// authority is over ports that are configured, not over the bridge.
	fn plan_bridge_vlans(&mut self, interface: &Interface, observed: &Observed, base: &[u32]) {
		if interface.bridge_vlans.is_empty() {
			return;
		}
		let name = &interface.name;
		// A VLAN on the bridge device itself is a SELF operation; one on a
		// port is MASTER. Getting it backwards is accepted by the kernel and
		// configures the wrong device.
		let on_self = matches!(interface.kind, InterfaceKind::Bridge(_));

		// A link this plan is about to create has no VLANs yet, which is not
		// the same as having none to compare against -- returning early here
		// meant a freshly created bridge got its VLANs on the *next* reconcile
		// instead of this one. Anything absent by now is being created; the
		// cases that are genuinely missing were dropped further up.
		let existing = observed.link(name);
		let current: Vec<&netcfgd_model::ObservedBridgeVlan> = existing
			.map(|link| {
				observed
					.bridge_vlans
					.iter()
					.filter(|vlan| vlan.index == link.index)
					.collect()
			})
			.unwrap_or_default();

		// The kernel puts VLAN 1 on a port the moment it joins a filtering
		// bridge, which happens during *this* apply -- so it is not in the
		// observed state the plan was computed from, and without this the
		// removal would land on the next reconcile. That is fine for the
		// daemon and never happens under `--oneshot`.
		//
		// Safe to plan unconditionally because removing a VLAN that is not
		// there is a silent success: checked against the kernel with filtering
		// both on and off, and with the id absent.
		if existing.is_none() && !interface.bridge_vlans.iter().any(|vlan| vlan.vid == 1) {
			self.push(
				Op::BridgeVlanDel {
					iface: name.clone(),
					vid: 1,
					on_self,
				},
				Reason::unwanted(name, "vlans", "1 (the kernel's default)".to_owned()),
				base.to_vec(),
				None,
			);
		}

		for wanted in &interface.bridge_vlans {
			// Compared on the flags too: a VLAN that is present but tagged
			// where the document says untagged is wrong in a way that shows up
			// as traffic arriving with a tag nobody expected.
			if current.iter().any(|vlan| {
				vlan.vid == wanted.vid
					&& vlan.pvid == wanted.pvid
					&& vlan.untagged == wanted.untagged
			}) {
				continue;
			}
			self.push(
				Op::BridgeVlanAdd {
					iface: name.clone(),
					vid: wanted.vid,
					pvid: wanted.pvid,
					untagged: wanted.untagged,
					on_self,
				},
				Reason::absent(name, "vlans", render_vlan(*wanted)),
				base.to_vec(),
				Some(Op::BridgeVlanDel {
					iface: name.clone(),
					vid: wanted.vid,
					on_self,
				}),
			);
		}

		for present in current {
			if interface
				.bridge_vlans
				.iter()
				.any(|wanted| wanted.vid == present.vid)
			{
				continue;
			}
			self.push(
				Op::BridgeVlanDel {
					iface: name.clone(),
					vid: present.vid,
					on_self,
				},
				Reason::unwanted(name, "vlans", present.vid.to_string()),
				base.to_vec(),
				Some(Op::BridgeVlanAdd {
					iface: name.clone(),
					vid: present.vid,
					pvid: present.pvid,
					untagged: present.untagged,
					on_self,
				}),
			);
		}
	}

	/// The backend an interface needs before it can carry anything.
	///
	/// Four cases and one shape: an 802.1X port has not authenticated, a radio
	/// is not running its access point, a radio has not associated, and a PPP
	/// interface does not exist. All four are prerequisites rather than
	/// addressing, and all four go in the same place in the order -- before any
	/// address, because a client started first spends its backoff talking to
	/// something that is not listening.
	fn plan_prerequisite(
		&mut self,
		interface: &Interface,
		observed: &Observed,
		base: &[u32],
	) -> Vec<u32> {
		if interface.dot1x.is_some() {
			return self.plan_backend(interface, BackendKind::Supplicant, "dot1x", observed, base);
		}
		if matches!(interface.kind, InterfaceKind::Pppoe(_)) {
			return self.plan_backend(interface, BackendKind::Pppoe, "pppoe", observed, base);
		}
		// Before the supplicant, because a radio that runs an access point does
		// not also join networks with the same interface. The warning that says
		// so is emitted once, up front, rather than here -- this runs per
		// interface and per plan, and a warning that repeats is one people
		// learn to page past.
		if self
			.access_point_devices
			.iter()
			.any(|name| name == &interface.name)
		{
			return self.plan_backend(
				interface,
				BackendKind::AccessPoint,
				"access_point",
				observed,
				base,
			);
		}
		if self.radios.iter().any(|name| name == &interface.name) && self.has_networks {
			// The field named is the `device` block's, not the interface's,
			// because that is where somebody would go to turn this off.
			return self.plan_backend(interface, BackendKind::Supplicant, "wifi", observed, base);
		}
		Vec::new()
	}

	/// A PPP interface that does not exist yet.
	///
	/// Only the dial is planned. PPP negotiates asynchronously, so the
	/// interface appears seconds after `pppd` starts -- "waits for the
	/// session" means "arrives on a later reconcile" rather than "later in
	/// this plan". The daemon gets there on its own when netlink reports the
	/// new link; `ncfg apply --oneshot` needs a second run, and the warning
	/// says so rather than leaving a DSL user wondering why their route is
	/// missing.
	fn plan_ppp_session(&mut self, interface: &Interface, observed: &Observed) {
		let name = &interface.name;
		let base = self.gate(name);
		self.plan_backend(interface, BackendKind::Pppoe, "pppoe", observed, &base);
		self.warn(
			name,
			"the ppp session is not up yet; addressing and routes are planned once it is",
		);
	}

	/// Rule 1: create a link before anything references it.
	fn plan_link_creation(&mut self, interface: &Interface, observed: &Observed) {
		if observed.link(&interface.name).is_some() {
			return;
		}
		if matches!(interface.kind, InterfaceKind::Pppoe(_)) {
			// A PPP interface is created by `pppd` when the session comes up,
			// not by netlink. Planning a `link.create` for it would emit an
			// action that must fail; the `backend.start` below is what brings
			// it into existence.
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
		if link.is_none() && matches!(interface.kind, InterfaceKind::Pppoe(_)) {
			self.plan_ppp_session(interface, observed);
			return;
		}
		if link.is_none()
			&& matches!(interface.kind, InterfaceKind::Physical)
			&& !self.appearing.iter().any(|peer| peer == name)
		{
			// Absent hardware. Planning for a NIC that is not plugged in would
			// fill every plan with actions that cannot run.
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
		if link.is_none() && matches!(interface.kind, InterfaceKind::Pppoe(_)) {
			self.plan_ppp_session(interface, observed);
			return;
		}
		if link.is_none()
			&& matches!(interface.kind, InterfaceKind::Physical)
			&& !self.appearing.iter().any(|peer| peer == name)
		{
			// Absent hardware. Planning for a NIC that is not plugged in would
			// fill every plan with actions that cannot run.
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

		// 802.1X comes before addressing, not after. A port that has not
		// authenticated drops everything, so a DHCP client started first would
		// spend its whole backoff sequence talking to a switch that is not
		// listening -- and then report a failure whose real cause is two steps
		// earlier. Decision 0008 puts wired 802.1X on the same supplicant as
		// wifi, so this is the same op either way.
		let authentication = self.plan_prerequisite(interface, observed, &base);
		self.plan_bridge_vlans(interface, observed, &base);

		let mut addressing_ids = Vec::new();
		for (index, source) in interface.addressing.iter().enumerate() {
			let mut source_base = base.clone();
			source_base.extend(authentication.iter().copied());
			addressing_ids.extend(self.plan_source(
				interface,
				index,
				source,
				observed,
				&source_base,
			));
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
				self.plan_delegated(interface, delegated, &field, observed, base)
			}
		}
	}

	/// An address derived from a prefix the ISP delegated.
	///
	/// Decision 0009: the document holds a reference, never a value, so this
	/// is where the value is looked up. Three outcomes, and the difference
	/// between the first two is the whole reason the indirection exists:
	///
	/// - **No delegation yet.** The lease has not arrived. Nothing is planned
	///   and a warning says what is being waited for -- not an error, because
	///   the config is correct and the answer is "later".
	/// - **A delegation that cannot produce this address.** The subnet does
	///   not fit, or the suffix is wider than the block. That is a config that
	///   can never work, so it is a refusal rather than a wait.
	/// - **A resolved address**, planned exactly as a static one would be.
	///   Renumbering then falls out of the ordinary diff: a new delegation
	///   produces a different address, the old one is no longer wanted, and
	///   the plan is an `addr.del` and an `addr.add`.
	fn plan_delegated(
		&mut self,
		interface: &Interface,
		delegated: &netcfgd_model::Delegated,
		field: &str,
		observed: &Observed,
		base: &[u32],
	) -> Vec<u32> {
		let name = &interface.name;
		let source = &delegated.prefix.source;

		let Some(delegation) = observed.delegation(source) else {
			self.warn(
				name,
				format!("waiting on a delegated prefix from {source}; nothing planned for {field}"),
			);
			return Vec::new();
		};
		let Some(prefix) = delegation.prefixes.get(delegated.prefix.index as usize) else {
			self.warn(
				name,
				format!(
					"{source} has {} delegated prefix(es) and {field} asks for index {}",
					delegation.prefixes.len(),
					delegated.prefix.index
				),
			);
			return Vec::new();
		};

		let address = match netcfgd_model::derive_from_delegation(
			prefix,
			&delegated.prefix,
			&delegated.suffix,
		) {
			Ok(address) => address,
			Err(message) => {
				// A warning rather than a refusal: `Refusal` is for a guard
				// declining a disruptive action, and this is a configuration
				// that cannot be satisfied. Both stop the address being
				// planned; only one of them is about consent.
				self.warn(name, format!("{field}: {message}"));
				return Vec::new();
			}
		};

		if observed
			.addresses_on(name)
			.any(|existing| existing.address == address)
		{
			return Vec::new();
		}

		// The source interface's lease has to exist before this address can,
		// and it does -- the delegation was read from observed state. What
		// this still waits for is the same base the interface's other
		// addresses do.
		let id = self.push(
			Op::AddrAdd {
				iface: name.clone(),
				addr: address.clone(),
				preferred_lifetime: None,
				valid_lifetime: None,
			},
			Reason::absent(name, field, format!("{address} (from {source})")),
			base.to_vec(),
			Some(Op::AddrDel {
				iface: name.clone(),
				addr: address.clone(),
			}),
		);
		self.added.push((name.clone(), address, id));
		vec![id]
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

		// A route down a cable that is not plugged in is a black hole, and a
		// lower metric would make the kernel prefer it over the wifi that
		// works. So an interface with a preference does not get its routes
		// while it has no carrier. Without a preference nothing here applies:
		// a server with one uplink keeps its routes through a flap.
		if interface.preference.is_some() && !Self::has_carrier(name, observed) {
			self.warn(
				name,
				format!("no carrier, so {name}'s routes are not installed"),
			);
			return;
		}

		let route = &with_metric(route, interface.preference);
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

	/// Policy routing rules, reconciled against what the kernel holds.
	///
	/// Keyed on `(family, priority)`, which is what the kernel keys them by --
	/// two rules cannot share it. That is also why `priority` is mandatory in
	/// the model: an unnumbered rule lands wherever the kernel puts it, and
	/// two applies can produce different orders, which makes the document stop
	/// describing the system.
	/// Driver offloads, for each interface whose `ethtool` block sets any.
	///
	/// Only the ones the document names. A mask bitset means "change exactly
	/// these", so an offload nobody mentioned keeps whatever the driver chose,
	/// which is the same posture netcfgd takes to every other object it did
	/// not install.
	fn plan_offloads(&mut self, desired: &Document, observed: &Observed) {
		for interface in &desired.interfaces {
			let Some(settings) = &interface.link_settings else {
				continue;
			};
			// The link may not exist yet -- this is the first apply and it is
			// about to be created. Nothing is known about its offloads then,
			// so every named one is planned and the action waits on the
			// creation. Skipping instead is what made a fresh apply leave the
			// offloads at the driver default and need a second run.
			let link = observed.link(&interface.name);

			let mut wanted: Vec<(String, bool)> = Vec::new();
			for (toggle, names) in [
				(settings.gro, netcfgd_model::interface::offload_names::GRO),
				(settings.gso, netcfgd_model::interface::offload_names::GSO),
				(settings.tso, netcfgd_model::interface::offload_names::TSO),
				(
					settings.rx_checksum,
					netcfgd_model::interface::offload_names::RX_CHECKSUM,
				),
				(
					settings.tx_checksum,
					netcfgd_model::interface::offload_names::TX_CHECKSUM,
				),
			] {
				let on = match toggle {
					netcfgd_model::Toggle::Unmanaged => continue,
					netcfgd_model::Toggle::On => true,
					netcfgd_model::Toggle::Off => false,
				};
				// "On" for a field covering several kernel features means any
				// of them; "off" means all of them. That is what `ethtool -K
				// dev tx on|off` does, and transmit checksumming is three
				// features because a driver offers whichever its hardware has.
				let held = link.is_some_and(|link| names.iter().any(|name| held_on(link, name)));
				if link.is_some() && held == on {
					continue;
				}
				for name in names {
					wanted.push(((*name).to_owned(), on));
				}
			}
			if wanted.is_empty() {
				continue;
			}
			wanted.sort();

			let describe = |features: &[(String, bool)]| {
				features
					.iter()
					.map(|(name, on)| format!("{name}={on}"))
					.collect::<Vec<_>>()
					.join(" ")
			};
			let inverse: Vec<(String, bool)> = wanted
				.iter()
				.map(|(name, _)| (name.clone(), link.is_some_and(|link| held_on(link, name))))
				.collect();
			self.push(
				Op::LinkSetOffloads {
					name: interface.name.clone(),
					features: wanted.clone(),
				},
				Reason {
					interface: Some(interface.name.clone()),
					field: "ethtool".to_owned(),
					desired: describe(&wanted),
					observed: describe(&inverse),
				},
				self.gate(&interface.name),
				Some(Op::LinkSetOffloads {
					name: interface.name.clone(),
					features: inverse,
				}),
			);
		}
	}

	/// The IPv6 interface identifier on each interface that names one.
	///
	/// Only where the document asks. A token nobody asked for is not removed:
	/// unlike an address it carries no ownership tag, and the kernel offers no
	/// way to tell one netcfgd set from one an operator set by hand.
	fn plan_ipv6_token(&mut self, desired: &Document, observed: &Observed) {
		for interface in &desired.interfaces {
			let Some(token) = &interface.ipv6_token else {
				continue;
			};
			let link = observed.link(&interface.name);
			let current = link.and_then(|link| link.ipv6_token.as_deref());
			// Compared as addresses, not as text: `::5` and `0:0:0:0:0:0:0:5`
			// are the same token, and the kernel reports its own spelling.
			let same = current
				.and_then(|held| held.parse::<std::net::IpAddr>().ok())
				.zip(token.parse::<std::net::IpAddr>().ok())
				.is_some_and(|(held, want)| held == want);
			if same {
				continue;
			}
			self.push(
				Op::LinkSetIpv6Token {
					name: interface.name.clone(),
					token: token.clone(),
				},
				Reason {
					interface: Some(interface.name.clone()),
					field: "ipv6_token".to_owned(),
					desired: token.clone(),
					observed: current.unwrap_or("<absent>").to_owned(),
				},
				self.gate(&interface.name),
				// The inverse clears it. Restoring a previous token would be
				// wrong where there was none, and `::` is how the kernel
				// spells "none".
				Some(Op::LinkSetIpv6Token {
					name: interface.name.clone(),
					token: current.unwrap_or("::").to_owned(),
				}),
			);
		}
	}

	fn plan_rules(&mut self, desired: &Document, observed: &Observed) {
		for rule in &desired.rules {
			let current = observed
				.rules
				.iter()
				.find(|held| held.family == rule.family && held.priority == rule.priority);
			if current.is_some_and(|held| same_rule(rule, held)) {
				continue;
			}
			// A rule at this priority that is not the one wanted has to go
			// first: the kernel keys on it, so adding would be `EEXIST`. Only
			// where it is netcfgd's to remove -- otherwise the plan says so
			// and changes nothing, which is what `may_remove` is for.
			if let Some(held) = current {
				if !held.ownership.may_remove() {
					self.warnings.push(Warning {
						message: format!(
							"rule `{}` wants priority {} in {:?}, and a rule netcfgd \
							 does not own is already there. Renumber it, or remove \
							 the other by hand.",
							rule.id, rule.priority, rule.family
						),
						interface: None,
					});
					continue;
				}
				self.push_root(
					Op::RuleDel {
						rule: Box::new(to_desired(held)),
					},
					Reason {
						interface: None,
						field: format!("rules.{}", rule.id),
						desired: describe(rule),
						observed: "a different rule at this priority".to_owned(),
					},
					None,
				);
			}
			self.push_root(
				Op::RuleAdd {
					rule: Box::new(rule.clone()),
				},
				Reason {
					interface: None,
					field: format!("rules.{}", rule.id),
					desired: describe(rule),
					observed: current.map_or_else(
						|| "<absent>".to_owned(),
						|_| "a different rule at this priority".to_owned(),
					),
				},
				Some(Op::RuleDel {
					rule: Box::new(rule.clone()),
				}),
			);
		}

		// And anything of netcfgd's the document no longer asks for.
		for held in &observed.rules {
			if !held.ownership.may_remove() {
				continue;
			}
			if desired
				.rules
				.iter()
				.any(|rule| rule.family == held.family && rule.priority == held.priority)
			{
				continue;
			}
			let rule = to_desired(held);
			self.push_root(
				Op::RuleDel {
					rule: Box::new(rule.clone()),
				},
				Reason {
					interface: None,
					field: "rules".to_owned(),
					desired: "<absent>".to_owned(),
					observed: describe(&rule),
				},
				Some(Op::RuleAdd {
					rule: Box::new(rule),
				}),
			);
		}
	}

	/// The root qdisc on each interface that names one.
	///
	/// Every interface always has a qdisc, so this is never "install where
	/// absent" -- it is always a comparison against something, which is what
	/// makes it idempotent without recorded state. Recorded state is needed
	/// only to know whether netcfgd may reset one.
	fn plan_qdisc(&mut self, desired: &Document, observed: &Observed) {
		for interface in &desired.interfaces {
			let link = observed.link(&interface.name);
			let current = link.and_then(|link| link.qdisc.as_deref());
			let current_rate = link.and_then(|link| link.qdisc_bandwidth_bits);
			let ours = observed.qdisc_applied.contains(&interface.name);

			let Some(policy) = interface.qdisc else {
				// Stopped asking. Put the kernel default back, but only where
				// netcfgd is what moved it -- an interface that was already
				// running `cake` before netcfgd existed keeps it.
				if ours {
					self.push(
						Op::QdiscReset {
							iface: interface.name.clone(),
						},
						Reason::unwanted(
							&interface.name,
							"qdisc",
							current.unwrap_or("<unknown>").to_owned(),
						),
						self.gate(&interface.name),
						current.map(|kind| Op::QdiscSet {
							iface: interface.name.clone(),
							kind: kind.to_owned(),
							bandwidth_bits: current_rate,
							ingress: link.is_some_and(|link| link.qdisc_ingress),
						}),
					);
				}
				continue;
			};

			// The rate is part of the comparison, not an afterthought. A
			// `cake` already installed at the wrong bandwidth is the exact
			// case where "the kind matches, nothing to do" shapes a line at
			// somebody else's number.
			let current_ingress = link.is_some_and(|link| link.qdisc_ingress);
			if current == Some(policy.kind.name())
				&& current_rate == policy.bandwidth_bits
				&& current_ingress == policy.ingress
			{
				continue;
			}

			let describe = |kind: &str, rate: Option<u64>| match rate {
				Some(bits) => format!("{kind} at {bits} bit/s"),
				None => kind.to_owned(),
			};
			self.push(
				Op::QdiscSet {
					iface: interface.name.clone(),
					kind: policy.kind.name().to_owned(),
					bandwidth_bits: policy.bandwidth_bits,
					ingress: policy.ingress,
				},
				Reason {
					interface: Some(interface.name.clone()),
					field: "qdisc".to_owned(),
					desired: describe(policy.kind.name(), policy.bandwidth_bits),
					observed: current.map_or_else(
						|| "<absent>".to_owned(),
						|kind| describe(kind, current_rate),
					),
				},
				self.gate(&interface.name),
				current.map(|kind| Op::QdiscSet {
					iface: interface.name.clone(),
					kind: kind.to_owned(),
					bandwidth_bits: current_rate,
					ingress: current_ingress,
				}),
			);
		}
	}

	/// The ingress redirect on each interface that asks for one.
	///
	/// Planned after the qdiscs so the `ifb` exists and is shaped before
	/// anything is pointed at it -- traffic redirected onto a device with no
	/// shaper is traffic that is not being shaped, which is worse than not
	/// redirecting it at all.
	fn plan_ingress(&mut self, desired: &Document, observed: &Observed) {
		for interface in &desired.interfaces {
			let current = observed
				.link(&interface.name)
				.and_then(|link| link.ingress_redirect.as_deref());
			let ours = observed.ingress_applied.contains(&interface.name);

			match interface.ingress_redirect.as_deref() {
				Some(target) if current == Some(target) => {}
				Some(target) => {
					self.push(
						Op::IngressRedirect {
							iface: interface.name.clone(),
							target: target.to_owned(),
						},
						Reason {
							interface: Some(interface.name.clone()),
							field: "ingress_redirect".to_owned(),
							desired: target.to_owned(),
							observed: current.unwrap_or("<absent>").to_owned(),
						},
						self.gate(target),
						Some(Op::IngressRedirectClear {
							iface: interface.name.clone(),
						}),
					);
				}
				// Same ownership rule as the qdisc: a redirect somebody else
				// put there is not netcfgd's to take away.
				None if current.is_some() && ours => {
					self.push(
						Op::IngressRedirectClear {
							iface: interface.name.clone(),
						},
						Reason::unwanted(
							&interface.name,
							"ingress_redirect",
							current.unwrap_or_default().to_owned(),
						),
						Vec::new(),
						current.map(|target| Op::IngressRedirect {
							iface: interface.name.clone(),
							target: target.to_owned(),
						}),
					);
				}
				None => {}
			}
		}
	}

	/// The `forwarding` sysctl on each interface that asks for one.
	///
	/// Planned per interface and applied per interface, rather than through
	/// the global `net.ipv4.ip_forward`. Writing the global one sets every
	/// device at once, so netcfgd would be turning forwarding on for
	/// interfaces the document says nothing about -- and it could never turn
	/// it off again without guessing which of those it had been responsible
	/// for.
	fn plan_forwarding(&mut self, desired: &Document, observed: &Observed) {
		for interface in &desired.interfaces {
			// An interface that stops asking is turned back off, but only
			// where netcfgd is the one that turned it on. Without this the
			// sysctl is a one-way door: deleting `forwarding = true` from the
			// document leaves the machine routing, which is drift the config
			// can no longer describe and constraint 1 does not allow.
			let wanted = match interface.forwarding {
				Some(wanted) => wanted,
				None if observed.forwarding_applied.contains(&interface.name) => false,
				None => continue,
			};
			let current = observed
				.link(&interface.name)
				.and_then(|link| link.forwarding);
			if current == Some(wanted) {
				continue;
			}
			self.push(
				Op::SysctlSetForwarding {
					iface: interface.name.clone(),
					enabled: wanted,
				},
				Reason {
					interface: Some(interface.name.clone()),
					field: "forwarding".to_owned(),
					desired: wanted.to_string(),
					observed: current
						.map_or_else(|| "<unreadable>".to_owned(), |on| on.to_string()),
				},
				self.gate(&interface.name),
				// Only where the previous value is known. A sysctl that could
				// not be read cannot be restored, and inventing `false` as the
				// inverse would have commit-confirm turn forwarding off on a
				// router that had it on before netcfgd ever ran.
				current.map(|previous| Op::SysctlSetForwarding {
					iface: interface.name.clone(),
					enabled: previous,
				}),
			);
		}
	}

	/// netcfgd's one nftables table, replaced whole.
	///
	/// The comparison is between two sorted lists of interface names, which is
	/// the entire diff -- there is no per-rule reconciliation because there is
	/// no per-rule change. Decision 0022.
	fn plan_nat(&mut self, desired: &Document, observed: &Observed) {
		let mut wanted: Vec<String> = desired
			.interfaces
			.iter()
			.filter(|interface| interface.nat == Some(true))
			.map(|interface| interface.name.clone())
			.collect();
		wanted.sort();

		// Reported whenever netcfgd has an opinion about NAT, including when
		// its opinion is "none" -- an operator who has just removed `nat` from
		// their config is exactly the person who needs to know something else
		// is still translating.
		if !observed.nat_conflicts.is_empty() && (!wanted.is_empty() || !observed.nat.is_empty()) {
			self.warnings.push(Warning {
				message: format!(
					"nftables table(s) `{}` also translate source addresses. Traffic \
					 matching both is translated twice, which breaks return paths in \
					 ways that look like packet loss. netcfgd will not delete another \
					 table -- it cannot tell what filtering is in there -- so remove \
					 the duplicate rule yourself, or drop `nat` here.",
					observed.nat_conflicts.join("`, `")
				),
				interface: None,
			});
		}

		// Forwarding is what makes NAT do anything, and the two are set
		// independently, so this is the mistake that produces a router which
		// translates nothing because nothing was forwarded to it.
		if !wanted.is_empty()
			&& !desired
				.interfaces
				.iter()
				.any(|interface| interface.forwarding == Some(true))
		{
			self.warnings.push(Warning {
				message: "`nat` is set but no interface has `forwarding = true`, so nothing \
					 will reach the translation. Set it on the interface the traffic \
					 arrives on -- the LAN side, not the uplink."
					.to_owned(),
				interface: None,
			});
		}

		if wanted == observed.nat {
			return;
		}

		let describe = |uplinks: &[String]| {
			if uplinks.is_empty() {
				"<none>".to_owned()
			} else {
				uplinks.join(", ")
			}
		};
		let reason = Reason {
			interface: None,
			field: "nat".to_owned(),
			desired: describe(&wanted),
			observed: describe(&observed.nat),
		};
		self.push_root(
			Op::NatReplace { uplinks: wanted },
			reason,
			Some(Op::NatReplace {
				uplinks: observed.nat.clone(),
			}),
		);
	}

	fn plan_dns(&mut self, desired: &Document, observed: &Observed) {
		let mut scopes: Vec<(String, &DnsPolicy)> = Vec::new();
		if desired.globals.dns.mode != netcfgd_model::dns::DnsMode::None {
			scopes.push(("globals".to_owned(), &desired.globals.dns));
		}
		for interface in &desired.interfaces {
			// An unmanaged interface contributes no scope. `DnsApply` is
			// host-wide, so it names no interface and the check in `push` does
			// not see it -- this is the one place that has to ask directly.
			if self.unmanaged.iter().any(|name| name == &interface.name) {
				continue;
			}
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
		self.tearing_down = true;

		// A device being cleared is decided about as if its `interface` block
		// were not there: the desired state is that netcfgd owns nothing on
		// it, and every teardown pass already knows how to remove what the
		// document does not want. Filtering the document once beats teaching
		// four passes about a policy none of them otherwise cares about.
		let filtered;
		let desired = if self.clearing.is_empty() {
			desired
		} else {
			let mut copy = desired.clone();
			copy.interfaces
				.retain(|interface| !self.clearing.iter().any(|name| name == &interface.name));
			filtered = copy;
			&filtered
		};

		self.teardown_routes(desired, observed);
		self.teardown_addresses(desired, observed);
		self.teardown_backends(desired, observed);
		self.teardown_links(desired, observed);
		self.tearing_down = false;
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
					// A route on an interface that has lost carrier stops
					// being wanted, which is what makes the switch happen:
					// removing it is how the kernel starts using the other
					// interface instead of black-holing traffic down this one.
					if interface.preference.is_some()
						&& !observed
							.link(&interface.name)
							.is_some_and(|link| link.carrier)
					{
						return false;
					}
					interface.routes.iter().any(|desired| {
						route_matches(&with_metric(desired, interface.preference), route)
					})
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
						// A derived address is as wanted as a literal one. The
						// document holds a reference rather than the value, so
						// answering "is this wanted?" means resolving it again
						// -- and a teardown that skipped that would delete the
						// address the same plan had just added, forever.
						AddressSource::Delegated(delegated) => observed
							.delegation(&delegated.prefix.source)
							.and_then(|delegation| {
								delegation.prefixes.get(delegated.prefix.index as usize)
							})
							.and_then(|prefix| {
								netcfgd_model::derive_from_delegation(
									prefix,
									&delegated.prefix,
									&delegated.suffix,
								)
								.ok()
							})
							.is_some_and(|derived| derived == address.address),
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

	/// Whether a running backend is one the document asks for, and which
	/// config field decides it.
	///
	/// **Exhaustive on the kind, deliberately.** This is the third place a new
	/// backend has had to be taught about, and the first two were both found
	/// the same way: the idempotence gate caught netcfgd starting something
	/// and stopping it on the next reconcile, forever. A wildcard arm here is
	/// what made that possible twice, so there is not one -- a kind added
	/// without an answer fails to compile.
	///
	/// The field is returned alongside because an operator told a supplicant
	/// was stopped because of `addressing` goes and looks at the wrong block.
	fn backend_wanted(
		&self,
		desired: &Document,
		backend: &netcfgd_model::ObservedBackend,
	) -> (bool, &'static str) {
		let on_interface = |predicate: &dyn Fn(&Interface) -> bool| {
			desired
				.interfaces
				.iter()
				.filter(|interface| interface.name == backend.interface)
				.any(predicate)
		};

		match backend.kind {
			BackendKind::Supplicant => (
				self.supplicant_wanted(desired, &backend.interface),
				"wifi/dot1x",
			),
			// The document still naming an access point on this device. Not
			// "this device is a radio": a radio whose `access_point` block was
			// deleted is exactly the case that has to stop hostapd, and the
			// radio is still a radio.
			BackendKind::AccessPoint => (
				desired
					.access_points
					.iter()
					.any(|access_point| access_point.device == backend.interface),
				"access_point",
			),
			BackendKind::Dhcp4 => (
				on_interface(&|interface| {
					interface
						.addressing
						.iter()
						.any(|source| matches!(source, AddressSource::Dhcp4(_)))
				}),
				"addressing",
			),
			BackendKind::Dhcp6 => (
				on_interface(&|interface| {
					interface
						.addressing
						.iter()
						.any(|source| matches!(source, AddressSource::Dhcp6(_)))
				}),
				"addressing",
			),
			// The session *is* the interface, so the question is whether the
			// document still declares one.
			BackendKind::Pppoe => (
				on_interface(&|interface| matches!(interface.kind, InterfaceKind::Pppoe(_))),
				"pppoe",
			),
			// Not started by the planner, so not stopped by it either. A
			// WireGuard device is configured at creation and a DNS delivery is
			// an action rather than a process; router advertisement is not
			// implemented. Reporting them as unwanted would stop something
			// netcfgd never started.
			BackendKind::WireGuard | BackendKind::Dns | BackendKind::RouterAdvert => (true, ""),
		}
	}

	/// Whether a running supplicant is one the document asks for.
	///
	/// The same two conditions that start one. Getting this wrong in the
	/// permissive direction leaves a supplicant nobody owns; getting it wrong
	/// in the other direction makes netcfgd start a supplicant and kill it on
	/// the next reconcile, forever -- which is what the idempotence gate
	/// caught when this function did not know the kind existed.
	fn supplicant_wanted(&self, desired: &Document, iface: &str) -> bool {
		let dot1x = desired
			.interfaces
			.iter()
			.any(|interface| interface.name == iface && interface.dot1x.is_some());
		if dot1x {
			return true;
		}
		// A radio that has been given an access point is not a station, so a
		// supplicant left over from before the `access_point` block was written
		// is unwanted. Without this arm the two backends would each be started
		// by the pass that wants it and stopped by the pass that does not.
		if self.access_point_devices.iter().any(|name| name == iface) {
			return false;
		}
		self.radios.iter().any(|name| name == iface) && self.has_networks
	}

	/// Notice a plan that walks away from a key nobody can withdraw.
	///
	/// Decision 0042, closing what 0037 left open. The test is deliberately
	/// narrow, and narrower than 0037 guessed: a credential qualifies only when
	/// **it cannot be revoked from this host** *and* **netcfgd holds the only
	/// copy anything will remove**. Exactly one thing passes both.
	///
	/// A `WireGuard` private key is loaded into the kernel by netcfgd, is
	/// readable back verbatim by root, and its authority lives as a public key
	/// in the configuration of every peer -- machines the operator may not own
	/// and cannot reach. Revoking it is an act by each of them. Walking away
	/// leaves whoever ends up with the hardware able to be this host on that
	/// network, indefinitely.
	///
	/// The other secrets 0037 named do not pass, and saying why is the point of
	/// the rule rather than an aside:
	///
	/// - **A supplicant's passphrases** and **a running hostapd's generated
	///   configuration** are copies of material sitting in the secrets
	///   directory on the same disk, which neither `leave` nor `clear` touches.
	///   The choice cannot change that exposure, so refusing over it would be
	///   refusing over something the operator cannot fix by deciding.
	/// - **A WPA passphrase** is shared, and revoking it is one change at the
	///   access point -- which for a network netcfgd itself runs is one line of
	///   this document.
	/// - **An EAP client key** is asymmetric and genuinely hard to revoke, but
	///   netcfgd never holds it: the model carries a `SecretRef` and a path,
	///   and the file stays on disk whichever policy is chosen.
	///
	/// Nothing is dropped from the plan here. `managed = false` already means
	/// no actions for the device, so there is nothing to withhold -- what this
	/// produces is a decision the operator has not made, and an exit code that
	/// says so.
	fn plan_stranded_credentials(&mut self, observed: &Observed, consented: &[String]) {
		// Driven by the observation rather than the document, on purpose and
		// twice over. The kernel is what decides whether a key is really there
		// -- a document declaring one for an interface that was never applied
		// strands nothing, and a notice about that would be a notice about a
		// file. And a `WireGuard` interface whose block has been *deleted* while
		// its `device` block still says `managed = false` still has the key
		// loaded, which the document no longer mentions at all.
		//
		// It also means the rule has no second opinion about which links are
		// `WireGuard`. `private_key_loaded` is set in one place, for links the
		// kernel calls `wireguard` and no others; a `kind` check here would be
		// a branch no test could ever make fail, which this project does not
		// keep.
		for link in &observed.links {
			let name = &link.name;
			if !link.private_key_loaded {
				continue;
			}
			// Only a device the document is walking away from. `clear` removes
			// the link and the key with it, which is the answer this exists to
			// point at -- reporting it as well would be reporting a hazard the
			// operator has already dealt with.
			if !self.unmanaged.iter().any(|device| device == name)
				|| self.clearing.iter().any(|device| device == name)
			{
				continue;
			}
			if consented.iter().any(|device| device == name) {
				continue;
			}

			self.stranded.push(Stranded {
				interface: name.clone(),
				credential: format!(
					"a WireGuard private key, loaded in the kernel on `{name}` and readable \
					 there by root"
				),
				irrevocable: "its authority is the matching public key in every peer's \
					configuration, so withdrawing it means changing each of them -- netcfgd \
					cannot, and the machines may not be yours"
					.to_owned(),
				remove_with: format!(
					"device {name} {{ managed = false; on_unmanage = \"clear\" }}"
				),
				consent_with: format!("ncfg apply --strand-credentials {name}"),
			});
		}
	}

	/// Converge a running access point's station lists against the document.
	///
	/// Decision 0041. hostapd reads `deny_mac_file` once, at startup, so up to
	/// here an edited `access_control` block did nothing at all until somebody
	/// restarted the access point -- and restarting deauthenticates every client
	/// on the radio, which for a feature whose purpose is a smooth handoff is
	/// worse than the gap it closes.
	///
	/// Only for an access point that is **running and reachable**. One that is
	/// not has no in-memory list to converge: it reads the generated file when
	/// it starts, and that file is already the document.
	fn plan_access_control(&mut self, desired: &Document, observed: &Observed) {
		for access_point in &desired.access_points {
			let device = &access_point.device;
			let Some(live) = observed
				.backends
				.iter()
				.find(|backend| {
					backend.kind == BackendKind::AccessPoint
						&& &backend.interface == device
						&& backend.running
				})
				.and_then(|backend| backend.access_control.as_ref())
			else {
				continue;
			};

			let wanted = access_point.access_control.as_ref();
			let running = live.policy;
			let policy = match (running, wanted.map(|acl| acl.policy)) {
				// No record, so netcfgd does not know which list this hostapd
				// consults by default. Nothing may be converged from here:
				// under `deny` an empty accept list is nothing, and under
				// `allow` it is a network nobody can join. Converging against a
				// guess is how an access point ends up closed at three in the
				// morning.
				(netcfgd_model::ObservedPolicy::Unknown, _) => {
					self.warn(
						device,
						format!(
							"netcfgd has no record of which access control policy the access \
							 point running on {device} was started with, so its station list is \
							 left alone. Restarting it writes the record"
						),
					);
					continue;
				}
				// Running what the document asks for. This is the ordinary case
				// and the one the whole feature is for.
				(netcfgd_model::ObservedPolicy::Set(running), Some(policy))
					if running == policy =>
				{
					Some(policy)
				}
				(netcfgd_model::ObservedPolicy::Unset, None) => None,
				// Anything else is a policy change, which `macaddr_acl` cannot
				// take over the control socket -- and converging the lists
				// without it would enforce the new list under the old default.
				// A document changed from `deny` to `allow` would leave every
				// unlisted station accepted, reported as applied.
				_ => {
					self.restart_access_point(device, running, wanted.map(|acl| acl.policy));
					continue;
				}
			};

			// Both lists, always. hostapd's `hostapd_check_acl` consults the
			// accept list *first* and the deny list second, whatever
			// `macaddr_acl` says -- that value decides only what happens to an
			// address in neither. So a station left on the accept list overrides
			// the deny list that is supposed to be refusing it, and leaving the
			// unused list alone would be leaving the failure this feature exists
			// to remove.
			let stations = wanted.map_or(&[][..], |acl| acl.stations.as_slice());
			for list in [AclPolicy::Deny, AclPolicy::Allow] {
				let want: &[String] = if Some(list) == policy { stations } else { &[] };
				self.converge_list(device, list, want, live.list(list));
			}
		}
	}

	/// Add and remove until one of hostapd's lists holds what the document says.
	fn converge_list(&mut self, device: &str, list: AclPolicy, want: &[String], live: &[String]) {
		let field = "access_point.access_control.stations";

		for station in want.iter().filter(|station| !live.contains(station)) {
			self.push_root(
				Op::AccessControlAdd {
					iface: device.to_owned(),
					list,
					station: station.clone(),
				},
				Reason::absent(device, field, format!("{station} ({list:?})")),
				Some(Op::AccessControlDel {
					iface: device.to_owned(),
					list,
					station: station.clone(),
				}),
			);
		}
		for station in live.iter().filter(|station| !want.contains(station)) {
			self.push_root(
				Op::AccessControlDel {
					iface: device.to_owned(),
					list,
					station: station.clone(),
				},
				Reason::unwanted(device, field, format!("{station} ({list:?})")),
				Some(Op::AccessControlAdd {
					iface: device.to_owned(),
					list,
					station: station.clone(),
				}),
			);
		}
	}

	/// Restart an access point whose access control policy changed.
	///
	/// The one change to an `access_control` block that cannot be made in place.
	/// `macaddr_acl` is settable over the control socket, but nothing
	/// disassociates on the change and nothing reports it back, so netcfgd would
	/// be converging a value it could never confirm -- and the failure mode is
	/// an open network reported as a closed one.
	///
	/// Restarting is honest about its cost instead. It is also the only part of
	/// an access point's configuration anything notices changing today: an
	/// edited SSID or channel is still invisible to the planner, which is older
	/// and wider than this.
	fn restart_access_point(
		&mut self,
		device: &str,
		running: netcfgd_model::ObservedPolicy,
		wanted: Option<AclPolicy>,
	) {
		let render = |policy: Option<AclPolicy>| {
			policy.map_or_else(|| "<absent>".to_owned(), |policy| format!("{policy:?}"))
		};
		let observed = match running {
			netcfgd_model::ObservedPolicy::Set(policy) => format!("{policy:?}"),
			netcfgd_model::ObservedPolicy::Unset => "<absent>".to_owned(),
			netcfgd_model::ObservedPolicy::Unknown => "<unknown>".to_owned(),
		};
		let reason = Reason::differs(
			device,
			"access_point.access_control.policy",
			render(wanted),
			observed,
		);

		self.warn(
			device,
			format!(
				"the access control policy on {device} changed, which hostapd only reads at \
				 startup, so the access point is restarted -- every station associated with it \
				 is deauthenticated and reconnects. Changing the stations in a list does not \
				 cost this"
			),
		);

		let stop = self.push_root(
			Op::BackendStop {
				kind: BackendKind::AccessPoint,
				iface: device.to_owned(),
			},
			reason.clone(),
			Some(Op::BackendStart {
				kind: BackendKind::AccessPoint,
				iface: device.to_owned(),
			}),
		);
		// Refused by a guard, or dropped for an unmanaged device. Emitting the
		// start on its own would bring the access point up a second time rather
		// than back up, so there is nothing further to plan.
		if stop == u32::MAX {
			return;
		}
		self.push(
			Op::BackendStart {
				kind: BackendKind::AccessPoint,
				iface: device.to_owned(),
			},
			reason,
			vec![stop],
			Some(Op::BackendStop {
				kind: BackendKind::AccessPoint,
				iface: device.to_owned(),
			}),
		);
	}

	fn teardown_backends(&mut self, desired: &Document, observed: &Observed) {
		for backend in &observed.backends {
			if !backend.running {
				continue;
			}
			let (wanted, field) = self.backend_wanted(desired, backend);
			if wanted {
				continue;
			}
			self.push_root(
				Op::BackendStop {
					kind: backend.kind,
					iface: backend.interface.clone(),
				},
				Reason::unwanted(&backend.interface, field, format!("{:?}", backend.kind)),
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
			stranded: self.stranded,
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

/// A route with the interface's preference filled in as its metric.
///
/// Resolved here rather than at compile time so the document stays a literal
/// reading of the config -- `ncfg show` reports what was written, and the plan
/// reports what it means. It also has to happen in exactly one place, because
/// the comparison that decides "is this route already present" uses the metric
/// and would loop forever against a value computed differently on each side.
fn with_metric(route: &Route, preference: Option<u32>) -> Route {
	if route.metric.is_some() {
		return route.clone();
	}
	Route {
		metric: preference,
		..route.clone()
	}
}

/// A VLAN as the config spells it, for a plan's reason line.
fn render_vlan(vlan: netcfgd_model::BridgeVlan) -> String {
	let mut out = vlan.vid.to_string();
	if vlan.pvid {
		out.push_str(" pvid");
	}
	if vlan.untagged {
		out.push_str(" untagged");
	}
	out
}

/// Whether one kernel feature name is currently on.
fn held_on(link: &netcfgd_model::ObservedLink, name: &str) -> bool {
	link.offloads.iter().any(|held| held == name)
}

/// Whether a desired rule and an observed one are the same rule.
///
/// Every selector, not just the key. Two rules at the same priority that
/// differ in `from` are different rules, and treating them as equal is how a
/// changed selector silently never takes effect.
fn same_rule(desired: &RoutingRule, observed: &netcfgd_model::ObservedRule) -> bool {
	desired.from == observed.from
		&& desired.to == observed.to
		&& desired.iif == observed.iif
		&& desired.oif == observed.oif
		&& desired.fwmark == observed.fwmark
		&& desired.fwmask == observed.fwmask
		&& desired.action == observed.action
		&& desired.suppress_prefixlength == observed.suppress_prefixlength
		&& desired.l3mdev == observed.l3mdev
		&& desired.invert == observed.invert
		// A lookup names a table; the other actions do not, and the kernel
		// reports `None` for them whatever the document says.
		&& (desired.action != netcfgd_model::RuleAction::Lookup || desired.table == observed.table)
}

/// An observed rule as a desired one, for the ops that carry a rule.
///
/// The `id` is netcfgd's handle and has no kernel counterpart, so a rule that
/// came back from a dump gets one describing where it came from rather than a
/// fabricated name that might collide with a real one.
fn to_desired(observed: &netcfgd_model::ObservedRule) -> RoutingRule {
	RoutingRule {
		id: format!("observed-{:?}-{}", observed.family, observed.priority),
		priority: observed.priority,
		family: observed.family,
		from: observed.from.clone(),
		to: observed.to.clone(),
		iif: observed.iif.clone(),
		oif: observed.oif.clone(),
		fwmark: observed.fwmark,
		fwmask: observed.fwmask,
		table: observed.table,
		action: observed.action,
		suppress_prefixlength: observed.suppress_prefixlength,
		l3mdev: observed.l3mdev,
		invert: observed.invert,
	}
}

/// One rule, for a plan line.
fn describe(rule: &RoutingRule) -> String {
	let mut out = format!("{} ", rule.priority);
	for (label, value) in [
		("from", rule.from.as_deref()),
		("to", rule.to.as_deref()),
		("iif", rule.iif.as_deref()),
		("oif", rule.oif.as_deref()),
	] {
		if let Some(value) = value {
			out.push_str(&format!("{label} {value} "));
		}
	}
	if let Some(mark) = rule.fwmark {
		out.push_str(&format!("fwmark {mark:#x} "));
	}
	out.push_str(rule.action.name());
	if let Some(table) = rule.table {
		out.push_str(&format!(" {table}"));
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
		InterfaceKind::Vrf(_) => "vrf",
		InterfaceKind::Macvlan(_) => "macvlan",
		InterfaceKind::Tunnel(tunnel) => tunnel.mode.name(),
		InterfaceKind::Tun(_) => "tun",
		InterfaceKind::Ifb => "ifb",
	}
}
