//! The fixture harness project.md section 5 asks to be built first.
//!
//! Fixture config text plus a fake observed snapshot, asserting on the action
//! list. No hardware, no filesystem, no netlink. Every fixture also goes
//! through [`settle`], which simulates applying the plan and re-plans -- that
//! is the plan-idempotence gate from section 6, and it is the check that
//! catches an action which does not actually converge.

use netcfgd_compile::{compile, NoHooks, SourceMap};
use netcfgd_model::{
	AppliedDns, BackendKind, Document, Observed, ObservedAddress, ObservedBackend, ObservedLink,
	ObservedRoute, Origin, Ownership,
};
use netcfgd_plan::{plan, Op, Plan, PlanOptions};

/// Compile fixture text into a document.
fn document(text: &str) -> Document {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	match compile(&sources, &mut NoHooks) {
		Ok(document) => document,
		Err(diagnostics) => panic!("fixture did not compile:\n{}", diagnostics.render(&sources)),
	}
}

/// A link that exists and is down, which is what a fresh boot looks like.
fn link(name: &str) -> ObservedLink {
	ObservedLink {
		name: name.to_owned(),
		index: 2,
		kind: String::new(),
		up: false,
		carrier: true,
		mtu: 1500,
		mac: None,
		master: None,
		qdisc: Some("noqueue".to_owned()),
		qdisc_bandwidth_bits: None,
		forwarding: None,
		ownership: Ownership::Unknown,
	}
}

fn with_delegation(links: &[&str], interface: &str, prefixes: &[&str]) -> Observed {
	let mut observed = observed_with(links);
	observed.delegations.push(netcfgd_model::Delegation {
		interface: interface.to_owned(),
		prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
	});
	observed
}

fn observed_with(links: &[&str]) -> Observed {
	Observed {
		links: links.iter().map(|name| link(name)).collect(),
		..Observed::default()
	}
}

fn names(plan: &Plan) -> Vec<&'static str> {
	plan.actions.iter().map(|a| a.op.name()).collect()
}

fn position(plan: &Plan, name: &str) -> usize {
	plan.actions
		.iter()
		.position(|a| a.op.name() == name)
		.unwrap_or_else(|| panic!("no {name} in plan: {:?}", names(plan)))
}

/// Apply a plan to an observed snapshot, as faithfully as a fake can.
///
/// This is the executor the idempotence gate needs. It deliberately models
/// what the kernel would end up in rather than what the action says it does --
/// an `addr.add` produces an address tagged as ours and originating from
/// config, because that is what a real apply would leave behind, and getting
/// that wrong is how a plan converges in the fake and loops on real hardware.
/// The VLAN half of [`simulate`], split out only because one match arm per op
/// had grown past what the style allows.
fn simulate_vlan(op: &Op, observed: &mut Observed) {
	let (iface, vid) = match op {
		Op::BridgeVlanAdd { iface, vid, .. } | Op::BridgeVlanDel { iface, vid, .. } => {
			(iface, *vid)
		}
		_ => return,
	};
	let Some(index) = observed
		.links
		.iter()
		.find(|link| &link.name == iface)
		.map(|link| link.index)
	else {
		return;
	};
	// Removed first in both cases: adding a VLAN that is already present with
	// different flags is how the kernel changes them, and a fake that appended
	// would report two.
	observed
		.bridge_vlans
		.retain(|vlan| !(vlan.index == index && vlan.vid == vid));

	if let Op::BridgeVlanAdd { pvid, untagged, .. } = op {
		observed
			.bridge_vlans
			.push(netcfgd_model::ObservedBridgeVlan {
				index,
				vid,
				pvid: *pvid,
				untagged: *untagged,
			});
	}
}

/// The qdisc half of [`simulate`], split out for the same reason as the VLAN
/// half: one match arm per op had grown past what the style allows.
fn simulate_qdisc(op: &Op, observed: &mut Observed) {
	let (Op::QdiscSet { iface, .. } | Op::QdiscReset { iface }) = op else {
		return;
	};
	// The kernel puts its default back on a reset, which for the fake link
	// here is `noqueue`. Modelling that as "no qdisc at all" would let a
	// planner bug that never converges look like it converged.
	let (kind, rate) = match op {
		Op::QdiscSet {
			kind,
			bandwidth_bits,
			..
		} => (kind.clone(), *bandwidth_bits),
		_ => ("noqueue".to_owned(), None),
	};

	if let Some(link) = observed.links.iter_mut().find(|l| &l.name == iface) {
		link.qdisc = Some(kind);
		link.qdisc_bandwidth_bits = rate;
	}

	observed.qdisc_applied.retain(|name| name != iface);
	if matches!(op, Op::QdiscSet { .. }) {
		observed.qdisc_applied.push(iface.clone());
	}
}

fn simulate(plan: &Plan, observed: &mut Observed) {
	for action in &plan.actions {
		match &action.op {
			Op::LinkCreate { name, .. } => {
				let mut created = link(name);
				created.ownership = Ownership::Ours;
				observed.links.push(created);
			}
			Op::LinkDelete { name } => {
				observed.links.retain(|link| &link.name != name);
				observed.addresses.retain(|a| &a.interface != name);
				observed.routes.retain(|r| &r.interface != name);
			}
			Op::LinkSetMtu { name, mtu } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.mtu = *mtu;
				}
			}
			Op::LinkSetMac { name, mac } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.mac = Some(mac.clone());
				}
			}
			Op::LinkSetMaster { name, master } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.master = Some(master.clone());
				}
			}
			Op::LinkUnsetMaster { name } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.master = None;
				}
			}
			Op::LinkUp { name } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.up = true;
				}
			}
			Op::LinkDown { name } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) {
					link.up = false;
				}
			}
			Op::AddrAdd { iface, addr, .. } => observed.addresses.push(ObservedAddress {
				interface: iface.clone(),
				address: addr.clone(),
				proto: Some(netcfgd_model::route::NETCFGD_PROTO),
				ownership: Ownership::Ours,
				origin: Some(Origin::Static),
			}),
			Op::AddrDel { iface, addr } => observed
				.addresses
				.retain(|a| !(&a.interface == iface && &a.address == addr)),
			Op::RouteAdd { iface, route } => observed.routes.push(ObservedRoute {
				interface: iface.clone(),
				destination: route.destination.clone(),
				via: route.via,
				metric: route.metric,
				// The kernel reports a table on every route, defaulting an
				// unqualified one to main. Copying the desired value through
				// is what let a real idempotence bug past this harness.
				table: Some(route.table.unwrap_or(netcfgd_model::route::MAIN_TABLE)),
				src: route.src,
				scope: route.scope,
				proto: Some(netcfgd_model::route::NETCFGD_PROTO),
				ownership: Ownership::Ours,
				origin: Some(Origin::Static),
			}),
			Op::RouteDel { iface, route } => observed.routes.retain(|r| {
				!(&r.interface == iface && r.destination == route.destination && r.via == route.via)
			}),
			Op::BackendStart { kind, iface } => observed.backends.push(ObservedBackend {
				kind: *kind,
				interface: iface.clone(),
				running: true,
			}),
			Op::BackendStop { kind, iface } => observed
				.backends
				.retain(|b| !(b.kind == *kind && &b.interface == iface)),
			Op::DnsApply { scope, policy } => {
				observed.dns.retain(|applied| &applied.scope != scope);
				observed.dns.push(AppliedDns {
					scope: scope.clone(),
					policy: (**policy).clone(),
				});
			}
			Op::QdiscSet { .. } | Op::QdiscReset { .. } => {
				simulate_qdisc(&action.op, observed);
			}
			Op::SysctlSetForwarding { iface, enabled } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == iface) {
					link.forwarding = Some(*enabled);
				}
			}
			// Whole-table replacement, so the observed list becomes the
			// requested one rather than accumulating -- which is the point of
			// the op and the thing that has to be true for the gate to mean
			// anything.
			Op::NatReplace { uplinks } => observed.nat.clone_from(uplinks),
			// Hooks and commit actions leave no observable state of their own.
			Op::BridgeVlanAdd { .. } | Op::BridgeVlanDel { .. } => {
				simulate_vlan(&action.op, observed);
			}
			_ => {}
		}
	}
	observed.canonicalize();
}

/// Plan, apply, re-plan. Returns the first plan, and asserts the second is
/// empty.
fn settle(desired: &Document, observed: &mut Observed) -> Plan {
	let first = plan(desired, observed, &PlanOptions::default());
	simulate(&first, observed);
	let second = plan(desired, observed, &PlanOptions::default());
	assert!(
		second.is_empty(),
		"applying the plan twice was not a no-op; the second plan was {:?}",
		names(&second)
	);
	first
}

/// The walking-skeleton case, end to end from config text.
#[test]
fn a_static_interface_is_brought_up_in_order() {
	let desired = document(
		r#"
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
			mtu    = 9000
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	assert_eq!(
		names(&plan),
		["link.set_mtu", "link.up", "addr.add", "route.add"]
	);
}

/// An already-correct system produces an empty plan. Section 4 calls this the
/// normal case, and it is what makes running apply on a timer harmless.
#[test]
fn an_already_correct_system_produces_no_actions() {
	let desired = document("interface eth0 { config = \"192.168.1.10/24\" }");
	let mut observed = observed_with(&["eth0"]);
	settle(&desired, &mut observed);

	let again = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		again.is_empty(),
		"expected nothing to do: {:?}",
		names(&again)
	);
	assert!(again.warnings.is_empty());
}

/// Rule 4: a route whose next hop lies in an address's subnet waits for that
/// address.
#[test]
fn a_route_waits_for_the_address_that_covers_its_gateway() {
	let desired = document(
		r#"
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	let addr = &plan.actions[position(&plan, "addr.add")];
	let route = &plan.actions[position(&plan, "route.add")];
	assert!(
		route.depends_on.contains(&addr.id),
		"route should depend on the covering address: {:?}",
		route.depends_on
	);
}

/// And a gateway outside every configured subnet gets no such edge, because
/// serialising work that need not be serialised is a cost with no payoff.
#[test]
fn a_route_outside_the_subnet_does_not_wait_for_the_address() {
	let desired = document(
		r#"
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "10.0.0.0/8 via 172.16.0.1 onlink"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	let addr = &plan.actions[position(&plan, "addr.add")];
	let route = &plan.actions[position(&plan, "route.add")];
	assert!(!route.depends_on.contains(&addr.id));
}

/// Rule 3: a lease needs a live link, so the DHCP backend waits for link.up --
/// but an address does not, because an address may be added to a down link.
#[test]
fn dhcp_waits_for_the_link_but_a_static_address_does_not() {
	let desired = document("interface eth0 { config = \"192.168.1.10/24\ndhcp\" }");
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	let up = &plan.actions[position(&plan, "link.up")];
	let addr = &plan.actions[position(&plan, "addr.add")];
	let backend = &plan.actions[position(&plan, "backend.start")];

	assert!(
		backend.depends_on.contains(&up.id),
		"dhcp must wait for the link"
	);
	assert!(
		!addr.depends_on.contains(&up.id),
		"an address may be added to a down link"
	);
}

/// Rule 2: the master waits for its members' enslavement, even though the
/// master sorts first and is therefore planned first.
#[test]
fn a_bridge_waits_for_its_members_even_though_it_sorts_first() {
	let desired = document(
		r#"
		interface br0 {
			bridge { members = "eth0" }
			config = "10.0.0.1/24"
		}
		interface eth0 {
			master = "br0"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	// br0 sorts before eth0, so a single pass would have planned the bridge's
	// address before the enslavement existed to depend on.
	assert!(desired.interfaces[0].name == "br0");

	let enslave = &plan.actions[position(&plan, "link.set_master")];
	let up = &plan.actions[position(&plan, "link.up")];
	let addr = &plan.actions[position(&plan, "addr.add")];
	assert!(
		addr.depends_on.contains(&enslave.id),
		"addressing the master must wait for enslavement: {:?}",
		addr.depends_on
	);
	assert!(
		up.depends_on.contains(&enslave.id),
		"bringing the master up must wait for enslavement: {:?}",
		up.depends_on
	);
}

/// Rule 1: a link that has to be created gates everything else on it.
#[test]
fn everything_on_a_created_link_waits_for_its_creation() {
	let desired = document(
		r#"
		interface lan10 {
			vlan   { parent = "eth0"; id = 10 }
			config = "10.0.10.1/24"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	let create = &plan.actions[position(&plan, "link.create")];
	assert_eq!(create.id, 0);
	for action in &plan.actions[1..] {
		assert!(
			action.depends_on.contains(&create.id),
			"{} should wait for link.create: {:?}",
			action.op.name(),
			action.depends_on
		);
	}
}

/// Rule 6: `pre_up` before `link.up`, `post_up` after the last addressing action.
#[test]
fn hooks_bracket_the_interface_lifecycle() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig = \"192.168.1.10/24\"\n\
		 \tpre_up {\necho before\n}\n\
		 \tpost_up {\necho after\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");

	let mut observed = observed_with(&["eth0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());
	simulate(&plan, &mut observed);

	let hooks: Vec<usize> = plan
		.actions
		.iter()
		.enumerate()
		.filter(|(_, a)| a.op.name() == "hook.run")
		.map(|(index, _)| index)
		.collect();
	assert_eq!(hooks.len(), 2);

	let up = &plan.actions[position(&plan, "link.up")];
	let addr = &plan.actions[position(&plan, "addr.add")];
	let pre = &plan.actions[hooks[0]];
	let post = &plan.actions[hooks[1]];

	assert!(
		up.depends_on.contains(&pre.id),
		"link.up must wait for pre_up"
	);
	assert!(
		post.depends_on.contains(&addr.id),
		"post_up must wait for the last addressing action"
	);
}

/// A hook has no inverse, and the plan says so loudly rather than pretending
/// commit-confirm can undo arbitrary shell.
#[test]
fn a_hook_is_irreversible_and_warned_about() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n\tpost_up {\necho hi\n}\n}\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let observed = observed_with(&["eth0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert_eq!(plan.irreversible().count(), 1);
	assert!(plan
		.warnings
		.iter()
		.any(|w| w.message.contains("cannot be undone")));
}

/// Rule 8: the confirm window is armed first, and the revert is computed at
/// plan time rather than after a failure.
#[test]
fn commit_arm_comes_first_and_carries_its_revert() {
	let desired = document("interface eth0 { config = \"10.0.0.1/24\" }");
	let observed = observed_with(&["eth0"]);
	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			confirm_window: Some(120),
			revert_to: Some("abc123".to_owned()),
			..PlanOptions::default()
		},
	);

	assert_eq!(plan.actions[0].op.name(), "commit.arm");
	assert!(matches!(
		plan.actions[0].inverse,
		Some(Op::CommitRevert { .. })
	));
}

/// The safety property that outranks everything else: a foreign object is
/// reported, never reconciled away. Over-claiming ownership deletes somebody's
/// manual change.
#[test]
fn a_foreign_address_is_never_removed() {
	let desired = document("interface eth0 { config = \"10.0.0.1/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.168.99.1/24".to_owned(),
		proto: Some(4),
		ownership: Ownership::Foreign,
		origin: Some(Origin::Static),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"addr.del"),
		"a foreign address must survive: {:?}",
		names(&plan)
	);
}

/// An address whose ownership the kernel could not report is treated as
/// foreign. On a pre-5.18 kernel that is most of them, and deleting on a
/// guess is the one mistake that cannot be walked back.
#[test]
fn an_address_of_unknown_ownership_is_never_removed() {
	let desired = document("interface eth0 { config = \"10.0.0.1/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.address_proto_supported = false;
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.168.99.1/24".to_owned(),
		proto: None,
		ownership: Ownership::Unknown,
		origin: Some(Origin::Static),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(!names(&plan).contains(&"addr.del"));
}

/// Ours, and no longer wanted, does come out.
#[test]
fn an_address_we_installed_and_no_longer_want_is_removed() {
	let desired = document("interface eth0 { config = \"10.0.0.1/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "10.0.0.99/24".to_owned(),
		proto: Some(netcfgd_model::route::NETCFGD_PROTO),
		ownership: Ownership::Ours,
		origin: Some(Origin::Static),
	});

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"addr.del"));

	// Make-before-break: the new address is in place before the old one goes.
	assert!(position(&plan, "addr.add") < position(&plan, "addr.del"));
}

/// Decision 0006 rule 7: a lease's address belongs to the backend. Removing it
/// here would fight the DHCP client for its own lease.
#[test]
fn a_lease_address_is_left_to_its_backend() {
	let desired = document("interface eth0 { config = \"dhcp\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Dhcp4,
		interface: "eth0".to_owned(),
		running: true,
	});
	// The lease produced this, and it is tagged as ours.
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.168.1.57/24".to_owned(),
		proto: Some(netcfgd_model::route::NETCFGD_PROTO),
		ownership: Ownership::Ours,
		origin: Some(Origin::Dhcp4),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.is_empty(),
		"nothing should be planned against a live lease: {:?}",
		names(&plan)
	);
}

/// Dropping DHCP from the config stops the backend.
#[test]
fn removing_dhcp_stops_the_backend() {
	let desired = document("interface eth0 { config = \"10.0.0.1/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Dhcp4,
		interface: "eth0".to_owned(),
		running: true,
	});

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"backend.stop"));
}

/// DNS is planned from the scope, and is idempotent because the observed model
/// records what was last delivered.
#[test]
fn dns_is_applied_once_and_then_left_alone() {
	let desired = document(
		r#"
		interface eth0 {
			config   = "10.0.0.2/24"
			dns      = "10.0.0.1"
			dns_mode = "openresolv"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"dns.apply"));
}

/// A configured device that is not plugged in cannot be fixed by a plan, so
/// the plan says so instead of emitting actions that must fail.
#[test]
fn a_missing_physical_device_is_reported_not_planned_around() {
	let desired = document("interface eth9 { config = \"10.0.0.1/24\" }");
	let observed = Observed::default();

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.is_empty(), "{:?}", names(&plan));
	assert!(plan
		.warnings
		.iter()
		.any(|w| w.message.contains("no such device")));
}

/// Every action's dependencies point at actions that come earlier in the list,
/// so an executor that ignores the edges entirely still behaves correctly.
#[test]
fn the_action_list_is_a_valid_topological_order() {
	let desired = document(
		r#"
		interface br0 {
			bridge { members = "eth0 eth1" }
			config = "10.0.0.1/24"
			routes = "default via 10.0.0.254"
		}
		interface eth0 { master = "br0" }
		interface eth1 { master = "br0" }
		interface wan0 { config = "dhcp"; mtu = 1492 }
		"#,
	);
	let mut observed = observed_with(&["eth0", "eth1", "wan0"]);
	let plan = settle(&desired, &mut observed);

	for (index, action) in plan.actions.iter().enumerate() {
		for dependency in &action.depends_on {
			let position = plan
				.actions
				.iter()
				.position(|a| a.id == *dependency)
				.expect("dependency exists");
			assert!(
				position < index,
				"{} at {index} depends on {dependency} at {position}",
				action.op.name()
			);
		}
	}
}

/// Every action carries a reason naming a field and both values, because an
/// action list without reasons is a black box with extra steps.
#[test]
fn every_action_explains_itself() {
	let desired = document(
		r#"
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
			mtu    = 9000
		}
		"#,
	);
	let observed = observed_with(&["eth0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert!(!plan.actions.is_empty());
	for action in &plan.actions {
		assert!(!action.reason.field.is_empty(), "{:?}", action.op.name());
		assert!(!action.reason.desired.is_empty());
		assert!(!action.reason.observed.is_empty());
	}
}

/// A hook sink for fixtures that need hooks in the document.
struct TestHooks;

impl netcfgd_compile::HookSink for TestHooks {
	fn materialise(
		&mut self,
		phase: netcfgd_model::HookPhase,
		owner: &str,
		_body: &str,
	) -> Result<netcfgd_model::HookRef, String> {
		Ok(netcfgd_model::HookRef {
			phase,
			path: format!("/run/netcfgd/hooks/{owner}.{phase:?}"),
			sha256: "0".repeat(64),
			run_as: None,
			timeout: None,
		})
	}
}

/// Decision 0010: a guarded interface refuses disruptive actions, and says so
/// in the plan rather than at apply time. A plan that lies is worse than no
/// plan.
#[test]
fn a_guard_refuses_a_disruptive_action_at_plan_time() {
	// The config no longer wants the address, so teardown would remove it --
	// which is exactly what breaks an NFS mount on that interface.
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.1/24"
			guard  = "nfs root"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "10.0.0.99/24".to_owned(),
		proto: Some(netcfgd_model::route::NETCFGD_PROTO),
		ownership: Ownership::Ours,
		origin: Some(Origin::Static),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert!(
		!names(&plan).contains(&"addr.del"),
		"a guarded interface must not be disrupted: {:?}",
		names(&plan)
	);
	assert_eq!(plan.refusals.len(), 1);
	let refusal = &plan.refusals[0];
	assert_eq!(refusal.op, "addr.del");
	assert_eq!(refusal.guard, "nfs root");
	assert_eq!(refusal.override_with, "ncfg apply --allow-disruption eth0");
}

/// The guard blocks only what can interrupt traffic. Adding an address to a
/// guarded interface is safe and still happens, or a guard would freeze the
/// interface entirely.
#[test]
fn a_guard_does_not_block_additive_work() {
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.1/24
10.0.0.2/24"
			guard  = "nfs root"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(
		names(&plan),
		["addr.add", "addr.add"],
		"additive work must survive a guard"
	);
	assert!(plan.refusals.is_empty());
}

/// Consent is per interface, and it unblocks exactly that one.
#[test]
fn consent_unblocks_the_named_interface_and_no_other() {
	let desired = document(
		r#"
		interface eth0 { config = "10.0.0.1/24"; guard = "nfs root" }
		interface eth1 { config = "10.0.1.1/24"; guard = "database replication" }
		"#,
	);
	let mut observed = observed_with(&["eth0", "eth1"]);
	observed.links[0].up = true;
	observed.links[1].up = true;
	for (interface, address) in [("eth0", "10.0.0.99/24"), ("eth1", "10.0.1.99/24")] {
		observed.addresses.push(ObservedAddress {
			interface: interface.to_owned(),
			address: address.to_owned(),
			proto: Some(netcfgd_model::route::NETCFGD_PROTO),
			ownership: Ownership::Ours,
			origin: Some(Origin::Static),
		});
	}

	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			allow_disruption: vec!["eth0".to_owned()],
			..PlanOptions::default()
		},
	);

	// eth0's stale address goes; eth1's is still protected.
	let removed: Vec<&str> = plan
		.actions
		.iter()
		.filter(|a| a.op.name() == "addr.del")
		.filter_map(|a| a.op.interface())
		.collect();
	assert_eq!(removed, ["eth0"]);
	assert_eq!(plan.refusals.len(), 1);
	assert_eq!(plan.refusals[0].interface, "eth1");
}

/// The case that motivated this: an interface dropped from the config is not
/// torn down while something depends on it.
#[test]
fn a_guarded_interface_is_not_torn_down_when_it_leaves_the_config() {
	// The bridge netcfgd created is gone from the config, so teardown would
	// delete it.
	let desired = document("interface eth0 { config = \"10.0.0.1/24\"; guard = \"nfs root\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.links[0].ownership = Ownership::Ours;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(!names(&plan).contains(&"link.delete"));
}

/// A radio carries nothing until it has associated, so the supplicant is a
/// prerequisite in the same way 802.1X is -- and gets the same position in the
/// order.
#[test]
fn a_managed_radio_gets_a_supplicant_before_addressing() {
	let document = document(
		r#"
device wlan0 { wifi { backend = "wpa_supplicant" } }
network "Home" { wifi { psk = "@secret:home" }; config = "dhcp" }
interface wlan0 { config = "dhcp" }
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	let plan = plan(&document, &observed, &PlanOptions::default());

	assert!(
		position(&plan, "link.up") < position(&plan, "backend.start"),
		"a radio has to be up before a supplicant can use it: {:?}",
		names(&plan)
	);

	// Two backends: the supplicant and the DHCP client. The DHCP one has to
	// wait -- a client started before association spends its whole backoff
	// talking to nothing.
	let starts: Vec<&str> = plan
		.actions
		.iter()
		.filter(|action| action.op.name() == "backend.start")
		.map(|action| action.reason.field.as_str())
		.collect();
	assert_eq!(starts.len(), 2, "got {starts:?}");
	assert!(
		starts.contains(&"wifi"),
		"the reason names the device block: {starts:?}"
	);

	settle(&document, &mut observed);
}

/// A radio with no networks to join gets no supplicant. Starting one that
/// would be handed nothing is a process running for no reason, and it makes
/// `ncfg status` report a backend nothing asked for.
#[test]
fn a_radio_with_no_networks_gets_no_supplicant() {
	let document = document(
		r#"
device wlan0 { wifi { backend = "wpa_supplicant" } }
interface wlan0 { config = "null" }
"#,
	);
	let plan = plan(
		&document,
		&observed_with(&["wlan0"]),
		&PlanOptions::default(),
	);
	assert!(
		!names(&plan).contains(&"backend.start"),
		"got {:?}",
		names(&plan)
	);
}

/// An unmanaged device is one netcfgd never touches, and that has to include
/// not starting a supplicant on it.
#[test]
fn an_unmanaged_radio_gets_no_supplicant() {
	let document = document(
		r#"
device wlan0 { managed = false; wifi { backend = "wpa_supplicant" } }
network "Home" { wifi { psk = "@secret:home" }; config = "dhcp" }
interface wlan0 { config = "null" }
"#,
	);
	let plan = plan(
		&document,
		&observed_with(&["wlan0"]),
		&PlanOptions::default(),
	);
	assert!(
		!names(&plan).contains(&"backend.start"),
		"got {:?}",
		names(&plan)
	);
}

/// The wired half of the same property. `tests/live/dot1x.sh` runs apply once
/// and would not have noticed a supplicant that gets stopped on the next
/// reconcile; the idempotence gate is what notices.
#[test]
fn a_dot1x_port_keeps_its_supplicant_across_reconciles() {
	let document = document(
		r#"
interface eth0 {
	dot1x { eap = "peap"; identity = "dave"; password = "@secret:corp"; ca_cert = "/ca.pem" }
	config = "dhcp"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		names(&plan).contains(&"backend.start"),
		"{:?}",
		names(&plan)
	);

	settle(&document, &mut observed);
}

/// And when the document stops asking, the supplicant does get stopped. A
/// backend nothing wants that keeps running is the other half of the same
/// mistake, and fixing the first one is how you introduce the second.
#[test]
fn removing_dot1x_stops_the_supplicant() {
	let mut observed = observed_with(&["eth0"]);
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Supplicant,
		interface: "eth0".to_owned(),
		running: true,
	});

	let document = document(r#"interface eth0 { config = "null" }"#);
	let plan = plan(&document, &observed, &PlanOptions::default());

	assert!(names(&plan).contains(&"backend.stop"), "{:?}", names(&plan));
	let stop = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "backend.stop")
		.expect("a stop");
	assert_eq!(
		stop.reason.field, "wifi/dot1x",
		"a supplicant stopped for `addressing` sends the reader to the wrong block"
	);
}

/// The M4 freeze put three features in the schema that nothing implements.
/// The failure mode to guard against is not that they do nothing -- that is
/// intended -- but that they do nothing *silently*, so a plan reports "one
/// action" about a config that asked for four things.
#[test]
fn recognised_but_unimplemented_features_are_named_in_the_plan() {
	let document = document(
		r#"
rule vpn { priority = 100; fwmark = 1; lookup = 42 }

access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
}

interface eth0 {
	ipv6_token = "::5"
	ethtool { gro = "off" }
	config = "null"
}
"#,
	);
	let plan = plan(
		&document,
		&observed_with(&["eth0"]),
		&PlanOptions::default(),
	);
	let warnings: Vec<&str> = plan
		.warnings
		.iter()
		.map(|warning| warning.message.as_str())
		.collect();

	for expected in [
		"access point `guest`",
		"ethtool",
		"ipv6_token",
		"policy routing rule",
	] {
		assert!(
			warnings.iter().any(|message| message.contains(expected)),
			"nothing warned about {expected}: {warnings:?}"
		);
	}

	// And each says which interface it concerns, where it concerns one -- a
	// warning about `ethtool` on a host with twelve interfaces is not useful
	// without the name.
	let ethtool = plan
		.warnings
		.iter()
		.find(|warning| warning.message.contains("ethtool"))
		.expect("an ethtool warning");
	assert_eq!(ethtool.interface.as_deref(), Some("eth0"));
}

/// A document that asks for none of them warns about none of them. A gate that
/// always fires is one people learn to scroll past.
#[test]
fn a_document_using_none_of_them_gets_no_such_warnings() {
	let document = document(r#"interface eth0 { config = "dhcp" }"#);
	let plan = plan(
		&document,
		&observed_with(&["eth0"]),
		&PlanOptions::default(),
	);
	for unwanted in ["ethtool", "ipv6_token", "policy routing", "access point"] {
		assert!(
			!plan
				.warnings
				.iter()
				.any(|warning| warning.message.contains(unwanted)),
			"warned about {unwanted} for a config that does not mention it"
		);
	}
}

/// Decision 0009: the document holds a reference and the plan holds the value.
/// Until the lease arrives there is nothing to plan and the operator is told
/// what is being waited for -- the config is right, the answer is "later".
#[test]
fn a_delegated_address_waits_for_its_lease() {
	let document = document(
		r#"
interface wan0  { config = "dhcp6" }
interface br-lan { config = "@pd:wan0=::1/64" }
"#,
	);
	let plan = plan(
		&document,
		&observed_with(&["wan0", "br-lan"]),
		&PlanOptions::default(),
	);

	assert!(
		!names(&plan).contains(&"addr.add"),
		"nothing can be addressed before the prefix is known: {:?}",
		names(&plan)
	);
	assert!(
		plan.warnings.iter().any(|warning| warning
			.message
			.contains("waiting on a delegated prefix from wan0")),
		"got {:?}",
		plan.warnings
	);
}

/// And once it has arrived, the address is planned exactly as a static one.
#[test]
fn a_delegated_address_resolves_once_the_lease_arrives() {
	let document = document(
		r#"
interface wan0   { config = "dhcp6" }
interface br-lan { config = "@pd:wan0=::1/64" }
"#,
	);
	let mut observed = with_delegation(&["wan0", "br-lan"], "wan0", &["2001:db8:1234::/56"]);
	let plan = plan(&document, &observed, &PlanOptions::default());

	let added: Vec<&str> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::AddrAdd { iface, addr, .. } if iface == "br-lan" => Some(addr.as_str()),
			_ => None,
		})
		.collect();
	assert_eq!(added, ["2001:db8:1234::1/64"]);

	// The reason names where the prefix came from, because "why does this
	// interface have this address" is unanswerable otherwise.
	let reason = plan
		.actions
		.iter()
		.find(|action| matches!(&action.op, Op::AddrAdd { iface, .. } if iface == "br-lan"))
		.expect("an add")
		.reason
		.desired
		.clone();
	assert!(reason.contains("from wan0"), "got: {reason}");

	settle(&document, &mut observed);
}

/// Two LANs off one delegation, which is what `subnet` is for.
#[test]
fn several_interfaces_share_one_delegation() {
	let document = document(
		r#"
interface wan0  { config = "dhcp6" }
interface lan-a { config = "@pd:wan0/0=::1/64" }
interface lan-b { config = "@pd:wan0/1=::1/64" }
"#,
	);
	let mut observed =
		with_delegation(&["wan0", "lan-a", "lan-b"], "wan0", &["2001:db8:1234::/56"]);
	let plan = plan(&document, &observed, &PlanOptions::default());

	let mut added: Vec<(&str, &str)> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::AddrAdd { iface, addr, .. } => Some((iface.as_str(), addr.as_str())),
			_ => None,
		})
		.collect();
	added.sort_unstable();
	assert_eq!(
		added,
		[
			("lan-a", "2001:db8:1234::1/64"),
			("lan-b", "2001:db8:1234:1::1/64"),
		]
	);

	settle(&document, &mut observed);
}

/// Renumbering. Decision 0009 wants this to be an ordinary diff rather than a
/// special case: the ISP changes the delegation, and every derived address
/// follows through the same `addr.del` then `addr.add` any other change uses.
#[test]
fn renumbering_is_an_ordinary_diff() {
	let document = document(
		r#"
interface wan0   { config = "dhcp6" }
interface br-lan { config = "@pd:wan0=::1/64" }
"#,
	);

	// Converge on the first delegation.
	let mut observed = with_delegation(&["wan0", "br-lan"], "wan0", &["2001:db8:1111::/56"]);
	let first = plan(&document, &observed, &PlanOptions::default());
	simulate(&first, &mut observed);
	assert!(observed
		.addresses_on("br-lan")
		.any(|address| address.address == "2001:db8:1111::1/64"));

	// The ISP renumbers.
	observed.delegations[0].prefixes = vec!["2001:db8:2222::/56".to_owned()];
	let second = plan(&document, &observed, &PlanOptions::default());

	let ops: Vec<&str> = second
		.actions
		.iter()
		.filter(|action| action.op.interface() == Some("br-lan"))
		.map(|action| action.op.name())
		.collect();
	assert!(ops.contains(&"addr.add"), "got {ops:?}");
	assert!(
		ops.contains(&"addr.del"),
		"the old address is no longer wanted and must go: {ops:?}"
	);

	simulate(&second, &mut observed);
	let remaining: Vec<&str> = observed
		.addresses_on("br-lan")
		.map(|address| address.address.as_str())
		.collect();
	assert_eq!(remaining, ["2001:db8:2222::1/64"]);
}

/// A delegation that cannot produce the requested address is a config that
/// can never work, so it is reported rather than waited on.
#[test]
fn an_impossible_subnet_is_reported_not_awaited() {
	let document = document(
		r#"
interface wan0   { config = "dhcp6" }
interface br-lan { config = "@pd:wan0/300=::1/64" }
"#,
	);
	let plan = plan(
		&document,
		&with_delegation(&["wan0", "br-lan"], "wan0", &["2001:db8:1234::/56"]),
		&PlanOptions::default(),
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("does not fit")),
		"got {:?}",
		plan.warnings
	);
	assert!(!names(&plan).contains(&"addr.add"));
}

/// Asking for the second prefix of a lease that carries one says so, rather
/// than silently using the first.
#[test]
fn an_out_of_range_prefix_index_is_named() {
	let document = document(
		r#"
interface wan0   { config = "dhcp6" }
interface br-lan { config = "@pd:wan0=::1/64" }
"#,
	);
	let mut observed = with_delegation(&["wan0", "br-lan"], "wan0", &["2001:db8::/56"]);
	// Reach past the end by hand: the DSL spells the index as `wan0/N`, which
	// is the subnet, and the prefix index has no surface syntax yet.
	let mut document = document;
	if let Some(netcfgd_model::AddressSource::Delegated(delegated)) = document
		.interfaces
		.iter_mut()
		.find(|interface| interface.name == "br-lan")
		.and_then(|interface| interface.addressing.first_mut())
	{
		delegated.prefix.index = 1;
	}

	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("asks for index 1")),
		"got {:?}",
		plan.warnings
	);
	let _ = &mut observed;
}

/// A PPP interface is created by pppd, not by netlink, so planning a
/// `link.create` for it would emit an action that must fail.
#[test]
fn a_ppp_session_is_dialled_not_created() {
	let document = document(
		r#"
interface ppp0 {
	pppoe { parent = "eth0"; username = "a"; password = "@secret:dsl" }
	routes = "default"
}
"#,
	);
	// eth0 exists; ppp0 does not, because the session has not come up.
	let plan = plan(
		&document,
		&observed_with(&["eth0"]),
		&PlanOptions::default(),
	);

	assert!(
		!names(&plan).contains(&"link.create"),
		"pppd creates the interface: {:?}",
		names(&plan)
	);
	assert!(
		names(&plan).contains(&"backend.start"),
		"{:?}",
		names(&plan)
	);
	// And the route waits, with the operator told why -- PPP negotiates
	// asynchronously, so it arrives on a later reconcile rather than later in
	// this plan.
	assert!(!names(&plan).contains(&"route.add"), "{:?}", names(&plan));
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("ppp session is not up yet")),
		"got {:?}",
		plan.warnings
	);
}

/// Once the session is up the interface is ordinary, and its route lands.
#[test]
fn a_live_ppp_interface_gets_its_route() {
	let document = document(
		r#"
interface ppp0 {
	pppoe { parent = "eth0"; username = "a"; password = "@secret:dsl" }
	routes = "default"
}
"#,
	);
	let mut observed = observed_with(&["eth0", "ppp0"]);
	// pppd started it and the backend is running, so nothing re-dials.
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Pppoe,
		interface: "ppp0".to_owned(),
		running: true,
	});

	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(names(&plan).contains(&"route.add"), "{:?}", names(&plan));
	assert!(
		!names(&plan).contains(&"backend.start"),
		"a running session must not be dialled again: {:?}",
		names(&plan)
	);

	settle(&document, &mut observed);
}

/// A port whose config lists VLANs has exactly those. That includes removing
/// the VLAN 1 the kernel adds by itself when a port joins a filtering bridge:
/// every real trunk setup begins by deleting it, and leaving it because the
/// kernel put it there would mean the document does not describe the port.
#[test]
fn a_configured_port_owns_its_vlan_list() {
	let document = document(
		r#"
interface br0  { bridge { vlan_filtering = true }; config = "null" }
interface lan1 { master = "br0"; vlans = "10 pvid untagged"; config = "null" }
"#,
	);
	let mut observed = observed_with(&["br0", "lan1"]);
	let index = observed
		.links
		.iter()
		.find(|link| link.name == "lan1")
		.expect("lan1")
		.index;
	// What the kernel has: its own default, and one the document dropped.
	observed
		.bridge_vlans
		.push(netcfgd_model::ObservedBridgeVlan {
			index,
			vid: 1,
			pvid: true,
			untagged: true,
		});
	observed
		.bridge_vlans
		.push(netcfgd_model::ObservedBridgeVlan {
			index,
			vid: 99,
			pvid: false,
			untagged: false,
		});

	let plan = plan(&document, &observed, &PlanOptions::default());
	let removed: Vec<u16> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::BridgeVlanDel { vid, .. } => Some(*vid),
			_ => None,
		})
		.collect();
	assert_eq!(removed, [1, 99], "both go, including the kernel's own");
	assert!(plan
		.actions
		.iter()
		.any(|action| matches!(&action.op, Op::BridgeVlanAdd { vid: 10, .. })));

	settle(&document, &mut observed);
}

/// A port the document says nothing about keeps whatever it has. The authority
/// is over ports that are configured, not over the bridge.
#[test]
fn an_unmentioned_port_keeps_its_vlans() {
	let document = document(
		r#"
interface br0   { bridge { vlan_filtering = true }; config = "null" }
interface other { master = "br0"; config = "null" }
"#,
	);
	let mut observed = observed_with(&["br0", "other"]);
	let index = observed
		.links
		.iter()
		.find(|link| link.name == "other")
		.expect("other")
		.index;
	observed
		.bridge_vlans
		.push(netcfgd_model::ObservedBridgeVlan {
			index,
			vid: 7,
			pvid: false,
			untagged: false,
		});

	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"bridge.vlan.del"),
		"an unconfigured port is not netcfgd's to strip: {:?}",
		names(&plan)
	);
}

/// A VLAN present but with the wrong flags is wrong in a way that shows up as
/// traffic arriving with a tag nobody expected, so it is corrected rather than
/// counted as present.
#[test]
fn wrong_vlan_flags_are_corrected() {
	let document = document(
		r#"
interface br0  { bridge { vlan_filtering = true }; config = "null" }
interface lan1 { master = "br0"; vlans = "10 pvid untagged"; config = "null" }
"#,
	);
	let mut observed = observed_with(&["br0", "lan1"]);
	let index = observed
		.links
		.iter()
		.find(|link| link.name == "lan1")
		.expect("lan1")
		.index;
	observed
		.bridge_vlans
		.push(netcfgd_model::ObservedBridgeVlan {
			index,
			vid: 10,
			pvid: false,
			untagged: false,
		});

	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		plan.actions.iter().any(|action| matches!(
			&action.op,
			Op::BridgeVlanAdd {
				vid: 10,
				pvid: true,
				..
			}
		)),
		"got {:?}",
		names(&plan)
	);
	settle(&document, &mut observed);
}

/// The laptop case: wired preferred, wifi as fallback, decided by metric.
#[test]
fn a_preference_becomes_the_route_metric() {
	let document = document(
		r#"
interface eth0  { preference = 100; config = "10.1.0.2/24"; routes = "default via 10.1.0.1" }
interface wlan0 { preference = 600; config = "10.2.0.2/24"; routes = "default via 10.2.0.1" }
"#,
	);
	let mut observed = observed_with(&["eth0", "wlan0"]);
	let plan = plan(&document, &observed, &PlanOptions::default());

	let mut metrics: Vec<(&str, Option<u32>)> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { iface, route, .. } => Some((iface.as_str(), route.metric)),
			_ => None,
		})
		.collect();
	metrics.sort_unstable();
	assert_eq!(metrics, [("eth0", Some(100)), ("wlan0", Some(600))]);

	settle(&document, &mut observed);
}

/// A route that names its own metric keeps it. The preference is a default,
/// not an override -- otherwise a config could not express one route on a
/// preferred interface that should lose to the rest.
#[test]
fn an_explicit_metric_wins_over_the_preference() {
	let document = document(
		r#"interface eth0 { preference = 100; config = "10.1.0.2/24"; routes = "default via 10.1.0.1 metric 5" }"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = plan(&document, &observed, &PlanOptions::default());

	assert!(plan.actions.iter().any(|action| matches!(
		&action.op,
		Op::RouteAdd { route, .. } if route.metric == Some(5)
	)));
	settle(&document, &mut observed);
}

/// The other half, and the one that makes the switch happen: a default route
/// down a cable that is not plugged in is a black hole, and its lower metric
/// would make the kernel prefer it over the wifi that works.
#[test]
fn losing_carrier_withdraws_the_route() {
	let document = document(
		r#"interface eth0 { preference = 100; config = "10.1.0.2/24"; routes = "default via 10.1.0.1" }"#,
	);
	let mut observed = observed_with(&["eth0"]);
	settle(&document, &mut observed);
	assert!(observed
		.routes_on("eth0")
		.any(|route| route.destination == "default"));

	// The cable comes out.
	for link in &mut observed.links {
		if link.name == "eth0" {
			link.carrier = false;
		}
	}

	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		plan.actions
			.iter()
			.any(|action| matches!(&action.op, Op::RouteDel { iface, .. } if iface == "eth0")),
		"got {:?}",
		names(&plan)
	);

	simulate(&plan, &mut observed);
	assert!(
		observed.routes_on("eth0").next().is_none(),
		"the route down the dead cable has to go"
	);

	// And it comes back when the cable does.
	for link in &mut observed.links {
		if link.name == "eth0" {
			link.carrier = true;
		}
	}
	settle(&document, &mut observed);
	assert!(observed
		.routes_on("eth0")
		.any(|route| route.destination == "default"));
}

/// An interface with no preference keeps its routes through a flap. A server
/// with one uplink does not want them withdrawn because a switch port
/// bounced -- there is nothing to fail over to.
#[test]
fn without_a_preference_carrier_is_not_consulted() {
	let document =
		document(r#"interface eth0 { config = "10.1.0.2/24"; routes = "default via 10.1.0.1" }"#);
	let mut observed = observed_with(&["eth0"]);
	settle(&document, &mut observed);

	for link in &mut observed.links {
		if link.name == "eth0" {
			link.carrier = false;
		}
	}
	let plan = plan(&document, &observed, &PlanOptions::default());
	assert!(
		plan.actions.is_empty(),
		"a flap must not disturb an interface that opted out: {:?}",
		names(&plan)
	);
}

/// NAT is one table, replaced whole, and the plan converges on the second run.
///
/// The interesting half is the second assertion. `settle` re-plans after
/// applying, so a `nat.replace` that did not compare against what the kernel
/// holds would be planned again every time -- which is exactly what happened
/// before the observed side read the rules back rather than assuming them.
#[test]
fn nat_is_planned_once_and_then_left_alone() {
	let desired = document(
		r#"
		interface eth0 {
			config     = "10.0.0.2/24"
			nat        = true
		}
		interface eth1 {
			config     = "192.168.1.1/24"
			forwarding = true
		}
		"#,
	);
	let mut observed = observed_with(&["eth0", "eth1"]);
	let plan = settle(&desired, &mut observed);

	assert!(names(&plan).contains(&"nat.replace"));
	assert_eq!(observed.nat, vec!["eth0".to_owned()]);
	assert!(
		names(&plan).contains(&"sysctl.set_forwarding"),
		"{:?}",
		names(&plan)
	);
}

/// Dropping `nat` from the document removes the table rather than leaving it.
///
/// The empty-list case is the one a bolted-on "add the rules" implementation
/// gets wrong: there is nothing to add, so nothing is planned, and the machine
/// keeps translating after the config stopped asking for it.
#[test]
fn removing_nat_withdraws_the_table() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.nat = vec!["eth0".to_owned()];

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"nat.replace"));
	assert!(observed.nat.is_empty());
}

/// NAT with nothing forwarding is a router that translates nothing, so the
/// plan says so. Cheap to get wrong and invisible on the wire.
#[test]
fn nat_without_forwarding_is_warned_about() {
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.2/24"
			nat    = true
		}
		"#,
	);
	let observed = observed_with(&["eth0"]);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan
		.warnings
		.iter()
		.any(|w| w.message.contains("no interface has `forwarding = true`")));
}

/// A second table doing source NAT is reported and never deleted.
#[test]
fn a_foreign_nat_table_is_reported_not_removed() {
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.2/24"
			nat    = true
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.nat_conflicts = vec!["fw4".to_owned()];

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.warnings.iter().any(|w| w.message.contains("`fw4`")));
	assert!(
		!names(&plan).iter().any(|name| name.contains("delete")),
		"{:?}",
		names(&plan)
	);
}

/// A named scheduler is installed once and then left alone.
#[test]
fn a_qdisc_is_set_once_and_then_left_alone() {
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.2/24"
			qdisc  = "fq_codel"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	assert!(names(&plan).contains(&"qdisc.set"));
	assert_eq!(
		observed.link("eth0").and_then(|l| l.qdisc.as_deref()),
		Some("fq_codel")
	);
}

/// The rate is part of the comparison, not an afterthought.
///
/// `cake` already installed at the wrong bandwidth is the case where "the kind
/// matches, so nothing to do" leaves a line shaped at somebody else's number.
#[test]
fn a_cake_at_the_wrong_rate_is_reshaped() {
	let desired = document(
		r#"
		interface eth0 {
			config = "10.0.0.2/24"
			qdisc {
				kind      = "cake"
				bandwidth = "100mbit"
			}
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.qdisc = Some("cake".to_owned());
		link.qdisc_bandwidth_bits = Some(50_000_000);
	}

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"qdisc.set"));
	assert_eq!(
		observed.link("eth0").and_then(|l| l.qdisc_bandwidth_bits),
		Some(100_000_000)
	);
}

/// Dropping `qdisc` puts the kernel default back, but only where netcfgd is
/// what moved it.
#[test]
fn removing_a_qdisc_netcfgd_set_restores_the_default() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.qdisc = Some("cake".to_owned());
	}
	observed.qdisc_applied = vec!["eth0".to_owned()];

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"qdisc.reset"));
	assert_eq!(
		observed.link("eth0").and_then(|l| l.qdisc.as_deref()),
		Some("noqueue")
	);
}

/// A qdisc somebody else set is left exactly where it is.
///
/// The counterpart of the test above, and the one that matters: without the
/// ownership record netcfgd would reset every interface whose config does not
/// mention a qdisc, which is most of them.
#[test]
fn a_qdisc_netcfgd_did_not_set_is_left_alone() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.qdisc = Some("cake".to_owned());
	}

	let plan = settle(&desired, &mut observed);
	assert!(!names(&plan).contains(&"qdisc.reset"), "{:?}", names(&plan));
}
