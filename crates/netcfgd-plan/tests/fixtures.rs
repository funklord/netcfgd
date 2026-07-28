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
		ownership: Ownership::Unknown,
	}
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
				table: route.table,
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
			// Hooks and commit actions leave no observable state of their own.
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
