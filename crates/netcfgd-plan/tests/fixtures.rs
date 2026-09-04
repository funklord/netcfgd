//! The fixture harness project.md section 5 asks to be built first.
//!
//! Fixture config text plus a fake observed snapshot, asserting on the action
//! list. No hardware, no filesystem, no netlink. Every fixture also goes
//! through [`settle`], which simulates applying the plan and re-plans -- that
//! is the plan-idempotence gate from section 6, and it is the check that
//! catches an action which does not actually converge.

use netcfgd_compile::{compile, NoHooks, SourceMap};
use netcfgd_model::{
	AppliedDns, BackendKind, Document, HookPhase, Observed, ObservedAddress, ObservedBackend,
	ObservedLink, ObservedRoute, Origin, Ownership,
};
use netcfgd_plan::{plan as plan_unchecked, Op, Plan, PlanOptions};

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
		// A fixture convention: a name beginning `wlan` is a radio. The real
		// answer comes from `/sys/class/net/<name>/wireless`, which cannot be
		// consulted for an interface that does not exist -- and every radio
		// in this file is called `wlan0`. It has to be a property of the link
		// rather than of the `device` block, because a `wifi { }` section
		// carries things like `portal_check` that are meaningful on anything.
		wireless: name.starts_with("wlan"),
		network: None,
		up: false,
		carrier: true,
		reachable: None,
		probe_detail: None,
		mtu: 1500,
		mac: None,
		master: None,
		parent: None,
		offloads: Vec::new(),
		ipv6_token: None,
		qdisc: Some("noqueue".to_owned()),
		qdisc_bandwidth_bits: None,
		qdisc_ingress: false,
		ingress_redirect: None,
		forwarding: None,
		privacy: None,
		// An ordinary interface: the kernel's default, and it forwards nothing,
		// so advertisements arrive. A fixture that wants the trap -- `accept_ra`
		// 1 on an interface that forwards -- says so by hand, because that is the
		// state the whole pass exists for.
		accept_ra: Some(netcfgd_model::ObservedAcceptRa {
			value: 1,
			effective: true,
		}),
		rfkill: None,
		ownership: Ownership::Unknown,
		private_key_loaded: false,
		wireguard: None,
		bond: None,
		bridge: None,
		macvlan: None,
		vlan: None,
		tunnel: None,
		vxlan: None,
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
	let (kind, rate, ingress) = match op {
		Op::QdiscSet {
			kind,
			bandwidth_bits,
			ingress,
			..
		} => (kind.clone(), *bandwidth_bits, *ingress),
		_ => ("noqueue".to_owned(), None, false),
	};

	if let Some(link) = observed.links.iter_mut().find(|l| &l.name == iface) {
		link.qdisc = Some(kind);
		link.qdisc_bandwidth_bits = rate;
		link.qdisc_ingress = ingress;
	}

	observed.qdisc_applied.retain(|name| name != iface);
	if matches!(op, Op::QdiscSet { .. }) {
		observed.qdisc_applied.push(iface.clone());
	}
}

/// The link-attribute half of [`simulate`]: find the link, set the field.
fn simulate_link(op: &Op, observed: &mut Observed) {
	let (Op::LinkSetMtu { name, .. }
	| Op::LinkSetMac { name, .. }
	| Op::LinkSetMaster { name, .. }
	| Op::LinkUnsetMaster { name }
	| Op::LinkUp { name }
	| Op::LinkDown { name }) = op
	else {
		return;
	};
	let Some(link) = observed.links.iter_mut().find(|l| &l.name == name) else {
		return;
	};
	match op {
		Op::LinkSetMtu { mtu, .. } => link.mtu = *mtu,
		Op::LinkSetMac { mac, .. } => link.mac = Some(mac.clone()),
		Op::LinkSetMaster { master, .. } => link.master = Some(master.clone()),
		Op::LinkUnsetMaster { .. } => link.master = None,
		Op::LinkUp { .. } => link.up = true,
		Op::LinkDown { .. } => link.up = false,
		_ => {}
	}
}

/// The ingress half of [`simulate`].
fn simulate_ingress(op: &Op, observed: &mut Observed) {
	let (Op::IngressRedirect { iface, .. } | Op::IngressRedirectClear { iface }) = op else {
		return;
	};
	let target = match op {
		Op::IngressRedirect { target, .. } => Some(target.clone()),
		_ => None,
	};
	if let Some(link) = observed.links.iter_mut().find(|l| &l.name == iface) {
		link.ingress_redirect = target;
	}
	observed.ingress_applied.retain(|name| name != iface);
	if matches!(op, Op::IngressRedirect { .. }) {
		observed.ingress_applied.push(iface.clone());
	}
}

/// The rule half of [`simulate`].
fn simulate_rule(op: &Op, observed: &mut Observed) {
	match op {
		Op::RuleAdd { rule } => observed.rules.push(netcfgd_model::ObservedRule {
			priority: rule.priority,
			family: rule.family,
			from: rule.from.clone(),
			to: rule.to.clone(),
			iif: rule.iif.clone(),
			oif: rule.oif.clone(),
			fwmark: rule.fwmark,
			fwmask: rule.fwmask,
			// The kernel reports no table for the non-lookup actions,
			// whatever the document said. A fake that echoed the desired
			// value back would hide a real mismatch.
			table: (rule.action == netcfgd_model::RuleAction::Lookup)
				.then_some(rule.table)
				.flatten(),
			action: rule.action,
			suppress_prefixlength: rule.suppress_prefixlength,
			l3mdev: rule.l3mdev,
			invert: rule.invert,
			ownership: Ownership::Ours,
		}),
		Op::RuleDel { rule } => observed
			.rules
			.retain(|held| !(held.family == rule.family && held.priority == rule.priority)),
		_ => {}
	}
}

/// What a freshly started access point holds, which is what the document says.
///
/// hostapd reads the generated station list once, at startup, and netcfgd
/// writes the policy record into the same file -- so this is the one moment the
/// live lists and the document are guaranteed to agree.
fn started_access_control(
	kind: BackendKind,
	iface: &str,
	desired: &Document,
) -> Option<netcfgd_model::ObservedAccessControl> {
	if kind != BackendKind::AccessPoint {
		return None;
	}
	let access_point = desired
		.access_points
		.iter()
		.find(|access_point| access_point.device == iface)?;
	let (policy, stations) = match &access_point.access_control {
		Some(acl) => (
			netcfgd_model::ObservedPolicy::Set(acl.policy),
			acl.stations.clone(),
		),
		// No block, so hostapd was given no `macaddr_acl` and netcfgd wrote no
		// station list to record one in.
		None => (netcfgd_model::ObservedPolicy::Unset, Vec::new()),
	};
	let listed = |wanted| {
		if matches!(policy, netcfgd_model::ObservedPolicy::Set(held) if held == wanted) {
			stations.clone()
		} else {
			Vec::new()
		}
	};
	Some(netcfgd_model::ObservedAccessControl {
		policy,
		denied: listed(netcfgd_model::AclPolicy::Deny),
		accepted: listed(netcfgd_model::AclPolicy::Allow),
	})
}

/// hostapd's lists, changed the way `ADD_MAC` and `DEL_MAC` change them.
fn simulate_access_control(op: &Op, observed: &mut Observed) {
	let (Op::AccessControlAdd {
		iface,
		list,
		station,
	}
	| Op::AccessControlDel {
		iface,
		list,
		station,
	}) = op
	else {
		return;
	};
	let Some(live) = observed
		.backends
		.iter_mut()
		.find(|backend| backend.kind == BackendKind::AccessPoint && &backend.interface == iface)
		.and_then(|backend| backend.access_control.as_mut())
	else {
		return;
	};
	let held = match list {
		netcfgd_model::AclPolicy::Deny => &mut live.denied,
		netcfgd_model::AclPolicy::Allow => &mut live.accepted,
	};
	held.retain(|entry| entry != station);
	if matches!(op, Op::AccessControlAdd { .. }) {
		held.push(station.clone());
	}
	// hostapd sorts its lists on every add (`qsort` by address in
	// `hostapd_ctrl_iface_acl_add_mac`), and the parser sorts what it reads
	// back. A simulator that did not would let a plan pass the idempotence gate
	// while differing from the live list on ordering alone.
	held.sort();
}

/// What a backend looks like once netcfgd has started it.
///
/// A restarted access point re-reads the file netcfgd wrote from the document,
/// so what it holds afterwards is what the document says -- policy record,
/// identity and secret included. Simulating any of those as "netcfgd could not
/// ask" would make the planner skip its comparison, and the idempotence gate
/// would then pass because the feature was invisible rather than because it
/// converged.
fn started_backend(
	kind: netcfgd_model::BackendKind,
	iface: &str,
	desired: &Document,
) -> ObservedBackend {
	let access_point = desired
		.access_points
		.iter()
		.find(|point| point.device == iface);
	ObservedBackend {
		kind,
		interface: iface.to_owned(),
		running: true,
		answering: None,
		access_control: started_access_control(kind, iface, desired),
		started_with: access_point.map(|point| netcfgd_model::ObservedAccessPoint {
			ssid: point.ssid.clone(),
			band: point.band.clone(),
			channel: point.channel,
		}),
		secret_matches: access_point.map(|_| true),
		config_matches: None,
		advertised: Vec::new(),
	}
}

/// Fill in what the kernel would say about a link that was just created.
///
/// The document is the source, because the kernel's answer for a device netcfgd
/// just made *is* what netcfgd asked for -- with one exception that matters and
/// is the reason this exists at all: a field the document does not state comes
/// back as whatever the kernel chose, which is not the document's `None`. Those
/// are left absent here rather than guessed, so a comparison that treats "not
/// stated" as a difference still converges in this harness and only a real
/// comparison bug loops.
fn describe_created(link: &mut ObservedLink, desired: &Document) {
	use netcfgd_model::InterfaceKind as Kind;

	let Some(interface) = desired
		.devices
		.iter()
		.find(|interface| interface.name == link.name)
	else {
		return;
	};
	let kind = match &interface.kind {
		Kind::Bridge(_) => "bridge",
		Kind::Bond(_) => "bond",
		Kind::Vlan(_) => "vlan",
		Kind::Vxlan(_) => "vxlan",
		Kind::WireGuard(_) => "wireguard",
		Kind::Dummy => "dummy",
		Kind::Veth(_) => "veth",
		Kind::Vrf(_) => "vrf",
		Kind::Macvlan(_) => "macvlan",
		Kind::Tunnel(tunnel) => tunnel.mode.name(),
		Kind::Ifb => "ifb",
		// A physical device reports no kind, and the three that come from
		// somewhere other than netlink are not created by a `link.create` at
		// all.
		Kind::Physical | Kind::Pppoe(_) | Kind::OpenVpn(_) | Kind::Tun(_) => "",
	};
	kind.clone_into(&mut link.kind);
	match &interface.kind {
		Kind::Vlan(vlan) => {
			link.vlan = Some(netcfgd_model::ObservedVlan {
				id: Some(vlan.id),
				protocol: Some(vlan.protocol.name().to_owned()),
			});
		}
		Kind::Macvlan(macvlan) => {
			link.macvlan = Some(netcfgd_model::ObservedMacvlan {
				mode: Some(macvlan.mode.name().to_owned()),
			});
		}
		Kind::Vxlan(vxlan) => {
			link.vxlan = Some(netcfgd_model::ObservedVxlan {
				id: Some(vxlan.id),
				local: vxlan.local,
				remote: vxlan.remote,
				port: vxlan.port,
			});
		}
		Kind::Tunnel(tunnel) => {
			link.tunnel = Some(netcfgd_model::ObservedTunnel {
				local: tunnel.local,
				remote: tunnel.remote,
				ttl: tunnel.ttl,
				key: tunnel.key,
			});
		}
		Kind::Bond(bond) => {
			link.bond = Some(netcfgd_model::ObservedBond {
				mode: Some(bond.mode.name().to_owned()),
				miimon: bond.miimon,
			});
		}
		Kind::Bridge(bridge) => {
			link.bridge = Some(netcfgd_model::ObservedBridge {
				stp: bridge.stp,
				forward_delay: bridge.forward_delay,
				hello_time: bridge.hello_time,
				ageing_time: bridge.ageing_time,
				priority: bridge.priority,
				vlan_filtering: bridge.vlan_filtering,
			});
		}
		_ => {}
	}
}

/// The two per-link attributes that are neither addressing nor a link setting.
fn simulate_attribute(op: &Op, observed: &mut Observed) {
	match op {
		Op::LinkSetOffloads { name, features } => {
			if let Some(link) = observed.links.iter_mut().find(|link| &link.name == name) {
				for (feature, on) in features {
					link.offloads.retain(|held| held != feature);
					if *on {
						link.offloads.push(feature.clone());
					}
				}
				link.offloads.sort();
			}
		}
		Op::LinkSetIpv6Token { name, token } => {
			if let Some(link) = observed.links.iter_mut().find(|link| &link.name == name) {
				// `::` is how the kernel spells "none", so it clears rather than
				// storing an address.
				link.ipv6_token = (token != "::").then(|| token.clone());
			}
		}
		_ => {}
	}
}

/// The whole-host half of [`simulate`]: the hostname and the privacy sysctl.
///
/// Split out for the reason the VLAN and qdisc halves were: one match arm per op
/// had grown past what the style allows.
fn simulate_host(op: &Op, observed: &mut Observed) {
	match op {
		// An event hook's record, without which the "once per event" property cannot
		// be tested at all: the second plan would fire it again and `settle` would
		// catch that as a non-empty plan -- which is what this models rather than
		// hides. The lifecycle phases carry no value and leave no record, which is
		// why they fall through.
		Op::HookRun {
			iface,
			phase,
			value: Some(value),
			..
		} => {
			observed
				.hook_state
				.retain(|record| &record.interface != iface || record.phase != *phase);
			observed.hook_state.push(netcfgd_model::ObservedHookState {
				interface: iface.clone(),
				phase: *phase,
				value: value.clone(),
			});
		}
		Op::HostnameSet { name } => observed.hostname = Some(name.clone()),
		Op::SysctlSetAcceptRa { iface, value } => {
			// What the kernel would report afterwards, both halves of it: a `2`
			// is effective whatever the interface forwards, and a `1` is
			// effective only where it does not. Without the second half a plan
			// that hands an interface back would never converge -- the fake
			// would keep reporting the state the write had just left.
			let forwards = observed
				.links
				.iter()
				.find(|link| &link.name == iface)
				.and_then(|link| link.accept_ra)
				.is_some_and(|state| state.value == 1 && !state.effective);
			if let Some(link) = observed.links.iter_mut().find(|link| &link.name == iface) {
				link.accept_ra = Some(netcfgd_model::ObservedAcceptRa {
					value: *value,
					effective: *value == 2 || !forwards,
				});
			}
			observed.accept_ra_applied.retain(|name| name != iface);
			if *value != 1 {
				observed.accept_ra_applied.push(iface.clone());
			}
		}
		Op::SysctlSetPrivacy {
			iface,
			prefer_temporary,
		} => {
			if let Some(link) = observed.links.iter_mut().find(|link| &link.name == iface) {
				link.privacy = Some(*prefer_temporary);
			}
			// And the record of who set it, without which the "stopped asking"
			// direction cannot be tested at all.
			observed.privacy_applied.retain(|name| name != iface);
			if *prefer_temporary {
				observed.privacy_applied.push(iface.clone());
			}
		}
		_ => {}
	}
}

fn simulate(plan: &Plan, observed: &mut Observed, desired: &Document) {
	for action in &plan.actions {
		match &action.op {
			Op::LinkCreate { name, .. } => {
				let mut created = link(name);
				created.ownership = Ownership::Ours;
				// What the kernel would report about the thing that was just
				// made, not an empty link with the right name. A fake that left
				// the kind and the per-kind settings blank cannot see a
				// comparison that never converges: the second plan would find
				// nothing to compare and call that agreement, which is how a
				// recreation loop would look like a converged one here and loop
				// on a real kernel (0057, 0058, 0059).
				describe_created(&mut created, desired);
				observed.links.push(created);
			}
			Op::LinkDelete { name } => {
				observed.links.retain(|link| &link.name != name);
				observed.addresses.retain(|a| &a.interface != name);
				observed.routes.retain(|r| &r.interface != name);
			}
			Op::LinkSetMtu { .. }
			| Op::LinkSetMac { .. }
			| Op::LinkSetMaster { .. }
			| Op::LinkUnsetMaster { .. }
			| Op::LinkUp { .. }
			| Op::LinkDown { .. } => simulate_link(&action.op, observed),
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
			Op::BackendStart { kind, iface } => {
				observed
					.backends
					.push(started_backend(*kind, iface, desired));
			}
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
			Op::IngressRedirect { .. } | Op::IngressRedirectClear { .. } => {
				simulate_ingress(&action.op, observed);
			}
			Op::LinkSetOffloads { .. } | Op::LinkSetIpv6Token { .. } => {
				simulate_attribute(&action.op, observed);
			}
			Op::RuleAdd { .. } | Op::RuleDel { .. } => simulate_rule(&action.op, observed),
			Op::SysctlSetForwarding { iface, enabled } => {
				if let Some(link) = observed.links.iter_mut().find(|l| &l.name == iface) {
					link.forwarding = Some(*enabled);
				}
			}
			Op::HostnameSet { .. }
			| Op::SysctlSetPrivacy { .. }
			| Op::SysctlSetAcceptRa { .. }
			| Op::HookRun { .. } => {
				simulate_host(&action.op, observed);
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
			Op::AccessControlAdd { .. } | Op::AccessControlDel { .. } => {
				simulate_access_control(&action.op, observed);
			}
			_ => {}
		}
	}
	observed.canonicalize();
}

/// Plan, apply, re-plan. Returns the first plan, and asserts the second is
/// empty.
/// `netcfgd_plan::plan`, with the plan's own structural invariant checked.
///
/// Every fixture in this file goes through here, so the invariant is asserted
/// roughly two hundred times rather than once: **an action may only depend on
/// an action that exists and comes before it.**
///
/// It is a wrapper rather than a test because the failure it was written for
/// was not visible from any single fixture. A refused action's id is
/// `u32::MAX`, five accumulators inside the planner collect ids without asking
/// whether they are real, and all five feed somebody's `depends_on` -- so the
/// defect is wherever the next edge is added, not where the last one was
/// (0097).
fn plan(desired: &Document, observed: &Observed, options: &PlanOptions) -> Plan {
	let plan = plan_unchecked(desired, observed, options);

	let mut seen: Vec<u32> = Vec::new();
	for action in &plan.actions {
		for id in &action.depends_on {
			assert!(
				seen.contains(id),
				"{} (id {}) depends on action {id}, which is not earlier in the plan; \
				 the plan holds {:?}",
				action.op.name(),
				action.id,
				plan.actions
					.iter()
					.map(|earlier| (earlier.id, earlier.op.name()))
					.collect::<Vec<_>>()
			);
		}
		seen.push(action.id);
	}
	plan
}

fn settle(desired: &Document, observed: &mut Observed) -> Plan {
	let first = plan(desired, observed, &PlanOptions::default());
	simulate(&first, observed, desired);
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
		device eth0 { mtu = 9000 }
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
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
		device br0 {
			bridge { members = "eth0" }
		}
		interface br0 {
			config = "10.0.0.1/24"
		}
		device eth0 {
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
		device lan10 {
			vlan   { parent = "eth0"; id = 10 }
		}
		interface lan10 {
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
		 \tup {\necho live\n}\n\
		 \tpost_up {\necho after\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");

	let mut observed = observed_with(&["eth0"]);
	// Through `settle`, which is the idempotence gate -- and which no fixture with
	// hooks in it had ever used. Both up hooks were emitted unconditionally, so a
	// converged interface ran them on every apply and the second plan was never
	// empty; nothing in the harness asked, because the one test with hooks called
	// `plan` and `simulate` by hand. Section 6's gate with the subject missing from
	// its input set, one more time (0063).
	let plan = settle(&desired, &mut observed);

	let hooks: Vec<usize> = plan
		.actions
		.iter()
		.enumerate()
		.filter(|(_, a)| a.op.name() == "hook.run")
		.map(|(index, _)| index)
		.collect();
	assert_eq!(hooks.len(), 3, "three phases, three runs");

	let link_up = &plan.actions[position(&plan, "link.up")];
	let addr = &plan.actions[position(&plan, "addr.add")];
	let pre = &plan.actions[hooks[0]];
	let live = &plan.actions[hooks[1]];
	let post = &plan.actions[hooks[2]];

	assert!(
		link_up.depends_on.contains(&pre.id),
		"link.up must wait for pre_up"
	);
	// The middle one, which is the whole of what `up` means: after the link and
	// before the addressing. Asserted as *edges* rather than as positions,
	// because actions execute in list order and a check on position alone passes
	// on emission order -- which is what made a `depends_on` edge decoration
	// once already.
	assert!(
		live.depends_on.contains(&link_up.id),
		"up must wait for link.up"
	);
	assert!(
		addr.depends_on.contains(&live.id),
		"the addressing must wait for up, or the ordering is a claim rather than a fact"
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
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
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
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
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
		device br0 {
			bridge { members = "eth0 eth1" }
		}
		interface br0 {
			config = "10.0.0.1/24"
			routes = "default via 10.0.0.254"
		}
		device eth0 { master = "br0" }
		device eth1 { master = "br0" }
		device wan0 { mtu = 1492 }
		interface wan0 { config = "dhcp" }
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
		device eth0 { mtu = 9000 }
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
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

/// A radio with no networks to join **does** get a supplicant, which is the
/// reverse of what this test used to assert.
///
/// It said a supplicant handed nothing is "a process running for no reason,
/// and it makes `ncfg status` report a backend nothing asked for". That is
/// true only if nothing else needs it, and scanning does -- so the rule closed
/// a loop: no supplicant without a network, no scan without a supplicant, and
/// no network without a scan to find one. A machine whose wifi already worked
/// stayed working; a machine starting from nothing could not begin, and the
/// only way out was to hand-write a `network` block for a network you could
/// not yet see.
///
/// **It went unnoticed because `NetworkManager` was running.** NM adds the
/// interface to the system `wpa_supplicant`, which creates the control socket,
/// so netcfgd scanned through a supplicant it had not started and had no
/// opinion about. Stopping NM took the socket away and scanning stopped with
/// it. Found on a machine, not here.
///
/// The declaration that now decides it is the `device` block: an operator who
/// wrote `wifi { }` for a radio has said netcfgd manages it, and managing a
/// radio includes being able to look at what is in range.
#[test]
fn a_radio_with_no_networks_still_gets_a_supplicant() {
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
		names(&plan).contains(&"backend.start"),
		"a declared radio cannot be scanned with: {:?}",
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
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
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

/// The M4 freeze put four features in the schema that nothing implemented.
/// All four are built now; what remains unapplied is the half of the `ethtool`
/// block that can only be exercised against a physical NIC. The failure mode
/// to guard against is not that it does nothing -- that is intended -- but
/// that it does nothing *silently*, so a plan reports "one action" about a
/// config that asked for several things.
#[test]
fn recognised_but_unimplemented_features_are_named_in_the_plan() {
	let document = document(
		r#"
device eth0 {
	ethtool { gro = "off"; speed = 1000; wol = "g" }
}
interface eth0 {
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

	let expected = "`speed`, `wol`";
	assert!(
		warnings.iter().any(|message| message.contains(expected)),
		"nothing warned about {expected}: {warnings:?}"
	);

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

/// An access point is a prerequisite, in the same place a supplicant is: after
/// the link is up and before anything is addressed. hostapd needs the
/// interface up to put a BSS on it, and a bridge member with no BSS is an
/// interface that carries nothing.
#[test]
fn an_access_point_starts_after_the_link_is_up() {
	let desired = document(
		r#"
device wlan0 { wifi { } }

access_point "guest" {
	device  = "wlan0"
	channel = 6
	wifi    { open = true }
}

interface wlan0 { config = "192.168.9.1/24" }
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	let plan = settle(&desired, &mut observed);

	assert_eq!(names(&plan), ["link.up", "backend.start", "addr.add"]);

	let start = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "backend.start")
		.expect("a start");
	assert_eq!(
		start.reason.field, "access_point",
		"a backend started for `wifi` sends the reader to the wrong block"
	);
	let up = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "link.up")
		.expect("a link.up");
	assert!(
		start.depends_on.contains(&up.id),
		"hostapd was started without waiting for the link"
	);
}

/// One dial, not two. Both the link-attributes pass and the contents pass used
/// to plan it, so every apply of a session that had not come up yet ran the
/// daemon twice -- and the fixture that covered this asserted the action was
/// *present* rather than how many there were, which is why it went unnoticed
/// from the day `PPPoE` was written.
///
/// **And then this test stopped being able to see it.** It counted, which was
/// the fix, but its configuration was a bare `device` block -- so after 0155
/// pass 1b moved the dial onto the device walk and left the old call in the
/// interface walk, the duplicate needed *both* an interface and a device to
/// appear, and this had only the device. It passed with the fault
/// reintroduced, measured. The `interface` blocks below are the whole
/// difference: a test for a duplicate between two walks has to give both
/// walks something to find.
#[test]
fn a_tunnel_that_is_not_up_is_dialled_exactly_once() {
	for config in [
		r#"device t0 { pppoe { parent = "eth0"; username = "u"; password = "@secret:p" } }
		   interface t0 { config = "null" }"#,
		r#"device t0 { openvpn { config = "/etc/openvpn/work.ovpn" } }
		   interface t0 { config = "null" }"#,
	] {
		let desired = document(config);
		let plan = plan(&desired, &Observed::default(), &PlanOptions::default());
		let starts = names(&plan)
			.iter()
			.filter(|name| **name == "backend.start")
			.count();
		assert_eq!(starts, 1, "for {config}, got {:?}", names(&plan));
	}
}

/// A tunnel is an interface, exactly as a `PPPoE` session is: the daemon creates
/// the device, so nothing plans a `link.create`, and the backend is the
/// prerequisite that brings it into existence.
#[test]
fn an_openvpn_tunnel_is_started_rather_than_created() {
	let desired = document(r#"device vpn0 { openvpn { config = "/etc/openvpn/work.ovpn" } }"#);
	// The device does not exist yet, which is the ordinary state before the
	// daemon has connected.
	let observed = Observed::default();

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).iter().any(|name| *name == "link.create"),
		"openvpn makes the tun device; a link.create would be an action that must fail: {:?}",
		names(&plan)
	);
	assert!(
		plan.actions.iter().any(|action| matches!(&action.op,
			Op::BackendStart { kind, iface }
				if *kind == BackendKind::OpenVpn && iface == "vpn0")),
		"got {:?}",
		names(&plan)
	);
}

/// And once it is up, nothing starts it again.
#[test]
fn a_running_tunnel_is_left_alone() {
	let desired = document(r#"device vpn0 { openvpn { config = "/etc/openvpn/work.ovpn" } }"#);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::OpenVpn,
		interface: "vpn0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	let plan = settle(&desired, &mut observed);
	assert!(
		!names(&plan).iter().any(|name| name.starts_with("backend.")),
		"got {:?}",
		names(&plan)
	);
}

/// Deleting the block stops the daemon. The same question `backend_wanted`
/// answers for every other backend, and getting it wrong is an oscillation
/// rather than a missing feature -- start on one reconcile, stop on the next.
#[test]
fn a_tunnel_stops_when_its_block_goes() {
	let desired = document(
		r#"device vpn0 { kind = "dummy" }
interface vpn0 { config = "null" }"#,
	);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::OpenVpn,
		interface: "vpn0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	let plan = plan(&desired, &observed, &PlanOptions::default());
	let stop = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "backend.stop")
		.expect("a stop");
	assert_eq!(stop.reason.field, "openvpn");
}

/// An interface whose addresses come from a report.
fn reported_document() -> Document {
	document(
		r#"device wwan0 { kind = "dummy" }
interface wwan0 { config = "reported" }"#,
	)
}

/// `wwan0` present, with these addresses reported for it.
fn reported_observed(addresses: &[&str]) -> Observed {
	reporting(addresses, &[])
}

/// The same, with gateways too.
fn reporting(addresses: &[&str], gateways: &[&str]) -> Observed {
	let owned = |list: &[&str]| list.iter().map(|value| (*value).to_owned()).collect();
	let mut observed = observed_with(&["wwan0"]);
	observed.links[0].up = true;
	observed.reports.push(netcfgd_model::ObservedReport {
		interface: "wwan0".to_owned(),
		addresses: owned(addresses),
		gateways: owned(gateways),
		nameservers: Vec::new(),
		search: Vec::new(),
		routes: Vec::new(),
	});
	observed
}

/// The same, with routes the report names outright.
fn reporting_routes(routes: &[(&str, Option<&str>)]) -> Observed {
	let mut observed = reporting(&["10.8.0.2/24"], &[]);
	observed.reports[0].routes = routes
		.iter()
		.map(|(destination, via)| netcfgd_model::ReportedRoute {
			destination: (*destination).to_owned(),
			via: via.map(ToOwned::to_owned),
		})
		.collect();
	observed
}

/// The destination and next hop of every route a plan installs.
fn added_routes(plan: &Plan) -> Vec<(String, String)> {
	plan.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { route, .. } => Some((
				route.destination.clone(),
				route.via.map(|via| via.to_string()).unwrap_or_default(),
			)),
			_ => None,
		})
		.collect()
}

/// `wwan0` reporting nameservers, with the document's globals set to a mode.
fn reporting_nameservers(config: &str, servers: &[&str]) -> (Document, Observed) {
	let desired = document(config);
	let mut observed = reporting(&["10.64.1.23/30"], &[]);
	observed.reports[0].nameservers = servers.iter().map(|s| (*s).to_owned()).collect();
	(desired, observed)
}

/// The servers a plan would deliver for one scope.
fn delivered(plan: &Plan, scope: &str) -> Vec<String> {
	plan.actions
		.iter()
		.find_map(|action| match &action.op {
			Op::DnsApply {
				scope: name,
				policy,
			} if name == scope => Some(
				policy
					.servers
					.iter()
					.map(|server| server.addr.to_string())
					.collect(),
			),
			_ => None,
		})
		.unwrap_or_default()
}

/// Decision 0006 rule 4 says DNS merges in list order, and until now nothing
/// had ever exercised it: no addressing source contributed a nameserver. A
/// modem does, and the interface gets a scope for it.
#[test]
fn a_reported_nameserver_is_delivered() {
	let (desired, mut observed) = reporting_nameservers(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device wwan0 { kind = "dummy" }
interface wwan0 { config = "reported" }
"#,
		&["8.8.8.8"],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(delivered(&plan, "wwan0"), ["8.8.8.8"]);
}

/// The mode is not a choice. `netcfgd_dns::deliver` refuses a delivery whose
/// scopes disagree about it, so the only value that is not an error is the one
/// the rest of the host uses.
#[test]
fn a_synthesised_scope_takes_the_mode_the_host_already_uses() {
	let (desired, mut observed) = reporting_nameservers(
		r#"
global { dns { dns_mode = "resolvconf" } }
device wwan0 { kind = "dummy" }
interface wwan0 { config = "reported" }
"#,
		&["8.8.8.8"],
	);

	let plan = settle(&desired, &mut observed);
	let mode = plan.actions.iter().find_map(|action| match &action.op {
		Op::DnsApply { scope, policy } if scope == "wwan0" => Some(policy.mode.name().to_owned()),
		_ => None,
	});
	assert_eq!(mode.as_deref(), Some("resolvconf"));
}

/// A host that manages no DNS does not start managing it because a modem
/// appeared. Globals at `none` means nothing is delivered.
#[test]
fn a_host_that_manages_no_dns_still_manages_none() {
	let (desired, mut observed) = reporting_nameservers(
		r#"device wwan0 { kind = "dummy" }
interface wwan0 { config = "reported" }"#,
		&["8.8.8.8"],
	);

	let plan = settle(&desired, &mut observed);
	assert!(
		!names(&plan).iter().any(|name| *name == "dns.apply"),
		"got {:?}",
		names(&plan)
	);
}

/// Rule 4's "first occurrence winning", with the document first: a server an
/// operator wrote down beats one the network handed out.
#[test]
fn a_written_nameserver_comes_before_a_reported_one() {
	let (desired, mut observed) = reporting_nameservers(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device wwan0 {
	kind   = "dummy"
}
interface wwan0 {
	config = "reported"
	dns    = "9.9.9.9"
}
"#,
		&["8.8.8.8"],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(delivered(&plan, "wwan0"), ["9.9.9.9", "8.8.8.8"]);
}

/// A defect older than the modem work, found by merging two implementations of
/// the scope list into one.
///
/// `dns = "9.9.9.9"` on an interface compiles to a policy whose mode is `none`,
/// because the line says nothing about delivery. The executor built its scope
/// list separately and dropped any scope with that mode -- so an operator wrote
/// a nameserver down, nothing failed, nothing warned, and the server never
/// reached `resolv.conf`.
///
/// The mode was never a per-interface choice: `netcfgd-dns` refuses a delivery
/// whose scopes disagree about it, so `none` on a scope that has something to
/// deliver can only mean "not stated".
#[test]
fn a_nameserver_written_on_an_interface_reaches_the_resolver() {
	let desired = document(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device eth0 {
	kind   = "dummy"
}
interface eth0 {
	config = "10.0.0.1/24"
	dns    = "9.9.9.9"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);
	assert_eq!(
		delivered(&plan, "eth0"),
		["9.9.9.9"],
		"an interface's dns line has to reach the resolver"
	);
	// And the mode, which is the half that decides whether it is delivered at
	// all. Asserting only the servers checks that the *plan* carries them --
	// which it did all along, while the scope was dropped at delivery for
	// having no mode. The bug was invisible to a check on the plan alone.
	let mode = plan.actions.iter().find_map(|action| match &action.op {
		Op::DnsApply { scope, policy } if scope == "eth0" => Some(policy.mode.name().to_owned()),
		_ => None,
	});
	assert_eq!(
		mode.as_deref(),
		Some("write_resolv_conf"),
		"a scope with no mode of its own is dropped at delivery"
	);
}

/// And a block that asks for nothing produces no action, so the fix above does
/// not turn every `dns { }` into a delivery nobody wanted.
#[test]
fn a_dns_block_that_asks_for_nothing_plans_nothing() {
	let desired = document(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device eth0 { kind = "dummy" }
interface eth0 { config = "10.0.0.1/24"; dns { } }
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);
	assert!(delivered(&plan, "eth0").is_empty());
}

/// A report for an interface the document says nothing about contributes no
/// resolver, the same as it installs no route.
#[test]
fn a_report_without_the_source_contributes_no_nameserver() {
	let (desired, mut observed) = reporting_nameservers(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device wwan0 { kind = "dummy" }
interface wwan0 { config = "null" }
"#,
		&["8.8.8.8"],
	);

	let plan = settle(&desired, &mut observed);
	assert!(delivered(&plan, "wwan0").is_empty());
}

/// A tunnel's servers are not delivered because a tunnel reported them.
///
/// Decision 0049, and the difference from a route: netcfgd installs a route
/// down a tunnel it started on the strength of having started it, because a
/// route down a tunnel goes down that tunnel. A nameserver decides where every
/// query on the machine goes, so the document has to have asked. This is
/// decision 0007's opening failure -- bring up a VPN and every query silently
/// goes to the corporate resolver -- and it does not happen here.
#[test]
fn a_tunnels_nameservers_wait_for_the_document_to_ask() {
	let desired = document(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device vpn0 { openvpn { config = "/etc/netcfgd/work.ovpn" } }
interface vpn0 { }
"#,
	);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.reports.push(netcfgd_model::ObservedReport {
		interface: "vpn0".to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: vec!["10.0.0.53".to_owned()],
		search: Vec::new(),
		routes: vec![netcfgd_model::ReportedRoute {
			destination: "10.0.0.0/8".to_owned(),
			via: Some("10.8.0.1".to_owned()),
		}],
	});

	let plan = settle(&desired, &mut observed);
	assert!(
		delivered(&plan, "vpn0").is_empty(),
		"got {:?}",
		delivered(&plan, "vpn0")
	);
	// The route, on the same report, in the same plan. The two gates differ on
	// purpose and this is the assertion that says so -- without it, a change
	// that stopped believing the report at all would still pass the check
	// above.
	assert!(
		names(&plan).iter().any(|name| *name == "route.add"),
		"got {:?}",
		names(&plan)
	);
}

/// And they are delivered the moment it does. A `dns` block on the tunnel is
/// the operator saying which names travel this way; the servers that answer
/// them come from the report.
#[test]
fn a_dns_block_on_the_tunnel_is_what_asks() {
	let desired = document(
		r#"
global { dns { dns_mode = "dnsmasq" } }
device vpn0 {
	openvpn { config = "/etc/netcfgd/work.ovpn" }
}
interface vpn0 {
	dns { domains = ["corp.example"] }
}
"#,
	);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.reports.push(netcfgd_model::ObservedReport {
		interface: "vpn0".to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: vec!["10.0.0.53".to_owned()],
		search: Vec::new(),
		routes: Vec::new(),
	});

	let plan = settle(&desired, &mut observed);
	assert_eq!(delivered(&plan, "vpn0"), ["10.0.0.53"]);
}

/// A DSL line's resolvers, which are the one thing only pppd learns.
///
/// The same rule as a tunnel's and the same reason: `usepeerdns` gives netcfgd
/// the servers, and a `dns` block on the interface is the operator saying this
/// link answers for something. Without the block the report is read and
/// nothing is delivered.
#[test]
fn a_ppp_sessions_resolvers_follow_the_same_rule() {
	let config = |dns: &str| {
		format!(
			r#"
global {{ dns {{ dns_mode = "write_resolv_conf" }} }}
device ppp0 {{
	pppoe {{ parent = "eth0"; username = "alice"; password = "@secret:dsl" }}
}}
interface ppp0 {{
	{dns}
}}
"#
		)
	};
	let observe = || {
		let mut observed = observed_with(&["ppp0"]);
		observed.links[0].up = true;
		observed.reports.push(netcfgd_model::ObservedReport {
			interface: "ppp0".to_owned(),
			addresses: Vec::new(),
			gateways: Vec::new(),
			nameservers: vec!["195.190.228.10".to_owned()],
			search: Vec::new(),
			routes: Vec::new(),
		});
		observed
	};

	let desired = document(&config(""));
	let mut observed = observe();
	let plan = settle(&desired, &mut observed);
	assert!(
		delivered(&plan, "ppp0").is_empty(),
		"got {:?}",
		delivered(&plan, "ppp0")
	);

	let desired = document(&config("dns { }"));
	let mut observed = observe();
	let plan = settle(&desired, &mut observed);
	assert_eq!(delivered(&plan, "ppp0"), ["195.190.228.10"]);
}

/// The gate is the block, not what is in it.
///
/// `dns { }` on an interface asks for nothing of its own -- and that is exactly
/// what makes it the minimal way to say "this link's resolvers count". A host
/// with a flat resolver can take a tunnel's servers this way without a
/// scope-capable mode, which splitting would need.
#[test]
fn an_empty_dns_block_is_enough_to_claim_them() {
	let desired = document(
		r#"
global { dns { dns_mode = "write_resolv_conf" } }
device vpn0 {
	openvpn { config = "/etc/netcfgd/work.ovpn" }
}
interface vpn0 {
	dns { }
}
"#,
	);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.reports.push(netcfgd_model::ObservedReport {
		interface: "vpn0".to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: vec!["10.0.0.53".to_owned()],
		search: Vec::new(),
		routes: Vec::new(),
	});

	let plan = settle(&desired, &mut observed);
	assert_eq!(delivered(&plan, "vpn0"), ["10.0.0.53"]);
}

/// An edited SSID restarts the access point, which is what hostapd needs.
///
/// The gap project.md carried since 0041: hostapd reads its configuration once
/// and reports almost none of it back, so an SSID changed in the document left
/// the radio announcing the old one with an empty plan to explain it.
#[test]
fn an_edited_ssid_restarts_the_access_point() {
	let desired = document(
		r#"
device wlan0 { }
access_point "after" {
	device = "wlan0"
	wifi   { psk = "@secret:ap"; proto = "wpa2" }
}
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: Some(netcfgd_model::ObservedAccessPoint {
			ssid: netcfgd_model::Ssid::new(b"before".to_vec()).expect("an ssid"),
			band: None,
			channel: None,
		}),
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["backend.stop", "backend.start"]);
	assert_eq!(plan.actions[0].reason.field, "access_point.ssid");
	// And it says what the restart costs, because nothing else will.
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("deauthenticated")),
		"got {:?}",
		plan.warnings
	);
}

/// An edited `.ovpn` restarts the tunnel, and netcfgd never read the file.
///
/// The last of the stale-configuration questions (decision 0053). What the
/// planner sees is a boolean the observer computed from two hashes; the file
/// stays the operator's, which is what 0046 protects.
#[test]
fn an_edited_ovpn_restarts_the_tunnel() {
	let desired = document(r#"device vpn0 { openvpn { config = "/etc/netcfgd/work.ovpn" } }"#);
	let mut observed = observed_with(&["vpn0"]);
	observed.links[0].up = true;
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::OpenVpn,
		interface: "vpn0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: Some(false),
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["backend.stop", "backend.start"]);
	assert_eq!(plan.actions[0].reason.field, "openvpn.config");
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("drops it")),
		"got {:?}",
		plan.warnings
	);
}

/// And a tunnel running the file the document names is left alone -- including
/// when netcfgd could not check, which is not the same as a difference.
#[test]
fn a_tunnel_whose_file_is_unchanged_or_unreadable_is_left_alone() {
	let desired = document(r#"device vpn0 { openvpn { config = "/etc/netcfgd/work.ovpn" } }"#);
	for answer in [Some(true), None] {
		let mut observed = observed_with(&["vpn0"]);
		observed.links[0].up = true;
		observed.backends.push(netcfgd_model::ObservedBackend {
			kind: netcfgd_model::BackendKind::OpenVpn,
			interface: "vpn0".to_owned(),
			running: true,
			answering: None,
			access_control: None,
			started_with: None,
			secret_matches: None,
			config_matches: answer,
			advertised: Vec::new(),
		});

		let plan = plan(&desired, &observed, &PlanOptions::default());
		assert!(plan.actions.is_empty(), "{answer:?} got {:?}", names(&plan));
	}
}

/// An edited passphrase restarts it too, without the value going anywhere.
///
/// The one thing 0052 left open until the observer could answer it: the secret
/// is in neither the document nor the observation, so what travels is a
/// boolean, computed where both halves were already in hand. The reason names
/// the field and says which way it went and cannot print a passphrase, because
/// it never has one.
#[test]
fn an_edited_passphrase_restarts_the_access_point() {
	let desired = document(
		r#"
device wlan0 { }
access_point "home" {
	device = "wlan0"
	wifi   { psk = "@secret:ap"; proto = "wpa2" }
}
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		// The identity is unchanged; only the secret moved.
		started_with: Some(netcfgd_model::ObservedAccessPoint {
			ssid: netcfgd_model::Ssid::new(b"home".to_vec()).expect("an ssid"),
			band: None,
			channel: None,
		}),
		secret_matches: Some(false),
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["backend.stop", "backend.start"]);
	assert_eq!(plan.actions[0].reason.field, "access_point.wifi.psk");
}

/// "netcfgd could not check" is not a reason to deauthenticate a LAN.
///
/// `None` is the answer whenever anything is missing -- no document, no secret
/// in the store, an unreadable file -- and a restart on that would be a radio
/// dropped for a question nobody answered.
#[test]
fn a_secret_that_could_not_be_checked_restarts_nothing() {
	let desired = document(
		r#"
device wlan0 { }
access_point "home" {
	device = "wlan0"
	wifi   { psk = "@secret:ap"; proto = "wpa2" }
}
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: Some(netcfgd_model::ObservedAccessPoint {
			ssid: netcfgd_model::Ssid::new(b"home".to_vec()).expect("an ssid"),
			band: None,
			channel: None,
		}),
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.actions.is_empty(), "got {:?}", names(&plan));
}

/// An access point running what the document asks for is left alone, which is
/// what stops the restart happening on every reconcile.
#[test]
fn an_access_point_that_matches_is_not_restarted() {
	let desired = document(
		r#"
device wlan0 { }
access_point "home" {
	device  = "wlan0"
	channel = 6
	wifi    { psk = "@secret:ap"; proto = "wpa2" }
}
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: Some(netcfgd_model::ObservedAccessPoint {
			ssid: netcfgd_model::Ssid::new(b"home".to_vec()).expect("an ssid"),
			// The band the file records is the one netcfgd worked out from the
			// channel; the document states none. Comparing those would restart
			// the access point on every reconcile for a document nobody edited.
			band: Some("2.4".to_owned()),
			channel: Some(6),
		}),
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.actions.is_empty(), "got {:?}", names(&plan));
}

/// A renumbered delegation reloads what is being advertised.
///
/// The prefix is the one value in the document that arrives after the document
/// does, so an ISP that hands out a different block leaves a running daemon
/// announcing one the upstream has taken back -- every host on the LAN then
/// holds an address that does not route, and nothing in the config changed to
/// say so. radvd re-reads on `SIGHUP`, so this is a reload rather than a
/// restart and costs nothing on the wire.
#[test]
fn a_renumbered_delegation_reloads_the_advertisement() {
	let desired = document(
		r#"
device lan0 {
	kind   = "dummy"
}
interface lan0 {
	config = "@pd:wan0=::1/64"
	advertise { prefixes = ["@pd:wan0"] }
}
"#,
	);
	let mut observed = observed_with(&["lan0"]);
	observed.links[0].up = true;
	observed.delegations.push(netcfgd_model::Delegation {
		interface: "wan0".to_owned(),
		prefixes: vec!["2001:db8:5678::/56".to_owned()],
	});
	// Running, and started with the block the ISP has since taken back.
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::RouterAdvert,
		interface: "lan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: vec!["2001:db8:1234::/64".to_owned()],
	});
	// And the address it derived from the new one, so the only thing left to
	// do is the advertisement.
	observed.addresses.push(netcfgd_model::ObservedAddress {
		interface: "lan0".to_owned(),
		address: "2001:db8:5678::1/64".to_owned(),
		proto: Some(110),
		ownership: netcfgd_model::Ownership::Ours,
		origin: Some(netcfgd_model::Origin::Delegated),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["backend.reload"], "got {:?}", names(&plan));
	let reason = &plan.actions[0].reason;
	assert_eq!(reason.desired, "2001:db8:5678::/64");
	assert_eq!(reason.observed, "2001:db8:1234::/64");
}

/// And an advertisement that already matches is left alone, which is what
/// stops the reload happening on every reconcile.
#[test]
fn an_advertisement_that_matches_is_not_reloaded() {
	let desired = document(
		r#"
device lan0 {
	kind   = "dummy"
}
interface lan0 {
	config = "@pd:wan0=::1/64"
	advertise { prefixes = ["@pd:wan0"] }
}
"#,
	);
	let mut observed = observed_with(&["lan0"]);
	observed.links[0].up = true;
	observed.delegations.push(netcfgd_model::Delegation {
		interface: "wan0".to_owned(),
		prefixes: vec!["2001:db8:1234::/56".to_owned()],
	});
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::RouterAdvert,
		interface: "lan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: vec!["2001:db8:1234::/64".to_owned()],
	});
	observed.addresses.push(netcfgd_model::ObservedAddress {
		interface: "lan0".to_owned(),
		address: "2001:db8:1234::1/64".to_owned(),
		proto: Some(110),
		ownership: netcfgd_model::Ownership::Ours,
		origin: Some(netcfgd_model::Origin::Delegated),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.actions.is_empty(), "got {:?}", names(&plan));
}

/// A bearer gives you a way off the link, and without it an address is a
/// address on an island. The route comes from the report, not the document.
#[test]
fn a_reported_gateway_becomes_a_default_route() {
	let desired = reported_document();
	let mut observed = reporting(&["10.64.1.23/30"], &["10.64.1.24"]);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["addr.add", "route.add"]);
	let route = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "route.add")
		.expect("a route.add");
	let Op::RouteAdd { route, iface } = &route.op else {
		panic!("got {:?}", route.op);
	};
	assert_eq!(iface, "wwan0");
	assert_eq!(route.destination, "default");
	assert_eq!(
		route.via.map(|via| via.to_string()).as_deref(),
		Some("10.64.1.24")
	);
	// A cellular gateway is routinely outside every address the bearer was
	// given -- a /32 with a next hop elsewhere is the ordinary shape -- and the
	// kernel refuses such a route unless it is onlink.
	assert!(
		route.onlink,
		"a bearer's gateway is not covered by its address"
	);
}

/// Both families, which is why the report's `gateway` key repeats.
///
/// **Both are spelled `default`**, because that is the one word the kernel gives
/// back for either family -- a dump carries no destination for a default route
/// of either kind. The v6 one used to be spelled `::/0` here, which no
/// observation could ever match, so a dual-stack report added `::/0` and deleted
/// `default` on every reconcile. This assertion cannot catch that on its own,
/// since the harness's executor copies the destination it was given straight
/// into the observation; `tests/live/report.sh` does it against a real kernel.
#[test]
fn a_dual_stack_bearer_gets_a_default_route_each_way() {
	let desired = reported_document();
	let mut observed = reporting(
		&["10.64.1.23/30", "2001:db8::2/64"],
		&["10.64.1.24", "2001:db8::1"],
	);

	let plan = settle(&desired, &mut observed);
	let routes: Vec<(&str, String)> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { route, .. } => Some((
				route.destination.as_str(),
				route.via.map(|via| via.to_string()).unwrap_or_default(),
			)),
			_ => None,
		})
		.collect();
	assert_eq!(
		routes,
		[
			("default", "10.64.1.24".to_owned()),
			("default", "2001:db8::1".to_owned())
		]
	);
}

/// The bearer drops, the report stops naming the gateway, and the route goes --
/// the same withdrawal the address gets. A default route pointing down a dead
/// modem is worse than no route: it black-holes traffic that another interface
/// would have carried.
#[test]
fn the_default_route_goes_when_the_bearer_does() {
	let desired = reported_document();
	let mut observed = reporting(&["10.64.1.23/30"], &["10.64.1.24"]);
	settle(&desired, &mut observed);

	observed.reports[0].addresses.clear();
	observed.reports[0].gateways.clear();
	let plan = plan(&desired, &observed, &PlanOptions::default());
	let mut removed = names(&plan);
	removed.sort_unstable();
	assert_eq!(removed, ["addr.del", "route.del"]);
}

/// A route the report names outright, which is what a VPN server pushes and a
/// bearer normally does not. Decision 0047: the routes are the contested half,
/// so they are netcfgd's to install rather than the daemon's.
#[test]
fn a_reported_route_is_installed_with_its_next_hop() {
	let desired = reported_document();
	let mut observed = reporting_routes(&[
		("10.0.0.0/8", Some("10.8.0.1")),
		("192.168.44.0/24", Some("10.8.0.1")),
	]);

	let plan = settle(&desired, &mut observed);
	assert_eq!(
		added_routes(&plan),
		[
			("10.0.0.0/8".to_owned(), "10.8.0.1".to_owned()),
			("192.168.44.0/24".to_owned(), "10.8.0.1".to_owned())
		]
	);
}

/// A route with no next hop, which is what a point-to-point link gives: the
/// interface is the whole answer and there is nothing to be onlink about.
#[test]
fn a_reported_route_may_have_no_next_hop() {
	let desired = reported_document();
	let mut observed = reporting_routes(&[("172.16.0.0/12", None)]);

	let plan = settle(&desired, &mut observed);
	let route = plan
		.actions
		.iter()
		.find_map(|action| match &action.op {
			Op::RouteAdd { route, .. } => Some(route),
			_ => None,
		})
		.expect("a route.add");
	assert_eq!(route.destination, "172.16.0.0/12");
	assert_eq!(route.via, None);
	assert!(!route.onlink, "onlink means nothing without a gateway");
}

/// One spelling for the default route, whichever one the writer used. `openvpn`
/// says `0.0.0.0/0`, a person says `default`, and the kernel reports neither --
/// it reports no destination at all. A desired route spelled any other way
/// matches nothing observed and is added and deleted forever.
#[test]
fn every_spelling_of_the_default_route_becomes_one() {
	let desired = reported_document();
	let mut observed = reporting_routes(&[
		("0.0.0.0/0", Some("10.8.0.1")),
		("::/0", Some("fd00::1")),
		("default", Some("10.8.0.2")),
	]);

	let plan = settle(&desired, &mut observed);
	let destinations: Vec<String> = added_routes(&plan)
		.into_iter()
		.map(|(destination, _)| destination)
		.collect();
	assert_eq!(destinations, ["default", "default", "default"]);
}

/// The contract's rule for every other value, applied to this one: one bad line
/// does not discard the good ones. A destination that is not a prefix would
/// otherwise travel all the way to a netlink refusal, where nothing says which
/// file it came from.
#[test]
fn a_route_that_is_not_a_route_is_skipped_not_fatal() {
	let desired = reported_document();
	let mut observed = reporting_routes(&[
		("not-a-prefix", Some("10.8.0.1")),
		("10.0.0.0/8", Some("not-an-address")),
		("10.1.0.0/16", Some("10.8.0.1")),
	]);

	let plan = settle(&desired, &mut observed);
	assert_eq!(
		added_routes(&plan),
		[("10.1.0.0/16".to_owned(), "10.8.0.1".to_owned())]
	);
}

/// Rule 7 again, for the routes. The tunnel goes down, the report empties, and
/// what netcfgd installed on the strength of it goes with it.
#[test]
fn reported_routes_go_when_the_report_empties() {
	let desired = reported_document();
	let mut observed = reporting_routes(&[("10.0.0.0/8", Some("10.8.0.1"))]);
	settle(&desired, &mut observed);

	observed.reports[0].routes.clear();
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["route.del"]);
}

/// A report for an interface the document says nothing about is an observation
/// netcfgd has no instruction for. Installing a default route on the strength
/// of a file somebody dropped in `/run` is not something to invent.
#[test]
fn a_report_without_the_source_installs_no_route() {
	let desired = document(
		r#"device wwan0 { kind = "dummy" }
interface wwan0 { config = "null" }"#,
	);
	let mut observed = reporting(&["10.64.1.23/30"], &["10.64.1.24"]);
	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).is_empty(), "got {:?}", names(&plan));
}

/// The point of the source. Something reported an address; netcfgd installs it,
/// because the writer deliberately does not (`doc/interface-report.md`).
#[test]
fn a_reported_address_is_installed() {
	let desired = reported_document();
	let mut observed = reported_observed(&["10.64.1.23/30"]);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["addr.add"]);
	let added = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "addr.add")
		.expect("an addr.add");
	assert!(
		matches!(&added.op, Op::AddrAdd { addr, iface, .. }
			if addr == "10.64.1.23/30" && iface == "wwan0"),
		"got {:?}",
		added.op
	);
	// The reason sends the reader to the report rather than to the document,
	// because the document only names the source -- the value came from a file
	// somebody else wrote.
	assert!(
		added.reason.desired.contains("(reported)"),
		"got {:?}",
		added.reason
	);
}

/// Rule 7 for this source. A bearer that goes down empties the report, and the
/// address stops being wanted -- unlike a lease there is no client holding it
/// and no backend to restart, so the address is netcfgd's to withdraw.
#[test]
fn an_address_the_report_stops_naming_is_withdrawn() {
	let desired = reported_document();
	let mut observed = reported_observed(&["10.64.1.23/30"]);
	settle(&desired, &mut observed);

	// The bearer drops. The helper truncates its report, as the contract asks.
	observed.reports[0].addresses.clear();
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(names(&plan), ["addr.del"]);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("the link is down")),
		"got {:?}",
		plan.warnings
	);
}

/// No report at all is a different thing from a report with nothing in it, and
/// an operator needs to know which -- one means look at netcfgd, the other
/// means look at the helper.
#[test]
fn no_report_and_an_empty_report_say_different_things() {
	let desired = reported_document();

	let mut nothing = observed_with(&["wwan0"]);
	nothing.links[0].up = true;
	let plan = settle(&desired, &mut nothing);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("nothing has")),
		"got {:?}",
		plan.warnings
	);

	let mut empty = reported_observed(&[]);
	let plan = settle(&desired, &mut empty);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("the link is down")),
		"got {:?}",
		plan.warnings
	);
}

/// A `WireGuard` interface on `wg0`, with the device block the test needs.
fn wireguard_document(device: &str) -> Document {
	document(&format!(
		r#"
device wg0 {{
	{device}
	wireguard {{
		private_key = "@secret:wg0"
		peer hub {{
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			allowed_ips = "10.0.0.0/24"
		}}
	}}
}}
interface wg0 {{
	config = "10.0.0.5/32"
}}
"#
	))
}

/// `wg0` present, with or without a private key loaded in the kernel.
fn wireguard_observed(keyed: bool) -> Observed {
	let mut observed = observed_with(&["wg0"]);
	"wireguard".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].private_key_loaded = keyed;
	observed
}

/// The kernel state of `wg0` as decision 0054's comparison reads it.
///
/// `hub` is the peer `wireguard_document` declares, with the same allowed
/// prefix, so the default is a device that matches its document.
fn wireguard_running(port: Option<u16>, peers: &[&str]) -> netcfgd_model::ObservedWireGuard {
	netcfgd_model::ObservedWireGuard {
		public_key: Some(netcfgd_model::Key::from_bytes([0x11; 32])),
		listen_port: port,
		fwmark: None,
		key_matches: Some(true),
		peers: {
			let mut peers: Vec<netcfgd_model::ObservedWgPeer> = peers
				.iter()
				.map(|key| netcfgd_model::ObservedWgPeer {
					public_key: netcfgd_model::Key::parse(key).expect("a test key parses"),
					preshared_key: false,
					preshared_matches: None,
					endpoint: None,
					allowed_ips: vec!["10.0.0.0/24".to_owned()],
					keepalive: None,
				})
				.collect();
			peers.sort();
			peers
		},
	}
}

/// The peer `wireguard_document` names.
const HUB: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// A peer it does not.
const STRANGER: &str = "ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY=";

/// A device that matches its document plans nothing.
///
/// The check that has to come first. A comparison of two lists sorted
/// differently, or of a port the kernel chose against a port the document never
/// stated, differs on every reconcile -- and the plan that results is one an
/// operator watches reconfigure a working tunnel forever.
#[test]
fn a_wireguard_device_matching_its_document_plans_nothing() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	observed.links[0].wireguard = Some(wireguard_running(None, &[HUB]));

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetDevice { .. } | Op::WgSetPeers { .. })),
		"a device that matches its document was reconfigured: {:?}",
		plan.actions.iter().map(|a| a.op.name()).collect::<Vec<_>>()
	);
}

/// A peer the document no longer names is removed from the kernel.
///
/// Decision 0054, and the reason it is not a tidiness fix: an operator who
/// deletes a peer has revoked its access in their own mind. Before this, the
/// plan was empty and the peer kept the tunnel.
#[test]
fn a_peer_the_document_dropped_is_planned_away() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	observed.links[0].wireguard = Some(wireguard_running(None, &[HUB, STRANGER]));

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::WgSetPeers { .. }))
		.expect("the peer list differs, so it is replaced");
	assert_eq!(action.reason.field, "wireguard.peers");
	// The reason names which peers, because "the peer list changed" is not an
	// answer to "what did I just revoke". Public keys are not secret; they are
	// what one hands the other end.
	assert!(
		action.reason.observed.contains(STRANGER),
		"the reason does not name the peer being removed: {:?}",
		action.reason
	);
}

/// A rotated private key is planned, and names no key.
///
/// The comparison is the observer's -- a digest of what netcfgd loaded against
/// a digest of what the store holds -- so what reaches the planner is a
/// boolean, and a plan that could print a key would be a plan that writes one
/// into `/run/netcfgd/plan.last.json`.
#[test]
fn a_rotated_private_key_is_planned_without_naming_one() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	let mut running = wireguard_running(None, &[HUB]);
	running.key_matches = Some(false);
	observed.links[0].wireguard = Some(running);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::WgSetDevice { .. }))
		.expect("a rotated key is reconfigured");
	assert_eq!(action.reason.field, "wireguard.private_key");
	// The op carries a reference, which is the name of a secret rather than
	// one. Nothing else in the action may look like key material.
	let Op::WgSetDevice {
		private_key_ref, ..
	} = &action.op
	else {
		unreachable!("just matched")
	};
	assert_eq!(private_key_ref, "wg0");
}

/// "Could not check" is not "the key changed".
///
/// `None` is what a device netcfgd did not configure reports, and what a secret
/// that will not resolve reports. Rekeying a working tunnel over an unanswered
/// question is the failure `None is not false` names in decision 0052.
#[test]
fn a_key_that_could_not_be_checked_changes_nothing() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	let mut running = wireguard_running(None, &[HUB]);
	running.key_matches = None;
	observed.links[0].wireguard = Some(running);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetDevice { .. })),
		"an unanswered question rekeyed a tunnel"
	);
}

/// A peer whose preshared key was rotated has its list replaced.
///
/// Not a difference between the two peer lists: both say the peer has a
/// preshared key, because the kernel returns one zeroed. So the answer comes
/// from the observer as a boolean and is acted on separately -- and it produces
/// the same op, because the kernel takes a peer list rather than a peer.
#[test]
fn a_rotated_preshared_key_replaces_the_peer_list() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	let mut running = wireguard_running(None, &[HUB]);
	running.peers[0].preshared_key = true;
	running.peers[0].preshared_matches = Some(false);
	observed.links[0].wireguard = Some(running);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::WgSetPeers { .. }))
		.expect("a rotated preshared key replaces the list");
	assert_eq!(action.reason.field, "wireguard.peers.preshared_key");
	assert!(
		action.reason.observed.contains(HUB),
		"the reason does not name the peer: {:?}",
		action.reason
	);
}

/// And `None` from that comparison changes nothing, once more.
#[test]
fn a_preshared_key_that_could_not_be_checked_changes_nothing() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	let mut running = wireguard_running(None, &[HUB]);
	running.peers[0].preshared_matches = None;
	observed.links[0].wireguard = Some(running);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetPeers { .. })),
		"an unanswered question replaced a peer list"
	);
}

/// A listen port the document does not state is the kernel's to choose.
///
/// The trap decision 0052 fell into with an access point's band, arriving here
/// by a different road: a document that says nothing about a port is not a
/// document asking for the ephemeral one to change.
#[test]
fn a_port_the_document_never_stated_is_not_reconciled() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	observed.links[0].wireguard = Some(wireguard_running(Some(38_211), &[HUB]));

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetDevice { .. })),
		"an ephemeral port the document never asked about was reconfigured"
	);
}

/// A device that does not exist yet is configured by its creation, once.
///
/// `link.create` carries the whole configuration, so a second action saying the
/// peers differ would describe work the first action already did -- the shape
/// that had `PPPoE` dialling twice for a session that had not come up.
#[test]
fn a_device_being_created_is_not_also_reconfigured() {
	let desired = wireguard_document("");
	let observed = Observed::default();

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert_eq!(
		plan.actions
			.iter()
			.filter(|action| matches!(action.op, Op::WgSetDevice { .. } | Op::WgSetPeers { .. }))
			.count(),
		0,
		"a device being created was configured twice"
	);
}

/// Decision 0042. Walking away from a `WireGuard` key leaves whoever ends up
/// with the hardware able to be this host on that network, and revoking it is
/// an act by every peer rather than anything netcfgd or the operator can do
/// here.
#[test]
fn unmanaging_a_device_holding_a_wireguard_key_is_not_done_silently() {
	let desired = wireguard_document("managed = false");
	let observed = wireguard_observed(true);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.strands_credentials(), "got {:?}", plan.stranded);
	let stranded = &plan.stranded[0];
	assert_eq!(stranded.interface, "wg0");
	assert!(
		stranded.credential.contains("private key"),
		"got {:?}",
		stranded.credential
	);
	// Both ways out, because a notice an operator cannot act on is a complaint.
	assert!(stranded.remove_with.contains("on_unmanage = \"clear\""));
	assert!(stranded.consent_with.contains("--strand-credentials wg0"));
	// Nothing is dropped from the plan: `managed = false` already means no
	// actions for the device, so there is nothing to withhold.
	assert!(!plan.was_refused());
}

/// The consent is per device, and it is the whole of what the flag does.
#[test]
fn consenting_to_one_device_settles_it() {
	let desired = wireguard_document("managed = false");
	let observed = wireguard_observed(true);
	let options = PlanOptions {
		strand_credentials: vec!["wg0".to_owned()],
		..PlanOptions::default()
	};
	assert!(!plan(&desired, &observed, &options).strands_credentials());

	// And consenting to a different device does not settle this one, which is
	// the reason the flag names a device rather than being a blanket --force.
	let elsewhere = PlanOptions {
		strand_credentials: vec!["wg1".to_owned()],
		..PlanOptions::default()
	};
	assert!(plan(&desired, &observed, &elsewhere).strands_credentials());
}

/// `on_unmanage = "clear"` deletes the link netcfgd created, and the key goes
/// with it. Reporting a hazard the operator has already dealt with is how a
/// notice becomes something people pass over.
#[test]
fn clearing_is_the_answer_and_is_not_reported_as_the_problem() {
	let desired = wireguard_document(r#"managed = false; on_unmanage = "clear""#);
	let plan = plan(&desired, &wireguard_observed(true), &PlanOptions::default());
	assert!(!plan.strands_credentials(), "got {:?}", plan.stranded);
}

/// The kernel decides this, not the document. A document that declares a key
/// for an interface that was never applied strands nothing, and a notice about
/// it would be a notice about a file.
#[test]
fn a_key_that_was_never_loaded_is_not_stranded() {
	let desired = wireguard_document("managed = false");
	let unkeyed = plan(
		&desired,
		&wireguard_observed(false),
		&PlanOptions::default(),
	);
	assert!(!unkeyed.strands_credentials(), "got {:?}", unkeyed.stranded);

	// And the keyed case differs only in that one bit, so the check above
	// cannot be passing because the whole feature is switched off.
	let keyed = plan(&desired, &wireguard_observed(true), &PlanOptions::default());
	assert!(keyed.strands_credentials());
}

/// A managed device is not walking away from anything.
#[test]
fn a_managed_wireguard_device_strands_nothing() {
	let desired = wireguard_document("");
	let plan = plan(&desired, &wireguard_observed(true), &PlanOptions::default());
	assert!(!plan.strands_credentials(), "got {:?}", plan.stranded);
}

/// The narrow test decision 0042 turns on, checked by walking away from two
/// devices at once and reporting exactly one of them.
///
/// A supplicant's passphrases and a running hostapd's generated configuration
/// are copies of material sitting in the secrets directory on the same disk,
/// which neither policy touches -- so the operator cannot fix that exposure by
/// deciding, and a notice offering them the choice would offer a choice that
/// changes nothing.
///
/// **Both devices are in one document deliberately.** The first version of this
/// asserted only that the radio produced no notice, and it still passed with
/// the rule widened to every unmanaged interface -- because the radio has no
/// key loaded, so the *kind* check was never what excluded it. A check that
/// expects nothing is satisfied by the feature being off. This one fails at
/// zero notices and at two.
#[test]
fn a_radio_holding_passphrases_is_not_stranding_and_a_key_still_is() {
	let desired = document(
		r#"
device wlan0 { managed = false; wifi { } }
network "Home" { wifi { psk = "@secret:home" }; config = "dhcp" }

interface wlan0 { config = "dhcp" }

device wg0 {
	managed = false
	wireguard {
		private_key = "@secret:wg0"
		peer hub {
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			allowed_ips = "10.0.0.0/24"
		}
	}
}
interface wg0 {
	config = "10.0.0.5/32"
}
"#,
	);
	let mut observed = observed_with(&["wlan0", "wg0"]);
	for link in &mut observed.links {
		link.up = true;
	}
	"wireguard".clone_into(&mut observed.links[1].kind);
	observed.links[1].private_key_loaded = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Supplicant,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let named: Vec<&str> = plan
		.stranded
		.iter()
		.map(|stranded| stranded.interface.as_str())
		.collect();
	assert_eq!(
		named,
		["wg0"],
		"a WPA passphrase is revoked at the access point and sits in the secrets \
		 directory whichever policy is chosen; a WireGuard key is neither"
	);
	// The radio is still spoken about -- as the warning it always was.
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("passphrases")),
		"got {:?}",
		plan.warnings
	);
}

/// A document with an access point on `wlan0`, optionally with a station list.
fn access_point_document(access_control: Option<&str>) -> Document {
	document(&format!(
		r#"
device wlan0 {{ wifi {{ }} }}

access_point "guest" {{
	device  = "wlan0"
	channel = 6
	wifi    {{ open = true }}
	{}
}}

interface wlan0 {{ config = "null" }}
"#,
		access_control.unwrap_or("")
	))
}

/// A running access point, holding what the given lists say.
fn running_access_point(
	observed: &mut Observed,
	policy: netcfgd_model::ObservedPolicy,
	denied: &[&str],
	accepted: &[&str],
) {
	let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: Some(netcfgd_model::ObservedAccessControl {
			policy,
			denied: owned(denied),
			accepted: owned(accepted),
		}),
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
}

/// The point of decision 0041: an edited deny list reaches a running hostapd
/// without restarting it. Before this, a station added to the list stayed
/// associated until somebody restarted the access point by hand.
#[test]
fn an_edited_deny_list_converges_without_restarting_hostapd() {
	let desired = access_point_document(Some(
		r#"access_control { deny = ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"] }"#,
	));
	let mut observed = observed_with(&["wlan0"]);
	// hostapd read the list at startup and holds the first address only.
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Deny),
		&["00:11:22:33:44:55"],
		&[],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["access_control.add"]);
	assert!(
		!names(&plan).iter().any(|name| name.starts_with("backend.")),
		"restarting hostapd deauthenticates every client on the radio, which is \
		 what converging over the control socket exists to avoid: {:?}",
		names(&plan)
	);

	let added = &plan.actions[0];
	assert!(
		matches!(&added.op, Op::AccessControlAdd { station, list, iface }
			if station == "aa:bb:cc:dd:ee:ff"
				&& *list == netcfgd_model::AclPolicy::Deny
				&& iface == "wlan0"),
		"got {:?}",
		added.op
	);
	assert_eq!(added.reason.field, "access_point.access_control.stations");
	// Denying somebody takes their device off the network -- hostapd's
	// `DENY_ACL ADD_MAC` disassociates it -- so the guard has to see it.
	assert!(added.op.is_disruptive());
}

/// A station taken out of the deny list gets let back on, and that direction
/// interrupts nobody.
#[test]
fn a_station_removed_from_the_list_is_taken_off_hostapds() {
	let desired = access_point_document(Some(r#"access_control { deny = ["00:11:22:33:44:55"] }"#));
	let mut observed = observed_with(&["wlan0"]);
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Deny),
		&["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
		&[],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["access_control.del"]);
	assert!(
		!plan.actions[0].op.is_disruptive(),
		"letting a station back on interrupts nobody, and a guard that blocked \
		 it would block the repair for a deny list with the wrong address in it"
	);
}

/// hostapd's `hostapd_check_acl` consults the accept list *first* and the deny
/// list second, whatever `macaddr_acl` says -- so a station left on the accept
/// list is accepted despite being on the deny list the document wrote. The list
/// the policy does not name is not inert, and leaving it alone would leave a
/// deny list that looks applied and is not.
#[test]
fn the_list_the_policy_does_not_name_is_emptied_too() {
	let desired = access_point_document(Some(r#"access_control { deny = ["aa:bb:cc:dd:ee:ff"] }"#));
	let mut observed = observed_with(&["wlan0"]);
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Deny),
		&["aa:bb:cc:dd:ee:ff"],
		&["aa:bb:cc:dd:ee:ff"],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["access_control.del"]);
	assert!(
		matches!(&plan.actions[0].op, Op::AccessControlDel { list, .. }
			if *list == netcfgd_model::AclPolicy::Allow),
		"the entry overriding the deny list is the one that has to go: {:?}",
		plan.actions[0].op
	);
}

/// The policy is the one thing that cannot be converged in place: `macaddr_acl`
/// is only read at startup, and converging the lists without it would enforce
/// the new list under the old default. A document changed from `deny` to
/// `allow` would leave every unlisted station accepted -- an open network,
/// reported as applied.
#[test]
fn a_changed_policy_restarts_the_access_point_rather_than_converging_blind() {
	let desired =
		access_point_document(Some(r#"access_control { allow = ["aa:bb:cc:dd:ee:ff"] }"#));
	let mut observed = observed_with(&["wlan0"]);
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Deny),
		&["00:11:22:33:44:55"],
		&[],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["backend.stop", "backend.start"]);
	assert!(
		!names(&plan)
			.iter()
			.any(|name| name.starts_with("access_control.")),
		"converging the lists under a policy hostapd has not been told about is \
		 exactly the silent failure this restart exists to prevent: {:?}",
		names(&plan)
	);

	let start = &plan.actions[1];
	assert!(
		start.depends_on.contains(&plan.actions[0].id),
		"hostapd was started before it was stopped"
	);
	assert_eq!(
		plan.actions[0].reason.field,
		"access_point.access_control.policy"
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("deauthenticated")),
		"a restart takes every station off the radio and has to say so: {:?}",
		plan.warnings
	);
}

/// Deleting the whole block is a policy change too, in the direction that stops
/// enforcing one. It cannot be an empty deny list: `macaddr_acl` stays at
/// whatever hostapd was started with, and under `allow` an emptied accept list
/// is a network nobody can join.
#[test]
fn deleting_the_block_restarts_rather_than_emptying_the_list() {
	let desired = access_point_document(None);
	let mut observed = observed_with(&["wlan0"]);
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Allow),
		&[],
		&["aa:bb:cc:dd:ee:ff"],
	);

	let plan = settle(&desired, &mut observed);
	assert_eq!(names(&plan), ["backend.stop", "backend.start"]);
}

/// No record of what hostapd was started with means netcfgd cannot tell which
/// list it consults by default. Nothing may be converged from there -- under
/// `deny` an emptied accept list is nothing and under `allow` it is a lockout --
/// so it says so instead of guessing.
#[test]
fn an_unrecorded_policy_converges_nothing_and_says_why() {
	let desired = access_point_document(Some(r#"access_control { deny = ["aa:bb:cc:dd:ee:ff"] }"#));
	let mut observed = observed_with(&["wlan0"]);
	running_access_point(
		&mut observed,
		netcfgd_model::ObservedPolicy::Unknown,
		&[],
		&["00:11:22:33:44:55"],
	);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		names(&plan).is_empty(),
		"converging against a guess is how an access point ends up closed: {:?}",
		names(&plan)
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("no record")),
		"silence here reports a station list as applied when it was not: {:?}",
		plan.warnings
	);
}

/// An access point netcfgd cannot reach has no in-memory list to converge. It
/// reads the generated file when it starts, and that file is already the
/// document.
///
/// The reachable half is asserted alongside deliberately. This is a check that
/// expects *nothing*, and the whole feature being broken would satisfy it
/// perfectly -- so the same document against the same access point, differing
/// only in whether netcfgd could ask it, has to produce the action.
#[test]
fn an_unreachable_access_point_is_not_converged_against() {
	let desired = access_point_document(Some(r#"access_control { deny = ["aa:bb:cc:dd:ee:ff"] }"#));

	let mut unreachable = observed_with(&["wlan0"]);
	unreachable.links[0].up = true;
	unreachable.backends.push(ObservedBackend {
		kind: BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	let plan = settle(&desired, &mut unreachable);
	assert!(names(&plan).is_empty(), "got {:?}", names(&plan));

	let mut reachable = observed_with(&["wlan0"]);
	running_access_point(
		&mut reachable,
		netcfgd_model::ObservedPolicy::Set(netcfgd_model::AclPolicy::Deny),
		&[],
		&[],
	);
	assert_eq!(
		names(&settle(&desired, &mut reachable)),
		["access_control.add"],
		"the empty plan above would pass just as well with the feature removed"
	);
}

/// Deleting the block stops the access point. The radio is still a radio, so
/// "is this device wireless" is the wrong question to ask here -- the right
/// one is whether the document still names an access point on it.
#[test]
fn an_access_point_stops_when_its_block_goes() {
	let desired = document(r#"interface wlan0 { config = "null" }"#);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	let plan = plan(&desired, &observed, &PlanOptions::default());

	let stop = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "backend.stop")
		.expect("a stop");
	assert_eq!(stop.reason.field, "access_point");
}

/// One radio does not do both halves at once. Getting this wrong is not a
/// missing feature but an oscillation: the access-point pass starts hostapd,
/// the station pass wants a supplicant, and each reconcile stops what the last
/// one started. `settle` is what catches that, by re-planning after applying.
#[test]
fn a_radio_running_an_access_point_does_not_also_join_networks() {
	let desired = document(
		r#"
device wlan0 { wifi { } }

network "home" { wifi { psk = "@secret:home" } }

access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
}

interface wlan0 { config = "192.168.9.1/24" }
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	let plan = settle(&desired, &mut observed);

	let starts: Vec<&Op> = plan
		.actions
		.iter()
		.map(|action| &action.op)
		.filter(|op| op.name() == "backend.start")
		.collect();
	assert_eq!(starts.len(), 1, "{starts:?}");
	assert!(
		matches!(
			starts[0],
			Op::BackendStart {
				kind: BackendKind::AccessPoint,
				..
			}
		),
		"{starts:?}"
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("not also joining")),
		"nothing said the station side was dropped: {:?}",
		plan.warnings
	);
}

/// Turning a station into an access point stops the supplicant.
///
/// The case the arm above cannot see. A radio that was joining networks has a
/// supplicant *running*, and adding an `access_point` block has to take it
/// away -- otherwise the radio has a supplicant trying to associate and
/// hostapd trying to beacon on the same interface, which is a fight the
/// operator did not ask for and neither pass would ever resolve.
#[test]
fn a_radio_promoted_to_an_access_point_loses_its_supplicant() {
	let desired = document(
		r#"
device wlan0 { wifi { } }

network "home" { wifi { psk = "@secret:home" } }

access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
}

interface wlan0 { config = "null" }
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.backends.push(ObservedBackend {
		kind: BackendKind::Supplicant,
		interface: "wlan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	let plan = plan(&desired, &observed, &PlanOptions::default());

	let stopped: Vec<&Op> = plan
		.actions
		.iter()
		.map(|action| &action.op)
		.filter(|op| op.name() == "backend.stop")
		.collect();
	assert!(
		matches!(
			stopped.as_slice(),
			[Op::BackendStop {
				kind: BackendKind::Supplicant,
				..
			}]
		),
		"the supplicant was left running alongside hostapd: {stopped:?}"
	);
}

/// An access point on a device with no `interface` block is configured and
/// unreachable: nothing brings the radio up, so nothing starts hostapd. That
/// is a plan with no actions in it, which without a warning reads as "already
/// correct".
#[test]
fn an_access_point_needs_an_interface_block_to_run_on() {
	let desired = document(
		r#"
access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
}
"#,
	);
	let plan = plan(
		&desired,
		&observed_with(&["wlan0"]),
		&PlanOptions::default(),
	);

	assert!(plan.is_empty(), "{:?}", names(&plan));
	let warning = plan
		.warnings
		.iter()
		.find(|warning| warning.message.contains("no `interface` block"))
		.expect("a warning about the missing interface block");
	assert_eq!(warning.interface.as_deref(), Some("wlan0"));
}

/// Two access points on one radio needs multiple BSSes, which this build does
/// not have. The plan and the executor have to agree on *which* one runs, or
/// the plan names one and hostapd serves another.
#[test]
fn two_access_points_on_one_radio_run_the_first_by_name() {
	let desired = document(
		r#"
access_point "aaa" { device = "wlan0"; wifi { open = true } }
access_point "zzz" { device = "wlan0"; wifi { open = true } }

interface wlan0 { config = "null" }
"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	let plan = settle(&desired, &mut observed);

	assert_eq!(
		names(&plan)
			.iter()
			.filter(|name| **name == "backend.start")
			.count(),
		1
	);
	let warning = plan
		.warnings
		.iter()
		.find(|warning| warning.message.contains("one BSS per radio"))
		.expect("a warning about the second access point");
	assert!(
		warning.message.contains("`aaa` is started") && warning.message.contains("`zzz` is not"),
		"the warning has to name which one runs: {}",
		warning.message
	);
}

/// `managed = false` means netcfgd never touches the device.
///
/// The model has said so since M1 and the planner honoured it in exactly one
/// place -- the filter that decides which devices are radios. Everything else
/// ignored it, so the escape hatch documented in first-run.md for handing an
/// interface to another daemon planned three actions against it.
#[test]
fn an_unmanaged_device_is_not_touched() {
	let desired = document(
		r#"
device probe0 {
	managed = false
	kind   = "dummy"
}
interface probe0 {
	config = "10.5.5.1/24"
}

device probe1 {
	kind   = "dummy"
}
interface probe1 {
	config = "10.6.6.1/24"
}
"#,
	);
	let plan = plan(&desired, &observed_with(&[]), &PlanOptions::default());

	// Nothing for the unmanaged one, everything for its neighbour -- which is
	// what stops this passing because the planner did nothing at all.
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| action.op.interface() == Some("probe0")),
		"{:?}",
		names(&plan)
	);
	assert!(plan
		.actions
		.iter()
		.any(|action| action.op.interface() == Some("probe1")));

	// And it says so: a plan that silently does nothing about a block somebody
	// wrote is the failure this project keeps refusing to ship.
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("managed = false")),
		"{:?}",
		plan.warnings
	);
}

/// Walking away means walking away: a device that netcfgd configured before
/// the flag was set is left exactly as it is, rather than torn down.
///
/// The alternative -- release what we own, then stop -- would make marking
/// something unmanaged briefly disrupt it, which is the opposite of what the
/// flag is reached for.
#[test]
fn an_unmanaged_device_is_not_torn_down_either() {
	let desired = document("device probe0 { managed = false }");
	let mut observed = observed_with(&["probe0"]);
	observed.links[0].up = true;
	observed.links[0].ownership = Ownership::Ours;
	observed.addresses.push(ObservedAddress {
		interface: "probe0".to_owned(),
		address: "10.5.5.1/24".to_owned(),
		proto: None,
		ownership: Ownership::Ours,
		origin: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.is_empty(), "{:?}", names(&plan));
}

/// `on_unmanage = "clear"` empties the device first, then leaves it alone.
///
/// The point of the policy: walking away from a device strands whatever
/// netcfgd put on it, including credentials. Clearing is defined by ownership
/// rather than by content, so one rule covers every device -- it removes what
/// carries netcfgd's tag and nothing else.
#[test]
fn a_cleared_device_is_emptied_and_then_left_alone() {
	let desired = document(
		r#"
device probe0 {
	managed = false; on_unmanage = "clear"
	kind   = "dummy"
}
interface probe0 {
	config = "10.5.5.1/24"
}
"#,
	);
	let mut observed = observed_with(&["probe0"]);
	observed.links[0].up = true;
	observed.links[0].kind = "dummy".to_owned();
	observed.links[0].ownership = Ownership::Ours;
	observed.addresses.push(ObservedAddress {
		interface: "probe0".to_owned(),
		address: "10.5.5.1/24".to_owned(),
		proto: None,
		ownership: Ownership::Ours,
		origin: Some(Origin::Static),
	});

	let first = plan(&desired, &observed, &PlanOptions::default());
	assert!(names(&first).contains(&"addr.del"), "{:?}", names(&first));
	// And nothing is added back: planning an address and removing it in the
	// same plan is a loop rather than a convergence, which is why the forward
	// passes stay switched off for a device being cleared.
	assert!(!names(&first).contains(&"addr.add"), "{:?}", names(&first));

	// Once emptied, there is nothing left to do -- the policy is a state, so
	// it stops on its own rather than needing an edge to be detected.
	let emptied = plan(&desired, &observed_with(&[]), &PlanOptions::default());
	assert!(emptied.is_empty(), "{:?}", names(&emptied));
}

/// Clearing removes what netcfgd owns and nothing else. Whoever takes the
/// device over keeps their own configuration -- which is the property that
/// makes one rule safe on every device.
#[test]
fn clearing_leaves_what_netcfgd_did_not_put_there() {
	let desired = document(r#"device probe0 { managed = false; on_unmanage = "clear" }"#);
	let mut observed = observed_with(&["probe0"]);
	observed.links[0].up = true;
	observed.addresses.push(ObservedAddress {
		interface: "probe0".to_owned(),
		address: "192.0.2.9/24".to_owned(),
		proto: None,
		ownership: Ownership::Foreign,
		origin: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.is_empty(), "{:?}", names(&plan));
}

/// The default is still to walk away. A device that says nothing about
/// `on_unmanage` keeps the behaviour decision 0035 settled on, because you set
/// `managed = false` when something else is taking over and having netcfgd
/// pull the addresses out on its way past is the failure the flag prevents.
#[test]
fn leaving_is_still_what_happens_by_default() {
	let desired = document(r"device probe0 { managed = false }");
	let mut observed = observed_with(&["probe0"]);
	observed.links[0].up = true;
	observed.links[0].ownership = Ownership::Ours;
	observed.addresses.push(ObservedAddress {
		interface: "probe0".to_owned(),
		address: "10.5.5.1/24".to_owned(),
		proto: None,
		ownership: Ownership::Ours,
		origin: Some(Origin::Static),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(plan.is_empty(), "{:?}", names(&plan));
}

/// An unmanaged interface's DNS scope is not applied either. `dns.apply` is
/// host-wide and names no interface, so it is the one action the check in
/// `push` cannot see.
#[test]
fn an_unmanaged_interface_contributes_no_dns_scope() {
	let desired = document(
		r#"
device probe0 {
	managed = false
	kind = "dummy"
}
interface probe0 {
	dns  { mode = "write_resolv_conf"; servers = ["10.5.5.53"] }
}
"#,
	);
	let plan = plan(&desired, &observed_with(&[]), &PlanOptions::default());
	assert!(!names(&plan).contains(&"dns.apply"), "{:?}", names(&plan));
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
	simulate(&first, &mut observed, &document);
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

	simulate(&second, &mut observed, &document);
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
device ppp0 {
	pppoe { parent = "eth0"; username = "a"; password = "@secret:dsl" }
}
interface ppp0 {
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
			.any(|warning| warning.message.contains("tunnel is not up yet")),
		"got {:?}",
		plan.warnings
	);
}

/// Once the session is up the interface is ordinary, and its route lands.
#[test]
fn a_live_ppp_interface_gets_its_route() {
	let document = document(
		r#"
device ppp0 {
	pppoe { parent = "eth0"; username = "a"; password = "@secret:dsl" }
}
interface ppp0 {
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
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
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
device br0 { bridge { vlan_filtering = true } }
interface br0 { config = "null" }
device lan1 { master = "br0"; vlans = "10 pvid untagged" }
interface lan1 { config = "null" }
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
device br0 { bridge { vlan_filtering = true } }
interface br0 { config = "null" }
device other { master = "br0" }
interface other { config = "null" }
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
device br0 { bridge { vlan_filtering = true } }
interface br0 { config = "null" }
device lan1 { master = "br0"; vlans = "10 pvid untagged" }
interface lan1 { config = "null" }
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

	simulate(&plan, &mut observed, &document);
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
		device eth0 {
			qdisc  = "fq_codel"
		}
		interface eth0 {
			config = "10.0.0.2/24"
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
		device eth0 {
			qdisc {
				kind      = "cake"
				bandwidth = "100mbit"
			}
		}
		interface eth0 {
			config = "10.0.0.2/24"
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

/// A kernel that reports no qdisc at all must not be reset for ever.
///
/// `plan_qdisc` says "every interface always has a qdisc, so this is never
/// install-where-absent". Nothing enforced that, and an observation with no
/// qdisc produced a reset that could change nothing.
///
/// **This is not the `qdisc.sh` container failure**, though it was written
/// believing it was. That diagnostic reads `qdisc: <absent> (was noqueue)`,
/// and `Reason::unwanted` puts the *desired* value first -- so `<absent>` is
/// the configuration asking for no qdisc, and the observed value was
/// `noqueue`, not nothing. The case below is a real gap and a cheap guard; it
/// is not that bug, which is still open.
#[test]
fn an_absent_qdisc_is_nothing_to_reset() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	// The container's kernel: no qdisc reported at all.
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.qdisc = None;
	}
	// And netcfgd's record still says it set one, which is the state that
	// makes this loop rather than merely being odd.
	observed.qdisc_applied = vec!["eth0".to_owned()];

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"qdisc.reset"),
		"there is no qdisc to reset, so nothing should be planned: {:?}",
		names(&plan)
	);
}

/// `ingress_bandwidth` builds the whole ingress path: a device to redirect
/// onto, a shaper on it, and the redirect itself.
///
/// The ordering assertion is the one that matters. Traffic redirected onto a
/// device that is not yet shaped is traffic that is not being shaped, so the
/// `ifb` has to exist and carry its qdisc before anything is pointed at it.
#[test]
fn ingress_shaping_builds_a_device_a_shaper_and_a_redirect() {
	let desired = document(
		r#"
		device wan0 {
			qdisc {
				kind              = "cake"
				bandwidth         = "100mbit"
				ingress_bandwidth = "50mbit"
			}
		}
		interface wan0 {
			config = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["wan0"]);
	let plan = settle(&desired, &mut observed);

	assert!(
		names(&plan).contains(&"ingress.redirect"),
		"{:?}",
		names(&plan)
	);
	assert!(
		position(&plan, "link.create") < position(&plan, "ingress.redirect"),
		"the ifb must exist before traffic is sent to it: {:?}",
		names(&plan)
	);
	assert_eq!(
		observed
			.link("wan0")
			.and_then(|l| l.ingress_redirect.as_deref()),
		Some("ifb-wan0")
	);
	// The shaper on the ifb is told it is metering arrivals, which changes
	// what cake counts.
	let ifb = observed.link("ifb-wan0").expect("the ifb");
	assert_eq!(ifb.qdisc.as_deref(), Some("cake"));
	assert_eq!(ifb.qdisc_bandwidth_bits, Some(50_000_000));
	assert!(ifb.qdisc_ingress);
}

/// Dropping `ingress_bandwidth` takes the redirect and the device away.
#[test]
fn removing_ingress_shaping_removes_the_whole_path() {
	let desired = document(
		r#"
		device wan0 {
			qdisc  = "fq_codel"
		}
		interface wan0 {
			config = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["wan0", "ifb-wan0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "wan0") {
		link.ingress_redirect = Some("ifb-wan0".to_owned());
	}
	observed.ingress_applied = vec!["wan0".to_owned()];
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "ifb-wan0") {
		link.ownership = Ownership::Ours;
	}

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"ingress.redirect.clear"));
	assert!(names(&plan).contains(&"link.delete"));
	assert_eq!(
		observed
			.link("wan0")
			.and_then(|l| l.ingress_redirect.as_deref()),
		None
	);
}

/// A redirect netcfgd did not install is left where it is.
#[test]
fn a_redirect_netcfgd_did_not_install_is_left_alone() {
	let desired = document("interface wan0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["wan0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "wan0") {
		link.ingress_redirect = Some("ifb0".to_owned());
	}

	let plan = settle(&desired, &mut observed);
	assert!(
		!names(&plan).contains(&"ingress.redirect.clear"),
		"{:?}",
		names(&plan)
	);
}

/// A rule is installed once and then left alone.
#[test]
fn a_rule_is_installed_once_and_then_left_alone() {
	let desired = document(
		r#"
		interface eth0 { config = "10.0.0.2/24" }
		rule "uplink" {
			priority = 1000
			from     = "10.9.0.0/16"
			lookup   = 100
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	assert!(names(&plan).contains(&"rule.add"), "{:?}", names(&plan));
	assert_eq!(observed.rules.len(), 1);
	assert_eq!(observed.rules[0].priority, 1000);
}

/// Changing a selector reinstalls: the kernel keys on priority, so the old one
/// has to go first or the add is EEXIST.
#[test]
fn changing_a_selector_replaces_the_rule() {
	let desired = document(
		r#"
		interface eth0 { config = "10.0.0.2/24" }
		rule "uplink" {
			priority = 1000
			from     = "10.8.0.0/16"
			lookup   = 100
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.rules.push(netcfgd_model::ObservedRule {
		priority: 1000,
		family: netcfgd_model::RuleFamily::Inet,
		from: Some("10.9.0.0/16".to_owned()),
		to: None,
		iif: None,
		oif: None,
		fwmark: None,
		fwmask: None,
		table: Some(100),
		action: netcfgd_model::RuleAction::Lookup,
		suppress_prefixlength: None,
		l3mdev: false,
		invert: false,
		ownership: Ownership::Ours,
	});

	let plan = settle(&desired, &mut observed);
	let names = names(&plan);
	assert!(names.contains(&"rule.del"), "{names:?}");
	assert!(
		position(&plan, "rule.del") < position(&plan, "rule.add"),
		"the old rule must go before the new one: {names:?}"
	);
	assert_eq!(observed.rules[0].from.as_deref(), Some("10.8.0.0/16"));
}

/// A rule netcfgd did not install is never removed, and the collision is
/// reported rather than resolved.
#[test]
fn a_foreign_rule_at_the_same_priority_is_reported_not_removed() {
	let desired = document(
		r#"
		interface eth0 { config = "10.0.0.2/24" }
		rule "uplink" {
			priority = 1000
			lookup   = 100
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.rules.push(netcfgd_model::ObservedRule {
		priority: 1000,
		family: netcfgd_model::RuleFamily::Inet,
		from: None,
		to: None,
		iif: None,
		oif: None,
		fwmark: None,
		fwmask: None,
		table: Some(254),
		action: netcfgd_model::RuleAction::Lookup,
		suppress_prefixlength: None,
		l3mdev: false,
		invert: false,
		ownership: Ownership::Foreign,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(!names(&plan).contains(&"rule.del"), "{:?}", names(&plan));
	assert!(plan
		.warnings
		.iter()
		.any(|w| w.message.contains("netcfgd does not own")));
}

/// Dropping a rule from the document removes it.
#[test]
fn removing_a_rule_from_the_config_withdraws_it() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	observed.rules.push(netcfgd_model::ObservedRule {
		priority: 1000,
		family: netcfgd_model::RuleFamily::Inet,
		from: None,
		to: None,
		iif: None,
		oif: None,
		fwmark: None,
		fwmask: None,
		table: Some(100),
		action: netcfgd_model::RuleAction::Lookup,
		suppress_prefixlength: None,
		l3mdev: false,
		invert: false,
		ownership: Ownership::Ours,
	});

	let plan = settle(&desired, &mut observed);
	assert!(names(&plan).contains(&"rule.del"));
	assert!(observed.rules.is_empty());
}

/// A token is set once and then left alone.
#[test]
fn an_ipv6_token_is_set_once_and_then_left_alone() {
	let desired = document(
		r#"
		interface eth0 {
			config     = "10.0.0.2/24"
			ipv6_token = "::5"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	let plan = settle(&desired, &mut observed);

	assert!(
		names(&plan).contains(&"link.set_ipv6_token"),
		"{:?}",
		names(&plan)
	);
	assert_eq!(
		observed.link("eth0").and_then(|l| l.ipv6_token.as_deref()),
		Some("::5")
	);
}

/// The same token spelled differently is the same token.
///
/// The kernel reports its own spelling, so comparing text would reinstall on
/// every apply for anybody who wrote the long form.
#[test]
fn a_token_is_compared_as_an_address_not_as_text() {
	let desired = document(
		r#"
		interface eth0 {
			config     = "10.0.0.2/24"
			ipv6_token = "0:0:0:0:0:0:0:5"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.ipv6_token = Some("::5".to_owned());
	}

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"link.set_ipv6_token"),
		"{:?}",
		names(&plan)
	);
}

/// A token the document does not mention is left where it is.
///
/// It carries no ownership tag and the kernel offers no way to tell one
/// netcfgd set from one an operator set, so removing it would be a guess.
#[test]
fn a_token_nobody_asked_about_is_left_alone() {
	let desired = document("interface eth0 { config = \"10.0.0.2/24\" }");
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.ipv6_token = Some("::9".to_owned());
	}

	let plan = settle(&desired, &mut observed);
	assert!(
		!names(&plan).contains(&"link.set_ipv6_token"),
		"{:?}",
		names(&plan)
	);
	assert_eq!(
		observed.link("eth0").and_then(|l| l.ipv6_token.as_deref()),
		Some("::9")
	);
}

/// An offload is set once and then left alone.
#[test]
fn an_offload_is_set_once_and_then_left_alone() {
	let desired = document(
		r#"
		device eth0 {
			ethtool { gro = "off" }
		}
		interface eth0 {
			config  = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.offloads = vec!["rx-gro".to_owned()];
	}

	let plan = settle(&desired, &mut observed);
	assert!(
		names(&plan).contains(&"link.set_offloads"),
		"{:?}",
		names(&plan)
	);
	assert!(observed.link("eth0").is_some_and(|l| l.offloads.is_empty()));
}

/// An offload already in the wanted state plans nothing.
#[test]
fn an_offload_already_correct_plans_nothing() {
	let desired = document(
		r#"
		device eth0 {
			ethtool { gro = "on" }
		}
		interface eth0 {
			config  = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.offloads = vec!["rx-gro".to_owned()];
	}

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"link.set_offloads"),
		"{:?}",
		names(&plan)
	);
}

/// An offload the document does not mention is not touched.
///
/// The kernel takes a mask bitset, so a request names exactly what changes.
/// Sending the full set would turn off every offload the config is silent
/// about, which is most of them.
#[test]
fn an_unmentioned_offload_is_not_in_the_request() {
	let desired = document(
		r#"
		device eth0 {
			ethtool { gro = "off" }
		}
		interface eth0 {
			config  = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.offloads = vec!["rx-gro".to_owned(), "tx-tcp-segmentation".to_owned()];
	}

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|a| a.op.name() == "link.set_offloads")
		.expect("an offload action");
	let netcfgd_plan::Op::LinkSetOffloads { features, .. } = &action.op else {
		panic!("wrong op");
	};
	assert_eq!(features, &vec![("rx-gro".to_owned(), false)]);
}

/// Transmit checksumming is several kernel features and moves together.
#[test]
fn transmit_checksumming_covers_every_spelling() {
	let desired = document(
		r#"
		device eth0 {
			ethtool { tx_checksum = "off" }
		}
		interface eth0 {
			config  = "10.0.0.2/24"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	if let Some(link) = observed.links.iter_mut().find(|l| l.name == "eth0") {
		link.offloads = vec!["tx-checksum-ip-generic".to_owned()];
	}

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|a| a.op.name() == "link.set_offloads")
		.expect("an offload action");
	let netcfgd_plan::Op::LinkSetOffloads { features, .. } = &action.op else {
		panic!("wrong op");
	};
	assert_eq!(features.len(), 3, "{features:?}");
	assert!(features.iter().all(|(_, on)| !on));
}

/// A peer with an endpoint plans nothing, which is not what it did.
///
/// The comparison sets the desired endpoint to `None` because a peer roams and
/// the kernel rewrites it -- and the observation carries what the kernel says,
/// which after one handshake is an address. Comparing those two as values makes
/// every reconcile replace the peer list forever. The live test could not see
/// it: its peers have no endpoint and never handshake, so both sides were
/// `None` and agreed for the wrong reason.
#[test]
fn a_peer_with_an_endpoint_is_not_replaced_on_every_reconcile() {
	let desired = wireguard_document("");
	let mut observed = wireguard_observed(true);
	let mut running = wireguard_running(None, &[HUB]);
	running.peers[0].endpoint = Some("198.51.100.7:51820".to_owned());
	observed.links[0].wireguard = Some(running);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetPeers { .. })),
		"a roaming peer's endpoint was treated as a difference"
	);
}

/// A document that spells "none" as zero agrees with a kernel that omits it.
///
/// The kernel says "no firewall mark", "no keepalive" and "an ephemeral port"
/// with a zero, and the observation turns each into an absent field. A document
/// is allowed to write the zero, and if it arrived any other way the device
/// would differ from the kernel on every reconcile -- the same shape as the
/// endpoint, from the other side.
#[test]
fn a_zero_in_the_document_means_what_the_kernel_means_by_one() {
	let desired = document(
		r#"
device wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 0
		fwmark      = 0
		peer hub {
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			allowed_ips = "10.0.0.0/24"
			keepalive   = 0
		}
	}
}
interface wg0 {
	config = "10.0.0.5/32"
}
"#,
	);
	let mut observed = wireguard_observed(true);
	// What the kernel reports for exactly that: a port it chose, and nothing
	// for the mark or the keepalive.
	observed.links[0].wireguard = Some(wireguard_running(Some(45_678), &[HUB]));

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::WgSetDevice { .. } | Op::WgSetPeers { .. })),
		"a zero the kernel spells as absent was treated as a difference: {:?}",
		plan.actions
			.iter()
			.map(|action| (action.op.name(), action.reason.field.clone()))
			.collect::<Vec<_>>()
	);
}

/// A bridge whose settings the document moved is corrected.
///
/// Decision 0057. `stp` and `forward_delay` went over the wire inside
/// `link.create` and were never sent again, so editing either planned nothing
/// -- and a bridge's name encodes nothing, so unlike a VLAN there was no second
/// signal to notice instead.
#[test]
fn an_edited_bridge_setting_is_planned() {
	let desired = document(
		r#"
device br0 {
	bridge { stp = false; forward_delay = 20 }
}
interface br0 {
	config = "10.4.0.1/24"
}
"#,
	);
	let mut observed = observed_with(&["br0"]);
	"bridge".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].bridge = Some(netcfgd_model::ObservedBridge {
		stp: true,
		forward_delay: Some(4),
		hello_time: Some(2),
		ageing_time: Some(300),
		priority: Some(32_768),
		vlan_filtering: false,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetBridge { .. }))
		.expect("an edited bridge setting is corrected");
	assert_eq!(action.reason.field, "bridge.stp");
}

/// A bridge that matches its document plans nothing, twice over.
///
/// The check that catches a comparison in the wrong units. The kernel counts
/// hundredths of a second and the document counts seconds, so a reader that
/// forgot to divide would make every bridge differ from itself by a factor of a
/// hundred -- which is the same shape as the 40ms forward delay `links.sh`
/// exists partly to have caught.
#[test]
fn a_bridge_matching_its_document_plans_nothing() {
	let desired = document(
		r#"
device br0 {
	bridge { stp = true; forward_delay = 4 }
}
interface br0 {
	config = "10.4.0.1/24"
}
"#,
	);
	let mut observed = observed_with(&["br0"]);
	"bridge".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].bridge = Some(netcfgd_model::ObservedBridge {
		stp: true,
		forward_delay: Some(4),
		// What the document does not state is the kernel's, and comparing it
		// would rebuild a bridge on every reconcile -- 0052's band rule.
		hello_time: Some(2),
		ageing_time: Some(300),
		priority: Some(32_768),
		vlan_filtering: false,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetBridge { .. })),
		"a bridge that matches its document was corrected"
	);
}

/// A bond with members gets a sentence about its mode, not an action.
///
/// The kernel takes a mode only on a bond with none: with any, it answers
/// `ENOTEMPTY` and rejects the whole message, monitoring interval included.
/// Planning it anyway failed the apply and then planned the same thing again on
/// the next reconcile, forever -- decision 0057.
#[test]
fn a_bond_with_members_is_told_why_its_mode_cannot_move() {
	let desired = document(
		r#"
device bond0 {
	bond { members = "port0"; mode = "balance-rr"; miimon = 250 }
}
interface bond0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["bond0", "port0"]);
	"bond".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].bond = Some(netcfgd_model::ObservedBond {
		mode: Some("active-backup".to_owned()),
		miimon: Some(100),
	});
	observed.links[1].master = Some("bond0".to_owned());

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("while the bond has members")),
		"nothing said why the mode is not being changed: {:?}",
		plan.warnings
	);
	// And the interval still moves, in a message that does not carry the mode.
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetBond { .. }))
		.expect("the monitoring interval is still set");
	assert_eq!(action.reason.field, "bond.miimon");
	assert!(
		matches!(action.op, Op::LinkSetBond { mode: false, .. }),
		"the mode rode along with an interval the kernel would then refuse"
	);
}

/// An edited VLAN id is applied by making the interface again.
///
/// The kernel accepts `ip link set work-net type vlan id 43` and changes nothing,
/// so there is no set to emit -- and a VLAN is usually named for its id, which is
/// why this was invisible for so long: renaming the interface is a create and a
/// delete already. The operator who names one `work-net` is the one who got
/// silence (0059).
#[test]
fn an_edited_vlan_id_is_remade() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 43 }
}
interface work-net {
	config = "10.4.0.1/24"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});
	observed.addresses.push(ObservedAddress {
		interface: "work-net".to_owned(),
		address: "10.4.0.1/24".to_owned(),
		proto: Some(netcfgd_model::route::NETCFGD_PROTO),
		ownership: Ownership::Ours,
		origin: Some(Origin::Static),
	});

	let plan = settle(&desired, &mut observed);
	let deleted = position(&plan, "link.delete");
	let created = position(&plan, "link.create");
	assert!(
		deleted < created,
		"the interface was created before it was deleted: {:?}",
		names(&plan)
	);
	let action = &plan.actions[deleted];
	assert_eq!(action.reason.field, "vlan.id");
	assert_eq!(action.reason.desired, "43");
	assert_eq!(action.reason.observed, "42");
	// The address is the point of the exercise. It went with the interface, so
	// the plan has to put it back -- and it is the pass *after* the delete that
	// does, which only works because the observation those passes see no longer
	// has the interface in it.
	assert!(
		position(&plan, "addr.add") > created,
		"the address was not re-added after the interface was remade: {:?}",
		names(&plan)
	);
	// And `settle` has already asserted the second plan is empty, which is the
	// half that would fail if the remade interface were compared against the old
	// id forever.
}

/// The tag protocol is the same answer, and it is checked separately.
///
/// `vlan_changelink` ignores an edited protocol exactly as it ignores an edited
/// id -- measured, because the two are different attributes and one being
/// ignored does not prove the other is.
#[test]
fn an_edited_vlan_protocol_is_remade() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 42; protocol = "dot1ad" }
}
interface work-net {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});

	let plan = settle(&desired, &mut observed);
	let action = &plan.actions[position(&plan, "link.delete")];
	assert_eq!(action.reason.field, "vlan.protocol");
	assert_eq!(action.reason.desired, "dot1ad");
}

/// A VLAN that agrees with its document is left alone.
#[test]
fn a_vlan_matching_its_document_is_not_remade() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 42 }
}
interface work-net {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"link.delete"),
		"a VLAN that matches its document was deleted: {:?}",
		names(&plan)
	);
}

/// An interface that exists as a different kind entirely is remade.
///
/// Nothing compared this before 0059: a document declaring `mixup` as a macvlan,
/// against a `mixup` that is a dummy, planned a `link.up` and nothing else.
#[test]
fn an_interface_of_the_wrong_kind_is_remade() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device mixup {
	macvlan { parent = "base0"; mode = "bridge" }
}
interface mixup {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "mixup"]);
	"dummy".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;

	let plan = settle(&desired, &mut observed);
	let action = &plan.actions[position(&plan, "link.delete")];
	assert_eq!(action.reason.field, "kind");
	assert_eq!(action.reason.desired, "macvlan");
	assert_eq!(action.reason.observed, "dummy");
}

/// A link netcfgd did not create is reported and never deleted.
///
/// The safety property, and the one place in the planner where getting it wrong
/// destroys something: everything else in a plan adds or corrects.
#[test]
fn a_vlan_netcfgd_did_not_create_is_only_reported() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 43 }
}
interface work-net {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	// The default, spelled out: nobody recorded creating it.
	observed.links[1].ownership = Ownership::Unknown;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("a link it did not create")),
		"nothing said why the id was not corrected: {:?}",
		plan.warnings
	);
	assert!(
		!names(&plan).contains(&"link.delete"),
		"a link netcfgd did not create was deleted: {:?}",
		names(&plan)
	);
	assert!(
		!names(&plan).contains(&"link.create"),
		"a link that still exists was planned for creation: {:?}",
		names(&plan)
	);
}

/// A device with no `interface` block is still checked for its kind.
///
/// `plan_recreation` walked `desired.interfaces` while `kind` has lived on a
/// `device` since 0155 pass 1a, and pass 1b made a device without an interface
/// block the normal arrangement for a tunnel. So a link of the wrong kind
/// produced `nothing to do` -- no recreation, and not even the warning the
/// function exists to print. Adding an `interface` block made the same
/// configuration warn, which is what identified the walk rather than the check
/// as the fault.
///
/// Asserted on a link netcfgd owns, so the recreation is planned rather than
/// refused; the ownership half is `a_link_netcfgd_did_not_create_is_not_remade`
/// above.
#[test]
fn a_device_with_no_interface_block_is_still_remade_for_its_kind() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 43 }
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"dummy".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		names(&plan).contains(&"link.delete"),
		"a device whose kind is wrong was not remade: {:?}",
		names(&plan)
	);
	assert!(
		names(&plan).contains(&"link.create"),
		"the device was deleted and not made again: {:?}",
		names(&plan)
	);
}

/// A guard refuses the deletion, and then nothing else happens either.
///
/// The interaction that has to hold: a refused delete must not leave the rest of
/// the plan written as though the interface had gone. `link.create` on an
/// interface that still exists fails with `EEXIST`, and every address after it
/// would be planned against a device that is not the one in the document.
#[test]
fn a_guard_refuses_a_recreation_whole() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan   { parent = "base0"; id = 43 }
}
interface work-net {
	guard  = "the office VLAN carries the phones"
	config = "10.4.0.1/24"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.refusals
			.iter()
			.any(|refusal| refusal.op == "link.delete"),
		"the guard did not refuse the deletion: {:?}",
		plan.refusals
	);
	assert!(
		!names(&plan).contains(&"link.delete") && !names(&plan).contains(&"link.create"),
		"a guarded interface was remade anyway: {:?}",
		names(&plan)
	);
}

/// What runs on the interface is stopped before it goes.
///
/// A DHCP client bound to an interface that is about to be deleted would be left
/// holding a name that comes back as a different device, with netcfgd's own
/// record still saying it runs -- a plan that converges while nothing is leasing.
#[test]
fn a_backend_on_a_remade_interface_is_stopped_first() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device work-net {
	vlan { parent = "base0"; id = 43 }
}
interface work-net {
	config = "dhcp"
}
"#,
	);
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});
	observed.backends.push(started_backend(
		netcfgd_model::BackendKind::Dhcp4,
		"work-net",
		&desired,
	));

	let plan = settle(&desired, &mut observed);
	let stopped = position(&plan, "backend.stop");
	let deleted = position(&plan, "link.delete");
	let started = position(&plan, "backend.start");
	assert!(
		stopped < deleted && deleted < started,
		"the client was not stopped before the interface went and started after \
		 it came back: {:?}",
		names(&plan)
	);
}

/// A reported search suffix is delivered where the report's servers are, and never
/// as a routing domain.
///
/// The gate is the same one and that is the argument (0067): a suffix is only used
/// where that network's resolvers are already answering, and a party answering every
/// query gains nothing by also appending a suffix. Where an operator kept their own
/// resolvers -- no `dns` block, nothing claimed -- a lease does not get to redefine
/// what a bare name means.
#[test]
fn a_reported_search_suffix_follows_the_servers() {
	let report = |interface: &str| netcfgd_model::ObservedReport {
		interface: interface.to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: vec!["192.168.1.1".to_owned()],
		search: vec!["lan.example".to_owned()],
		routes: Vec::new(),
	};

	// Asked for: `dns { }` claims what the network offers.
	let asked = document(
		r#"
global { dns { mode = "write_resolv_conf" } }
interface eth0 { config = "dhcp"; dns { } }
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.reports.push(report("eth0"));

	let scopes = netcfgd_model::dns::scopes(&asked, &observed);
	let scope = scopes
		.iter()
		.find(|(name, _)| name == "eth0")
		.map(|(_, policy)| policy)
		.expect("the interface has a scope");
	assert_eq!(scope.search, vec!["lan.example".to_owned()]);
	// The line 0049 draws: a suffix completes a name, a routing domain decides
	// which resolver answers. Nothing reported ever becomes the second.
	assert!(
		scope.domains.is_empty(),
		"a reported suffix became a routing domain: {scope:?}"
	);

	// Not asked for: no `dns` block, so neither the servers nor the suffix.
	let unasked = document(
		r#"
global { dns { mode = "write_resolv_conf" } }
interface eth0 { config = "dhcp" }
"#,
	);
	let scopes = netcfgd_model::dns::scopes(&unasked, &observed);
	assert!(
		!scopes.iter().any(|(name, _)| name == "eth0"),
		"an interface that asked for nothing was given a scope: {scopes:?}"
	);

	// And what the operator wrote comes first, because resolution tries suffixes in
	// order and a document beats a suggestion.
	let both = document(
		r#"
global { dns { mode = "write_resolv_conf" } }
interface eth0 { config = "dhcp"; dns { search = ["ours.example"] } }
"#,
	);
	let scopes = netcfgd_model::dns::scopes(&both, &observed);
	let scope = scopes
		.iter()
		.find(|(name, _)| name == "eth0")
		.map(|(_, policy)| policy)
		.expect("the interface has a scope");
	assert_eq!(
		scope.search,
		vec!["ours.example".to_owned(), "lan.example".to_owned()]
	);
}

/// A resolver file with nothing in it is not written silently.
///
/// The mode the first-run guide recommends, an interface on DHCP, and no `dns`
/// block: netcfgd used to overwrite a working `/etc/resolv.conf` with a file
/// containing one comment and no nameservers, while the plan said `dns.apply` and
/// warned only that it could not be undone. Decision 0066.
#[test]
fn an_empty_resolver_delivery_says_so() {
	let desired = document(
		r#"
global { dns { mode = "write_resolv_conf" } }
interface eth0 { config = "dhcp" }
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	let said = |plan: &Plan, text: &str| {
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains(text))
	};

	// With nothing reported, the message says the configuration names no server.
	let first = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		said(&first, "resolves nothing"),
		"an empty delivery was silent: {:?}",
		first.warnings
	);
	assert!(said(
		&first,
		"nothing in the configuration names a nameserver"
	));

	// With a lease that offered some, it names the interface and the one-line fix --
	// which is the case an operator on a laptop is actually in.
	observed.reports.push(netcfgd_model::ObservedReport {
		interface: "eth0".to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: vec!["192.168.1.1".to_owned()],
		search: Vec::new(),
		routes: Vec::new(),
	});
	let offered = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		said(&offered, "a lease on eth0 offered nameservers"),
		"the reported servers were not mentioned: {:?}",
		offered.warnings
	);
	assert!(said(&offered, "add an empty `dns { }` block"));

	// And once the interface asks, there is nothing to warn about: 0049's third row
	// delivers the reported servers, so the file has one.
	let asked = document(
		r#"
global { dns { mode = "write_resolv_conf" } }
interface eth0 { config = "dhcp"; dns { } }
"#,
	);
	let quiet = plan(&asked, &observed, &PlanOptions::default());
	assert!(
		!said(&quiet, "resolves nothing"),
		"an interface that asked was still warned about: {:?}",
		quiet.warnings
	);
}

/// A carrier hook fires when the cable comes or goes, and where it belongs.
///
/// The ordering is the claim: gained goes *after* the addressing, because a script
/// that reacts to a cable by connecting somewhere needs the network to work; lost
/// goes early, before the teardown that withdraws the routes, so a script can stop
/// something that is using them. Decision 0068.
#[test]
fn a_carrier_hook_fires_on_a_change_and_in_the_right_place() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig = \"10.0.0.2/24\"\n\
		 \ton carrier {\necho carrier\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");

	// A cable, and netcfgd has never said anything about this interface: the first
	// observation is told the current state, which is what `ifplugd -i` does.
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].carrier = true;
	let plan = settle(&desired, &mut observed);
	let hook = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::HookRun { .. }))
		.expect("the first observation runs it");
	assert_eq!(hook.reason.field, "carrier");
	assert_eq!(hook.reason.desired, "up");
	assert_eq!(hook.reason.observed, "<absent>");
	assert!(
		matches!(&hook.op, Op::HookRun { value: Some(value), .. } if value == "up"),
		"the script is not told which way it went: {:?}",
		hook.op
	);
	// Gained: after the addressing, so the network works by the time it runs. The
	// *edge* as well as the position -- a plan is a DAG and a reader of
	// `depends_on` has to get the same answer as a reader of the list. Emission
	// order gives the position for free, so without this assertion deleting the
	// dependency changes nothing any test can see.
	let addressed = plan.actions[position(&plan, "addr.add")].id;
	assert!(
		position(&plan, "hook.run") > position(&plan, "addr.add"),
		"a gained carrier ran before the address was there: {:?}",
		names(&plan)
	);
	assert!(
		hook.depends_on.contains(&addressed),
		"a gained carrier does not wait for the addressing: {:?}",
		hook.depends_on
	);

	// `settle` has asserted the second plan is empty, so it does not fire again on
	// an unchanged cable. Now pull it.
	observed.links[0].carrier = false;
	let plan = settle(&desired, &mut observed);
	let hook = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::HookRun { .. }))
		.expect("losing the cable runs it");
	assert_eq!(hook.reason.desired, "down");
	assert_eq!(hook.reason.observed, "up");
	// Lost: before anything is taken away. Teardown is the last thing in a plan, so
	// this holds as long as the hook is emitted in the interface's own pass.
	let withdrawn = plan
		.actions
		.iter()
		.position(|action| matches!(action.op, Op::RouteDel { .. } | Op::AddrDel { .. }));
	if let Some(withdrawn) = withdrawn {
		assert!(
			position(&plan, "hook.run") < withdrawn,
			"a lost carrier ran after its interface had been stripped: {:?}",
			names(&plan)
		);
	}
}

/// An interface with no carrier hook plans nothing, whatever the cable does.
#[test]
fn an_interface_with_no_carrier_hook_is_left_alone() {
	let desired = document(r#"interface eth0 { config = "10.0.0.2/24" }"#);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].carrier = true;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"hook.run"),
		"a hook ran for an interface that declares none: {:?}",
		names(&plan)
	);
}

/// A lease hook fires when the address arrives, and once.
///
/// netcfgd never sees DHCP (0004), so the trigger is an address on the interface
/// that netcfgd did not install -- and the record of what a hook was already told
/// is what stops it firing on every reconcile. Decision 0064.
#[test]
fn a_lease_hook_fires_once_when_the_address_arrives() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig = \"dhcp\"\n\
		 \ton lease {\necho leased\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");

	// Before the client has a lease: the interface is up, the backend is running,
	// and there is no address. Nothing to tell a hook about.
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.backends.push(started_backend(
		netcfgd_model::BackendKind::Dhcp4,
		"eth0",
		&desired,
	));
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"hook.run"),
		"a lease hook fired before there was a lease: {:?}",
		names(&plan)
	);

	// The client gets one. netcfgd installed nothing, which is what identifies it.
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.168.1.50/24".to_owned(),
		proto: None,
		ownership: Ownership::Foreign,
		origin: None,
	});

	// `settle` asserts the second plan is empty, which is the "once" half: without
	// the record this fires again on every reconcile, forever.
	let plan = settle(&desired, &mut observed);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::HookRun { .. }))
		.expect("the lease hook fires");
	assert_eq!(action.reason.field, "lease");
	assert_eq!(action.reason.desired, "192.168.1.50/24");
	assert!(
		matches!(
			&action.op,
			Op::HookRun { value: Some(value), .. } if value == "192.168.1.50/24"
		),
		"the address the script gets is not the lease: {:?}",
		action.op
	);

	// And it fires again when the lease moves, which is the other half of once.
	observed.addresses[0].address = "192.168.1.77/24".to_owned();
	let plan = settle(&desired, &mut observed);
	assert!(
		names(&plan).contains(&"hook.run"),
		"a changed lease did not fire the hook: {:?}",
		names(&plan)
	);
}

/// What is not a lease: netcfgd's own address, a link-local, and SLAAC.
///
/// Each would otherwise look like one -- an address on the interface that arrived
/// without netcfgd asking -- and none of them is news a `lease` hook wants.
#[test]
fn a_lease_hook_ignores_what_is_not_a_lease() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig = \"dhcp dhcp6\"\n\
		 \ton lease {\necho leased\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	let mut add = |address: &str, proto: Option<u8>, ownership, origin| {
		observed.addresses.push(ObservedAddress {
			interface: "eth0".to_owned(),
			address: address.to_owned(),
			proto,
			ownership,
			origin,
		});
	};
	// netcfgd's own, from the config.
	add(
		"10.0.0.9/24",
		Some(netcfgd_model::route::NETCFGD_PROTO),
		Ownership::Ours,
		Some(Origin::Static),
	);
	// A v4 link-local, which is what a failed DHCP leaves behind.
	add("169.254.7.7/16", None, Ownership::Foreign, None);
	// A v6 link-local and a SLAAC address, the second one tagged `kernel_ra`.
	add("fe80::1/64", Some(3), Ownership::Foreign, None);
	add("2001:db8::1/64", Some(2), Ownership::Foreign, None);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"hook.run"),
		"something that is not a lease fired the hook: {:?}",
		plan.actions
	);
}

/// An interface with no `lease` hook plans nothing, however its addresses arrived.
#[test]
fn an_interface_with_no_lease_hook_is_left_alone() {
	let desired = document(r#"interface eth0 { config = "dhcp" }"#);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.168.1.50/24".to_owned(),
		proto: None,
		ownership: Ownership::Foreign,
		origin: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"hook.run"),
		"a hook ran for an interface that declares none: {:?}",
		names(&plan)
	);
}

/// `down` runs before the interface goes, `post_down` after it.
///
/// The ordering is the point. Teardown runs last in a plan, so at the moment a
/// `down` hook fires the interface still has its addresses and routes -- which is
/// what lets one unmount a share or stop a service that is using them. Decision
/// 0063.
#[test]
fn down_hooks_bracket_the_interface_going_down() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig  = \"10.0.0.2/24\"\n\
		 \tenabled = false\n\
		 \tdown {\necho going\n}\n\
		 \tpost_down {\necho gone\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let hooks: Vec<usize> = plan
		.actions
		.iter()
		.enumerate()
		.filter(|(_, action)| matches!(action.op, Op::HookRun { .. }))
		.map(|(index, _)| index)
		.collect();
	assert_eq!(hooks.len(), 2, "expected two hooks: {:?}", names(&plan));
	let down = position(&plan, "link.down");
	assert!(
		hooks[0] < down && down < hooks[1],
		"the hooks do not bracket the link going down: {:?}",
		names(&plan)
	);
	// And the dependencies say so as well as the order, because a plan is a DAG
	// and a reader of `depends_on` must get the same answer as a reader of the
	// list.
	assert!(plan.actions[down]
		.depends_on
		.contains(&plan.actions[hooks[0]].id));
	assert!(plan.actions[hooks[1]]
		.depends_on
		.contains(&plan.actions[down].id));
	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("never run by this build")),
		"a phase that now fires was reported as inert: {:?}",
		plan.warnings
	);
}

/// An interface being remade fires them too, and the up hooks on the way back.
///
/// The symmetry 0059 left open: the creation pass plans a remade interface as
/// absent, so `pre_up` and `post_up` fire again -- and without a `down` beside
/// them, an operator's pair would run half as often as it should.
#[test]
fn a_remade_interface_fires_down_and_up_hooks() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"device base0 { kind = \"dummy\" }
interface base0 { config = \"null\" }\n\
		 device work-net {\n\
		 \tvlan { parent = \"base0\"; id = 43 }\n\
		 }\n\
		 interface work-net {\n\
		 \tconfig = \"null\"\n\
		 \tdown {\necho going\n}\n\
		 \tpost_up {\necho back\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let mut observed = observed_with(&["base0", "work-net"]);
	"vlan".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let phases: Vec<&str> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::HookRun { phase, .. } => Some(phase.name()),
			_ => None,
		})
		.collect();
	assert_eq!(
		phases,
		vec!["down", "post_up"],
		"a remade interface did not run both halves: {:?}",
		names(&plan)
	);
	assert!(position(&plan, "hook.run") < position(&plan, "link.delete"));
}

/// A guarded interface refuses the down hook with the transition it belongs to.
///
/// `link.down` is disruptive and a guard refuses it (0010). The hook must go with
/// it: a `down` script that runs when nothing goes down is worse than one that
/// does not run, because it has already unmounted the share.
#[test]
fn a_guard_refusing_a_link_down_takes_its_hook_with_it() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig  = \"10.0.0.2/24\"\n\
		 \tenabled = false\n\
		 \tguard   = \"nfs root\"\n\
		 \tdown {\necho going\n}\n\
		 \tpost_down {\necho gone\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.refusals
			.iter()
			.any(|refusal| refusal.op == "link.down"),
		"the guard did not refuse the transition: {:?}",
		plan.refusals
	);
	assert!(
		!names(&plan).contains(&"hook.run"),
		"a hook ran for a transition that was refused: {:?}",
		names(&plan)
	);
}

/// A blocked radio is named, with the remedy for the switch that blocked it.
///
/// The gap this closes is a sentence rather than a feature: a radio that is off
/// looks exactly like a network that will not associate -- the supplicant starts,
/// the scan is empty, nothing fails. Decision 0062.
#[test]
fn a_blocked_radio_is_named_with_its_remedy() {
	let desired = document(
		r#"
device wlan0 { wifi { } }
interface wlan0 { config = "dhcp" }
"#,
	);

	for (soft, hard, expected) in [
		(true, false, "`rfkill unblock wifi` clears"),
		(false, true, "nothing in software can clear"),
	] {
		let mut observed = observed_with(&["wlan0"]);
		observed.links[0].rfkill = Some(netcfgd_model::ObservedRfkill {
			switch: "phy0".to_owned(),
			soft,
			hard,
		});

		let plan = plan(&desired, &observed, &PlanOptions::default());
		assert!(
			plan.warnings
				.iter()
				.any(|warning| warning.message.contains(expected)),
			"the {} block was not explained: {:?}",
			if hard { "hard" } else { "soft" },
			plan.warnings
		);
		// And the supplicant still starts: the switch may come back a second
		// later, and a radio nobody configured would then sit there doing
		// nothing.
		assert!(
			names(&plan).contains(&"backend.start"),
			"a blocked radio stopped the supplicant being planned: {:?}",
			names(&plan)
		);
	}
}

/// A radio that is on says nothing, and one that is not a radio says nothing.
#[test]
fn an_unblocked_radio_is_not_reported() {
	let desired = document(
		r#"
device wlan0 { wifi { } }
interface wlan0 { config = "dhcp" }
interface eth0  { config = "dhcp" }
"#,
	);
	let mut observed = observed_with(&["wlan0", "eth0"]);
	observed.links[0].rfkill = Some(netcfgd_model::ObservedRfkill {
		switch: "phy0".to_owned(),
		soft: false,
		hard: false,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("switched off")),
		"a working radio was reported as off: {:?}",
		plan.warnings
	);
}

/// Every phase the model declares actually runs.
///
/// This used to assert the opposite half: that a hook in a phase nothing fires
/// is *named* in the plan, because nine of the eleven were parsed, materialised
/// and never executed. The last of them fires as of 0096, so the warning has no
/// input any more -- and the property worth keeping is the one that made the
/// warning necessary: **no phase is silently unfired**.
///
/// The match below has no wildcard arm, so a phase added to the model is a
/// compile error here until somebody decides which list it belongs in. That is
/// the same guard `netcfgd-plan`'s own witness uses, and it is the half that
/// catches an addition -- the assertion catches a phase that stopped firing.
#[test]
fn no_phase_is_recognised_and_silently_unfired() {
	// Every variant, and how the config language spells it. A direct block for
	// the lifecycle phases, `on <event>` for the rest.
	let spelling = |phase: HookPhase| match phase {
		HookPhase::PreUp => "pre_up",
		HookPhase::Up => "up",
		HookPhase::PostUp => "post_up",
		HookPhase::PreDown => "pre_down",
		HookPhase::Down => "down",
		HookPhase::PostDown => "post_down",
		HookPhase::Carrier => "on carrier",
		HookPhase::Lease => "on lease",
		HookPhase::Roam => "on roam",
		HookPhase::Portal => "on portal",
		HookPhase::Drift => "on drift",
	};
	let every = [
		HookPhase::PreUp,
		HookPhase::Up,
		HookPhase::PostUp,
		HookPhase::PreDown,
		HookPhase::Down,
		HookPhase::PostDown,
		HookPhase::Carrier,
		HookPhase::Lease,
		HookPhase::Roam,
		HookPhase::Portal,
		HookPhase::Drift,
	];

	let mut text = String::from("interface eth0 {\n\tconfig = \"10.0.0.2/24\"\n");
	for phase in every {
		text.push_str(&format!("\t{} {{\necho {phase:?}\n}}\n", spelling(phase)));
	}
	text.push_str("}\n");

	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", &text);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let observed = observed_with(&["eth0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());

	let unfired: Vec<&str> = plan
		.warnings
		.iter()
		.map(|warning| warning.message.as_str())
		.filter(|message| message.contains("never run by this build"))
		.collect();
	assert!(
		unfired.is_empty(),
		"a phase is recognised and never run: {unfired:?}"
	);
	// And the ones a plan carries are still planned, so this did not pass by
	// the document failing to compile into anything.
	assert!(names(&plan).contains(&"hook.run"), "{:?}", names(&plan));
}

/// `portal_check` takes a URL, and an `https` one is refused with the reason.
///
/// It was a boolean that compiled and did nothing, warned about by the plan
/// since 0061. It is an operator's URL now (0095) and the plan says nothing,
/// because there is nothing left to say.
#[test]
fn a_portal_check_is_a_url_and_not_a_warning() {
	let desired = document(
		r#"
device wlan0 { wifi { portal_check = "http://example.com/generate_204" } }
interface wlan0 { config = "dhcp" }
"#,
	);
	let observed = observed_with(&["wlan0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("portal_check")),
		"portal_check is implemented and still warned about: {:?}",
		plan.warnings
	);
}

/// A hostname the document names is set, once.
#[test]
fn a_static_hostname_is_set_and_then_left_alone() {
	let desired = document(
		r#"
global { hostname = "laptop" }
interface eth0 { config = "10.0.0.2/24" }
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.hostname = Some("localhost".to_owned());

	let plan = settle(&desired, &mut observed);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::HostnameSet { .. }))
		.expect("the hostname is set");
	assert_eq!(action.reason.observed, "localhost");
	assert_eq!(action.reason.desired, "laptop");
	// Whole-host, so it names no interface -- a guard on eth0 must not be able to
	// refuse the machine's name.
	assert!(action.reason.interface.is_none());
	assert_eq!(observed.hostname.as_deref(), Some("laptop"));
}

/// `hostname = "dhcp"` says what it will not do, rather than doing nothing.
///
/// netcfgd delegates DHCP (0004) and never sees the lease, so the name a server
/// offered is the client's to act on. Before decision 0061 this key compiled and
/// was silently dropped.
#[test]
fn a_hostname_from_dhcp_is_explained_rather_than_dropped() {
	let desired = document(
		r#"
global { hostname = "dhcp" }
interface eth0 { config = "dhcp" }
"#,
	);
	let observed = observed_with(&["eth0"]);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("never sees the lease")),
		"nothing said the key was not applied: {:?}",
		plan.warnings
	);
	assert!(
		!names(&plan).contains(&"hostname.set"),
		"a name netcfgd does not have was set anyway: {:?}",
		names(&plan)
	);
}

/// A hostname that cannot be read is not written.
#[test]
fn an_unreadable_hostname_plans_nothing() {
	let desired = document(r#"global { hostname = "laptop" }"#);
	let mut observed = observed_with(&["eth0"]);
	observed.hostname = None;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"hostname.set"),
		"a hostname that could not be read was written: {:?}",
		names(&plan)
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("cannot be read")),
		"nothing said why: {:?}",
		plan.warnings
	);
}

/// A backend that will not stay up is started five times and then left alone.
///
/// Since 0078 the observation notices a daemon that died, and the planner
/// restarts it -- which on an interface set to `reconcile` meant 181 starts in
/// twelve seconds for a daemon that lived half a second. Decision 0079.
#[test]
fn a_backend_that_will_not_stay_up_stops_being_restarted() {
	let desired = document(
		r#"
device vpn0 {
	openvpn { config = "/etc/netcfgd/work.ovpn" }
}
"#,
	);
	let mut observed = observed_with(&["vpn0"]);

	// Four starts in: still trying, because a daemon can be slow to settle.
	observed
		.backend_restarts
		.push((netcfgd_model::BackendKind::OpenVpn, "vpn0".to_owned(), 4));
	assert!(
		names(&plan(&desired, &observed, &PlanOptions::default())).contains(&"backend.start"),
		"it gave up too early"
	);

	// Five, and it stops -- with a warning naming the interface, because a
	// tunnel that silently stops being retried is the same shape of defect as
	// one that is retried forever.
	observed.backend_restarts.clear();
	observed
		.backend_restarts
		.push((netcfgd_model::BackendKind::OpenVpn, "vpn0".to_owned(), 5));
	let capped = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&capped).contains(&"backend.start"),
		"it kept starting a daemon that will not stay up: {:?}",
		names(&capped)
	);
	assert!(
		capped
			.warnings
			.iter()
			.any(|warning| warning.message.contains("has not stayed up")),
		"nothing said why: {:?}",
		capped.warnings
	);
}

/// SLAAC on an interface that forwards makes the kernel listen.
///
/// The defect this pass exists for: `accept_ra` defaults to `1`, which means
/// "accept unless this interface forwards", so a router asking for SLAAC on its
/// WAN gets no address and nothing says why. Decision 0073.
#[test]
fn slaac_where_advertisements_are_ignored_writes_the_sysctl() {
	let desired = document(
		r#"
interface eth0 {
	config = "slaac"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	// The trap, spelled out: the kernel's default value, on an interface that
	// forwards. Both halves have to be here -- the value alone is the ordinary
	// working state of every laptop.
	observed.links[0].accept_ra = Some(netcfgd_model::ObservedAcceptRa {
		value: 1,
		effective: false,
	});

	let plan = settle(&desired, &mut observed);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::SysctlSetAcceptRa { .. }))
		.expect("the sysctl is written");
	assert!(
		matches!(action.op, Op::SysctlSetAcceptRa { value: 2, .. }),
		"the value written is not the one that survives forwarding: {:?}",
		action.op
	);
	// And the reason says which of the two halves is the problem, because
	// "accept_ra 1" on its own reads as the state that works.
	assert!(
		action.reason.observed.contains("forwards"),
		"the reason does not say why 1 is not enough: {:?}",
		action.reason
	);
}

/// And an interface that already listens is left alone.
///
/// Every ordinary laptop: `accept_ra` at the kernel's default with nothing
/// forwarding. A pass that wrote `2` here would touch a sysctl on every machine
/// to change nothing, and the plan would say so on every first apply.
#[test]
fn slaac_where_advertisements_already_arrive_plans_nothing() {
	let desired = document(
		r#"
interface eth0 {
	config = "slaac"
}
"#,
	);
	let observed = observed_with(&["eth0"]);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"sysctl.set_accept_ra"),
		"a working interface had its sysctl written anyway: {:?}",
		names(&plan)
	);
}

/// An interface that stops asking is handed back, and only netcfgd's own.
#[test]
fn dropping_slaac_hands_the_sysctl_back() {
	let desired = document(
		r#"
interface eth0 {
	config = "192.0.2.1/24"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].accept_ra = Some(netcfgd_model::ObservedAcceptRa {
		value: 2,
		effective: true,
	});

	// Nobody's record: netcfgd did not write it, so it is not netcfgd's to undo.
	let untouched = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&untouched).contains(&"sysctl.set_accept_ra"),
		"a value netcfgd never wrote was reset: {:?}",
		names(&untouched)
	);

	// With the record, it goes back to the kernel's default rather than to `0`.
	observed.accept_ra_applied.push("eth0".to_owned());
	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::SysctlSetAcceptRa { .. }))
		.expect("the sysctl is handed back");
	assert!(
		matches!(action.op, Op::SysctlSetAcceptRa { value: 1, .. }),
		"handed back the wrong value: {:?}",
		action.op
	);
}

/// A kernel with no `accept_ra` at all is reported, not written to.
#[test]
fn an_unreadable_accept_ra_says_so() {
	let desired = document(
		r#"
interface eth0 {
	config = "slaac"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].accept_ra = None;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"sysctl.set_accept_ra"),
		"a sysctl that cannot be read was written: {:?}",
		names(&plan)
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("accept_ra")),
		"nothing said why: {:?}",
		plan.warnings
	);
}

/// `slaac privacy prefer_temporary` writes the sysctl, once.
///
/// The whole point of the key, and the reason it needed the `use_tempaddr`
/// plumbing rather than an address action: a temporary address is the kernel's to
/// build from the next router advertisement, and netcfgd's job is to have asked.
#[test]
fn asking_for_temporary_addresses_writes_the_sysctl() {
	let desired = document(
		r#"
interface eth0 {
	config = "slaac privacy prefer_temporary"
}
"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].privacy = Some(false);

	let plan = settle(&desired, &mut observed);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::SysctlSetPrivacy { .. }))
		.expect("the sysctl is written");
	assert_eq!(action.reason.field, "addressing[slaac].privacy");
	assert_eq!(action.reason.desired, "prefer_temporary");
	assert!(
		matches!(
			action.op,
			Op::SysctlSetPrivacy {
				prefer_temporary: true,
				..
			}
		),
		"the op asked for the wrong value"
	);
	// `settle` has already asserted the second plan is empty, which is the half
	// that fails if the observation reads the sysctl and the comparison does not
	// agree about what `2` means.
}

/// Plain `slaac` leaves the sysctl alone unless netcfgd is what set it.
///
/// The two halves of the forwarding rule, in one test because they are one
/// decision: a machine whose `sysctl.conf` prefers temporary addresses globally
/// keeps them, and an interface that netcfgd switched on and that stops asking is
/// switched back off.
#[test]
fn temporary_addresses_are_only_undone_where_netcfgd_set_them() {
	let desired = document(r#"interface eth0 { config = "slaac" }"#);

	// Somebody else's setting: no record, so nothing is planned.
	let mut theirs = observed_with(&["eth0"]);
	theirs.links[0].privacy = Some(true);
	let plan = plan(&desired, &theirs, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"sysctl.set_privacy"),
		"a setting netcfgd did not make was undone: {:?}",
		names(&plan)
	);

	// netcfgd's own, which the document has stopped asking for.
	let mut ours = observed_with(&["eth0"]);
	ours.links[0].privacy = Some(true);
	ours.privacy_applied = vec!["eth0".to_owned()];
	let plan = settle(&desired, &mut ours);
	assert!(
		matches!(
			plan.actions
				.iter()
				.find(|action| matches!(action.op, Op::SysctlSetPrivacy { .. }))
				.map(|action| &action.op),
			Some(Op::SysctlSetPrivacy {
				prefer_temporary: false,
				..
			})
		),
		"netcfgd's own setting was not withdrawn: {:?}",
		names(&plan)
	);
}

/// A sysctl that cannot be read is not written.
///
/// An IPv6-disabled kernel, or a container with no `/proc/sys`. `None` is not
/// `false`: writing on one would fail the apply on every reconcile for a machine
/// that cannot have the feature at all.
#[test]
fn an_unreadable_privacy_sysctl_plans_nothing() {
	let desired = document(r#"interface eth0 { config = "slaac privacy prefer_temporary" }"#);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].privacy = None;

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"sysctl.set_privacy"),
		"a sysctl that could not be read was written anyway: {:?}",
		names(&plan)
	);
	// And it says so, rather than leaving the operator with a key that compiled
	// and did nothing -- which is the whole reason this key was implemented.
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("cannot be read")),
		"nothing said the sysctl was unreadable: {:?}",
		plan.warnings
	);
}

/// A moved VLAN parent is remade; a moved VXLAN underlay is set in place.
///
/// One word in the document, two answers from the kernel, and this is the pair
/// that says so: a VLAN's parent is the outer `IFLA_LINK`, which a live device
/// accepts and ignores, while a VXLAN's is an attribute in its own nest that the
/// kernel moves. Decision 0060.
#[test]
fn a_moved_vlan_parent_is_remade_and_a_vxlan_underlay_is_not() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device base1 { kind = "dummy" }
interface base1 { config = "null" }
device work-net {
	vlan { parent = "base1"; id = 42 }
}
interface work-net {
	config = "null"
}
device vx100 {
	vxlan { id = 100; parent = "base1"; remote = "10.9.0.2" }
}
interface vx100 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "base1", "work-net", "vx100"]);
	for index in [2, 3] {
		observed.links[index].up = true;
		observed.links[index].ownership = Ownership::Ours;
		observed.links[index].parent = Some("base0".to_owned());
	}
	"vlan".clone_into(&mut observed.links[2].kind);
	observed.links[2].vlan = Some(netcfgd_model::ObservedVlan {
		id: Some(42),
		protocol: Some("dot1q".to_owned()),
	});
	"vxlan".clone_into(&mut observed.links[3].kind);
	observed.links[3].vxlan = Some(netcfgd_model::ObservedVxlan {
		id: Some(100),
		local: None,
		remote: Some("10.9.0.2".parse().expect("an address")),
		port: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let deleted = plan
		.actions
		.iter()
		.find(|action| matches!(&action.op, Op::LinkDelete { name } if name == "work-net"))
		.expect("a moved vlan parent is remade");
	assert_eq!(deleted.reason.field, "parent");
	assert_eq!(deleted.reason.desired, "base1");
	assert_eq!(deleted.reason.observed, "base0");

	let set = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetVxlan { .. }))
		.expect("a moved vxlan underlay is set");
	assert_eq!(set.reason.field, "vxlan.parent");
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(&action.op, Op::LinkDelete { name } if name == "vx100")),
		"a VXLAN whose underlay the kernel will move was deleted instead: {:?}",
		names(&plan)
	);
}

/// A parent the document does not name is not compared.
///
/// A tunnel with no `parent` sends its outer packets through the routing table,
/// and the kernel picks the interface -- which it then reports. Comparing that
/// against the document's silence would remake or reconfigure the tunnel on
/// every reconcile.
#[test]
fn a_parent_the_document_does_not_name_is_not_compared() {
	let desired = document(
		r#"
device base0 { kind = "dummy" }
interface base0 { config = "null" }
device tun-office {
	tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.2" }
}
interface tun-office {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["base0", "tun-office"]);
	"gre".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].parent = Some("base0".to_owned());
	observed.links[1].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: Some("10.7.0.1".parse().expect("an address")),
		remote: Some("10.7.0.2".parse().expect("an address")),
		ttl: None,
		key: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"link.set_tunnel") && !names(&plan).contains(&"link.delete"),
		"a parent the document never named was compared: {:?}",
		names(&plan)
	);
}

/// A member of a remade master is enslaved to it again.
///
/// The half of the observation surgery that is not about the interface itself.
/// A member's `master` field still names the bridge that is about to be deleted,
/// so left as it is the enslavement pass sees the membership it wants and plans
/// nothing -- and the bridge comes back empty, with a plan that said nothing was
/// wrong.
#[test]
fn a_member_of_a_remade_master_is_enslaved_again() {
	let desired = document(
		r#"
device br0 { bridge { } }
interface br0 { config = "null" }
device port0 { kind = "dummy"; master = "br0" }
interface port0 { config = "null" }
"#,
	);
	let mut observed = observed_with(&["br0", "port0"]);
	// The name is right and the kind is not: this `br0` is a bond, which is what
	// a document edited from `bond` to `bridge` leaves behind.
	"bond".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].ownership = Ownership::Ours;
	observed.links[0].bond = Some(netcfgd_model::ObservedBond {
		mode: Some("balance-rr".to_owned()),
		miimon: None,
	});
	"dummy".clone_into(&mut observed.links[1].kind);
	observed.links[1].up = true;
	observed.links[1].ownership = Ownership::Ours;
	observed.links[1].master = Some("br0".to_owned());

	let plan = settle(&desired, &mut observed);
	assert!(
		names(&plan).contains(&"link.set_master"),
		"the member was left with a master that had been deleted: {:?}",
		names(&plan)
	);
	assert!(
		position(&plan, "link.set_master") > position(&plan, "link.create"),
		"the member was enslaved before the master existed: {:?}",
		names(&plan)
	);
}

/// A macvlan whose mode the document moved is corrected.
///
/// The kernel takes this on a live device -- asked one mode at a time, since it
/// takes three of the four and refuses the fourth (decision 0058).
#[test]
fn an_edited_macvlan_mode_is_planned() {
	let desired = document(
		r#"
device mv0 {
	macvlan { parent = "base0"; mode = "vepa" }
}
interface mv0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["mv0", "base0"]);
	"macvlan".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].macvlan = Some(netcfgd_model::ObservedMacvlan {
		mode: Some("bridge".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetMacvlan { .. }))
		.expect("an edited macvlan mode is corrected");
	assert_eq!(action.reason.field, "macvlan.mode");
	assert_eq!(action.reason.desired, "vepa");
	assert_eq!(action.reason.observed, "bridge");
}

/// One that agrees with its document plans nothing.
#[test]
fn a_macvlan_matching_its_document_plans_nothing() {
	let desired = document(
		r#"
device mv0 {
	macvlan { parent = "base0"; mode = "bridge" }
}
interface mv0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["mv0", "base0"]);
	"macvlan".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].macvlan = Some(netcfgd_model::ObservedMacvlan {
		mode: Some("bridge".to_owned()),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetMacvlan { .. })),
		"a macvlan that matches its document was corrected"
	);
}

/// `passthru` cannot be entered or left, so that edit is a sentence.
///
/// `macvlan_changelink` refuses the transition in either direction with `EINVAL`
/// -- the one mode of the four that cannot move. Both directions are checked,
/// because the kernel's condition is a comparison rather than a target: a check
/// on one direction alone passes with the other half of the condition deleted.
#[test]
fn a_passthru_macvlan_is_told_why_its_mode_cannot_move() {
	let leaving = document(
		r#"
device mv0 {
	macvlan { parent = "base0"; mode = "bridge" }
}
interface mv0 {
	config = "null"
}
"#,
	);
	let entering = document(
		r#"
device mv0 {
	macvlan { parent = "base0"; mode = "passthru" }
}
interface mv0 {
	config = "null"
}
"#,
	);
	for (desired, running) in [(&leaving, "passthru"), (&entering, "bridge")] {
		let mut observed = observed_with(&["mv0", "base0"]);
		"macvlan".clone_into(&mut observed.links[0].kind);
		observed.links[0].up = true;
		observed.links[0].macvlan = Some(netcfgd_model::ObservedMacvlan {
			mode: Some(running.to_owned()),
		});

		let plan = plan(desired, &observed, &PlanOptions::default());
		assert!(
			plan.warnings
				.iter()
				.any(|warning| warning.message.contains("into or out of passthru")),
			"nothing said why the mode is not being changed from {running}: {:?}",
			plan.warnings
		);
		assert!(
			!plan
				.actions
				.iter()
				.any(|action| matches!(action.op, Op::LinkSetMacvlan { .. })),
			"a mode the kernel refuses was planned anyway, from {running}"
		);
	}
}

/// A mode netcfgd has no word for is left alone.
///
/// The `source` mode, which this build cannot express. Correcting it would mean
/// overwriting a choice netcfgd cannot describe -- the rule a bond's unknown mode
/// already follows.
#[test]
fn a_macvlan_mode_netcfgd_cannot_name_is_left_alone() {
	let desired = document(
		r#"
device mv0 {
	macvlan { parent = "base0"; mode = "bridge" }
}
interface mv0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["mv0", "base0"]);
	"macvlan".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].macvlan = Some(netcfgd_model::ObservedMacvlan { mode: None });

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetMacvlan { .. })),
		"a mode netcfgd has no name for was overwritten"
	);
}

/// A tunnel whose endpoint the document moved is corrected.
#[test]
fn an_edited_tunnel_endpoint_is_planned() {
	let desired = document(
		r#"
device tun-office {
	tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.9" }
}
interface tun-office {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["tun-office"]);
	"gre".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: Some("10.7.0.1".parse().expect("an address")),
		remote: Some("10.7.0.2".parse().expect("an address")),
		ttl: Some(64),
		key: Some(42),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetTunnel { .. }))
		.expect("an edited remote is corrected");
	assert_eq!(action.reason.field, "tunnel.remote");
	assert_eq!(action.reason.observed, "10.7.0.2");
}

/// One that agrees with its document plans nothing, with a TTL and a key the
/// document does not state.
///
/// The input set is the point. A tunnel whose observation carries only the two
/// fields the document names could not notice a comparison that treats an unstated
/// `ttl` as a difference -- which would re-send the whole nest on every reconcile.
#[test]
fn a_tunnel_matching_its_document_plans_nothing() {
	let desired = document(
		r#"
device tun-office {
	tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.2" }
}
interface tun-office {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["tun-office"]);
	"gre".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: Some("10.7.0.1".parse().expect("an address")),
		remote: Some("10.7.0.2".parse().expect("an address")),
		// Neither is in the document, so neither is compared.
		ttl: Some(64),
		key: Some(42),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetTunnel { .. })),
		"a tunnel that matches its document was corrected"
	);
}

/// A geneve VNI gets a sentence, and the remote beside it still moves.
///
/// The kernel refuses a changed VNI as the whole message, so the nest the
/// executor sends leaves the VNI out on a change -- which is what keeps a refused
/// attribute from taking its neighbour with it (0057's rule, and the bond's
/// shape).
#[test]
fn a_geneve_vni_is_told_why_it_cannot_move() {
	let desired = document(
		r#"
device gnv0 {
	tunnel { mode = "geneve"; remote = "10.7.0.9"; vni = 501 }
}
interface gnv0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["gnv0"]);
	"geneve".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: None,
		remote: Some("10.7.0.4".parse().expect("an address")),
		ttl: None,
		key: Some(500),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("VNI of a geneve tunnel")),
		"nothing said why the VNI is not being changed: {:?}",
		plan.warnings
	);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetTunnel { .. }))
		.expect("the remote still moves");
	assert_eq!(action.reason.field, "tunnel.remote");
}

/// A GRE key is not a VNI: the kernel takes it, so it is planned.
///
/// The same field of the same model type, with the opposite answer -- which is
/// why the sentence above is conditional on the kind rather than on the field.
#[test]
fn an_edited_gre_key_is_planned() {
	let desired = document(
		r#"
device tun-office {
	tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.2"; key = 43 }
}
interface tun-office {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["tun-office"]);
	"gre".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: Some("10.7.0.1".parse().expect("an address")),
		remote: Some("10.7.0.2".parse().expect("an address")),
		ttl: None,
		key: Some(42),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetTunnel { .. }))
		.expect("an edited key is corrected");
	assert_eq!(action.reason.field, "tunnel.key");
	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("will not change")),
		"a GRE key produced the geneve sentence: {:?}",
		plan.warnings
	);
}

/// A remote in the other family is refused whole, so nothing is attempted.
///
/// Reachable because the device is not always netcfgd's: a geneve somebody else
/// built with a v6 remote, named in a document that asks for a v4 one, is a set
/// the kernel rejects as an address-family change rather than as an endpoint
/// change.
#[test]
fn a_geneve_remote_in_the_other_family_is_a_sentence() {
	let desired = document(
		r#"
device gnv0 {
	tunnel { mode = "geneve"; remote = "10.7.0.4"; vni = 500 }
}
interface gnv0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["gnv0"]);
	"geneve".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].tunnel = Some(netcfgd_model::ObservedTunnel {
		local: None,
		remote: Some("fd00::4".parse().expect("an address")),
		ttl: None,
		key: Some(500),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("address family its remote is in")),
		"nothing said why the remote is not being changed: {:?}",
		plan.warnings
	);
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetTunnel { .. })),
		"a family change the kernel refuses was planned anyway"
	);
}

/// A VXLAN's endpoints move; its id and its port get sentences.
///
/// Both refusals in one plan, because they are one edit an operator makes -- and
/// the endpoint still has to move, which is the property that would be lost if
/// the nest carried either of them.
#[test]
fn a_vxlan_id_and_port_are_told_why_they_cannot_move() {
	let desired = document(
		r#"
device vx0 {
	vxlan { id = 101; local = "10.9.0.1"; remote = "10.9.0.9"; port = 4790 }
}
interface vx0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["vx0"]);
	"vxlan".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].vxlan = Some(netcfgd_model::ObservedVxlan {
		id: Some(100),
		local: Some("10.9.0.1".parse().expect("an address")),
		remote: Some("10.9.0.2".parse().expect("an address")),
		port: Some(4789),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("VNI of a VXLAN")),
		"nothing said why the id is not being changed: {:?}",
		plan.warnings
	);
	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("destination port of a VXLAN")),
		"nothing said why the port is not being changed: {:?}",
		plan.warnings
	);
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetVxlan { .. }))
		.expect("the remote still moves");
	assert_eq!(action.reason.field, "vxlan.remote");
}

/// One that agrees with its document plans nothing.
#[test]
fn a_vxlan_matching_its_document_plans_nothing() {
	let desired = document(
		r#"
device vx0 {
	vxlan { id = 100; local = "10.9.0.1"; remote = "10.9.0.2" }
}
interface vx0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["vx0"]);
	"vxlan".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].vxlan = Some(netcfgd_model::ObservedVxlan {
		id: Some(100),
		local: Some("10.9.0.1".parse().expect("an address")),
		remote: Some("10.9.0.2".parse().expect("an address")),
		// Not in the document, so not compared -- the kernel chose 4789 itself.
		port: Some(4789),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.actions
			.iter()
			.any(|action| matches!(action.op, Op::LinkSetVxlan { .. })),
		"a VXLAN that matches its document was corrected"
	);
	assert!(
		plan.warnings.is_empty(),
		"a VXLAN that matches its document produced a warning: {:?}",
		plan.warnings
	);
}

/// With no members, the mode is the kernel's to take and is planned.
#[test]
fn a_bond_with_no_members_has_its_mode_planned() {
	let desired = document(
		r#"
device bond0 {
	bond { members = ""; mode = "balance-rr" }
}
interface bond0 {
	config = "null"
}
"#,
	);
	let mut observed = observed_with(&["bond0"]);
	"bond".clone_into(&mut observed.links[0].kind);
	observed.links[0].up = true;
	observed.links[0].bond = Some(netcfgd_model::ObservedBond {
		mode: Some("active-backup".to_owned()),
		miimon: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let action = plan
		.actions
		.iter()
		.find(|action| matches!(action.op, Op::LinkSetBond { .. }))
		.expect("a bond with no members has its mode set");
	assert_eq!(action.reason.field, "bond.mode");
	assert!(matches!(action.op, Op::LinkSetBond { mode: true, .. }));
}

/// A daemon that is there and is not answering is named, and only that one.
///
/// The last corner of "is what is running still what the document says?"
/// (0085). Three states and only one of them is a warning, which is the whole
/// point: `None` means netcfgd could not ask, and reading that as trouble would
/// put a warning on every dhcpcd on every machine.
#[test]
fn a_wedged_daemon_is_named_and_a_silent_one_is_not() {
	let desired = access_point_document(None);

	for (answering, expected) in [
		(Some(false), true),
		// It answered. Nothing to say.
		(Some(true), false),
		// netcfgd could not ask -- no control socket, or nothing tried. Not
		// the same as "it did not answer", and the difference is the reason
		// this field is an `Option` at all.
		(None, false),
	] {
		let mut observed = observed_with(&["wlan0"]);
		observed.backends.push(netcfgd_model::ObservedBackend {
			kind: netcfgd_model::BackendKind::AccessPoint,
			interface: "wlan0".to_owned(),
			running: true,
			answering,
			access_control: None,
			started_with: None,
			secret_matches: None,
			config_matches: None,
			advertised: Vec::new(),
		});

		// Computed before `plan` the binding shadows `plan` the function.
		let consented = plan(
			&desired,
			&observed,
			&PlanOptions {
				restart_wedged: vec!["wlan0".to_owned()],
				..PlanOptions::default()
			},
		);
		let plan = plan(&desired, &observed, &PlanOptions::default());
		let said = plan.warnings.iter().any(|warning| {
			warning
				.message
				.contains("did not answer its control socket")
		});
		assert_eq!(
			said, expected,
			"answering={answering:?} said={said}: {:?}",
			plan.warnings
		);
		// **And it is now a refusal as well as a warning (0141).** This used
		// to assert the opposite -- "a warning, never a refusal", on the
		// reasoning that netcfgd cannot tell a wedged daemon from a slow one.
		// That reasoning is why netcfgd still does not restart it by default;
		// what changed is that declining is now said in the type built for
		// declining, which carries the invocation that consents. A refusal
		// stops no other action, so the old worry about stopping an apply does
		// not apply to it.
		let refused = plan
			.refusals
			.iter()
			.any(|refusal| refusal.op == "backend.restart");
		assert_eq!(
			refused, expected,
			"answering={answering:?}: refusals {:?}",
			plan.refusals
		);
		if expected {
			let refusal = plan
				.refusals
				.iter()
				.find(|refusal| refusal.op == "backend.restart")
				.expect("checked above");
			assert!(
				refusal.override_with.contains("--restart-wedged"),
				"the refusal must name the option that consents: {refusal:?}"
			);
		}

		// **And with consent it restarts instead of refusing.** Without this
		// half the option could be accepted and ignored, which is the shape
		// that passes a test while doing nothing.
		let restarts = consented
			.actions
			.iter()
			.filter(|action| {
				matches!(
					action.op,
					netcfgd_plan::Op::BackendStop { .. } | netcfgd_plan::Op::BackendStart { .. }
				)
			})
			.count();
		assert_eq!(
			restarts > 0,
			expected,
			"answering={answering:?} with consent: actions {:?}",
			consented.actions.len()
		);
		assert!(
			consented
				.refusals
				.iter()
				.all(|refusal| refusal.op != "backend.restart"),
			"consent given and still refused: {:?}",
			consented.refusals
		);
	}
}

/// A daemon netcfgd's record calls stopped says nothing, whatever it answered.
///
/// `running: false` with a stale `answering` is reachable: the liveness pass
/// clears `running` when the pid has gone, and it runs after the round trip
/// that set the other field. A warning about a daemon netcfgd already knows is
/// not there would be noise on exactly the machine that has a real problem.
#[test]
fn a_daemon_that_is_not_running_is_not_called_wedged() {
	let desired = access_point_document(None);
	let mut observed = observed_with(&["wlan0"]);
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::AccessPoint,
		interface: "wlan0".to_owned(),
		running: false,
		answering: Some(false),
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("did not answer")),
		"a stopped daemon was reported as wedged: {:?}",
		plan.warnings
	);
}

/// An EAP network that pins no CA is warned about, and not refused.
///
/// The refusal used to live in the compiler, where every diagnostic is fatal,
/// so netcfgd could not configure a network that pins nothing -- which 0017 had
/// already rejected in as many words. Both halves are asserted here, because
/// only saying it and only allowing it are each half a decision (0087).
#[test]
fn an_eap_network_with_no_ca_certificate_is_warned_about_and_still_planned() {
	let desired = document(
		r#"
device wlan0 { wifi { } }
network "Corp" { wifi { eap = "ttls"; identity = "d"; password = "@secret:c" } }
interface wlan0 { config = "dhcp" }
"#,
	);
	let observed = observed_with(&["wlan0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert!(
		plan.warnings
			.iter()
			.any(|warning| warning.message.contains("trust any server that answers")),
		"nothing said the network pins no CA: {:?}",
		plan.warnings
	);
	// And the radio is still configured, which is the half a refusal took away.
	// `backend.start` rather than `wifi.set_profiles`: the supplicant is handed
	// its profiles as it starts, and asserting the op this fixture does not
	// produce would have been a check about the plan's shape rather than about
	// the network being usable.
	assert!(
		names(&plan).contains(&"backend.start"),
		"a network with no CA stopped the radio being configured: {:?}",
		names(&plan)
	);
	assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
}

/// And one that pins a CA says nothing.
#[test]
fn an_eap_network_with_a_ca_certificate_is_not_warned_about() {
	let desired = document(
		r#"
device wlan0 { wifi { } }
network "Corp" {
	wifi { eap = "ttls"; identity = "d"; password = "@secret:c"; ca_cert = "/ca.pem" }
}
interface wlan0 { config = "dhcp" }
"#,
	);
	let observed = observed_with(&["wlan0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!plan
			.warnings
			.iter()
			.any(|warning| warning.message.contains("trust any server")),
		"a network that pins a CA was warned about anyway: {:?}",
		plan.warnings
	);
}

/// A machine that asked for a confirm window gets one on every apply.
///
/// `global { confirm = 90 }` compiled, was carried in the document and in the
/// witness, and was read by nothing -- so an operator who wrote it believing
/// every apply had a safety net had none (0094). The same inert-key defect
/// 0061 closed four of, and silent in the same way.
#[test]
fn a_documents_confirm_default_arms_a_window() {
	let desired = document(
		r#"
global { confirm = 90 }
interface eth0 { config = "10.0.0.2/24" }
"#,
	);
	let observed = observed_with(&["eth0"]);

	// No window asked for by the caller: the document's answer is used.
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		names(&plan).contains(&"commit.arm"),
		"the document asked for a window and got none: {:?}",
		names(&plan)
	);
	// And it is the document's number, not some default of the planner's.
	let armed = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "commit.arm")
		.expect("the arm action");
	assert!(
		armed.reason.desired.contains("90"),
		"armed the wrong window: {:?}",
		armed.reason
	);
}

/// And a caller who says a number gets that number rather than the document's.
#[test]
fn an_explicit_window_beats_the_documents() {
	let desired = document(
		r#"
global { confirm = 90 }
interface eth0 { config = "10.0.0.2/24" }
"#,
	);
	let observed = observed_with(&["eth0"]);
	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			confirm_window: Some(30),
			..PlanOptions::default()
		},
	);
	let armed = plan
		.actions
		.iter()
		.find(|action| action.op.name() == "commit.arm")
		.expect("the arm action");
	assert!(armed.reason.desired.contains("30"), "{:?}", armed.reason);
}

/// Zero is how a caller says "no window" on a machine that set one.
///
/// It cannot mean a window of no seconds: that would arm and expire, which is
/// two spellings of "no" where one of them reverts the change. Without this
/// there is no way at all to override a document default from the command line.
#[test]
fn zero_seconds_means_no_window_rather_than_an_instant_one() {
	let desired = document(
		r#"
global { confirm = 90 }
interface eth0 { config = "10.0.0.2/24" }
"#,
	);
	let observed = observed_with(&["eth0"]);
	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			confirm_window: Some(0),
			..PlanOptions::default()
		},
	);
	assert!(
		!names(&plan).contains(&"commit.arm"),
		"zero armed a window: {:?}",
		names(&plan)
	);
	// And the rest of the plan is still there, so this refused the window and
	// not the apply.
	assert!(names(&plan).contains(&"addr.add"), "{:?}", names(&plan));
}

/// A machine that said nothing still gets nothing.
///
/// The opt-in half. Arming a window on every apply everywhere would make a
/// change revert itself on machines that never asked for that.
#[test]
fn a_document_that_asked_for_no_window_gets_none() {
	let desired = document(r#"interface eth0 { config = "10.0.0.2/24" }"#);
	let observed = observed_with(&["eth0"]);
	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(!names(&plan).contains(&"commit.arm"), "{:?}", names(&plan));
}

/// Taking an interface down removes what netcfgd put on it, in order.
///
/// Two things at once (0096). The ordering gives `pre_down` a moment of its own
/// -- before the addresses go, when the network still works -- which is what
/// 0063 said the phase needed and did not have. And the address removal is a
/// fix in its own right: `link.down` flushes IPv6 and **leaves IPv4 behind**,
/// measured on a real kernel, so a disabled interface kept a stale address that
/// netcfgd still recorded as its own.
#[test]
fn taking_an_interface_down_withdraws_its_addresses_first() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\
		 \tconfig  = \"10.0.0.2/24\"\n\
		 \tenabled = false\n\
		 \tpre_down {\necho early\n}\n\
		 \tdown {\necho late\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "10.0.0.2/24".to_owned(),
		proto: None,
		ownership: Ownership::Ours,
		origin: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let order = names(&plan);

	let at = |op: &str| {
		order
			.iter()
			.position(|name| *name == op)
			.unwrap_or_else(|| panic!("no {op} in {order:?}"))
	};
	// The address goes, and before the link does.
	assert!(at("addr.del") < at("link.down"), "{order:?}");

	// And the two hook phases are now two moments rather than one: the first
	// hook runs before the address is withdrawn and the second after it. That
	// is the whole of what 0063 was waiting for.
	let hooks: Vec<usize> = order
		.iter()
		.enumerate()
		.filter(|(_, name)| **name == "hook.run")
		.map(|(index, _)| index)
		.collect();
	assert_eq!(hooks.len(), 2, "{order:?}");
	assert!(
		hooks[0] < at("addr.del"),
		"pre_down ran too late: {order:?}"
	);
	assert!(hooks[1] > at("addr.del"), "down ran too early: {order:?}");
	assert!(hooks[1] < at("link.down"), "down ran too late: {order:?}");

	// And the *edge*, not only the position. Actions execute in list order, so
	// every assertion above passes on emission order alone -- deleting the
	// dependency changes nothing any of them can see, which project.md already
	// records as the way a `depends_on` becomes decoration. This is the one
	// that fails when `down` stops waiting for the withdrawal.
	let withdrawal = plan.actions[at("addr.del")].id;
	let late_hook = &plan.actions[hooks[1]];
	assert!(
		late_hook.depends_on.contains(&withdrawal),
		"the `down` hook does not wait for the address to go: {:?}",
		late_hook.depends_on
	);
	// Its counterpart: `pre_down` must *not* wait for it, or the two phases are
	// one moment again.
	assert!(
		!plan.actions[hooks[0]].depends_on.contains(&withdrawal),
		"the `pre_down` hook waits for the withdrawal it is supposed to precede"
	);
}

/// An address that is not netcfgd's is left where it is.
///
/// Disabling an interface is not permission to remove somebody else's address
/// from it -- the same rule every other teardown here follows, and the reason
/// `Ownership` exists.
#[test]
fn taking_an_interface_down_leaves_somebody_elses_address_alone() {
	let desired = document("interface eth0 {\n\tconfig = \"10.0.0.2/24\"\n\tenabled = false\n}\n");
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;
	observed.addresses.push(ObservedAddress {
		interface: "eth0".to_owned(),
		address: "192.0.2.9/24".to_owned(),
		proto: None,
		ownership: Ownership::Foreign,
		origin: None,
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"addr.del"),
		"removed an address that was not ours: {:?}",
		names(&plan)
	);
	assert!(names(&plan).contains(&"link.down"), "{:?}", names(&plan));
}

/// A refused action is not something to wait for.
///
/// `push` returns `u32::MAX` for an action it does not emit, and five
/// accumulators inside the planner collect ids without asking whether they are
/// real. Guarding a bridge member refuses the enslavement -- and the master's
/// `link.up` and `addr.add`, which wait for it by rule 2, were left depending
/// on action 4294967295 (0097).
///
/// Downstream that was not cosmetic: `restrict`, which is how drift is
/// reconciled on one interface, drops an action whose dependency it did not
/// keep. So a machine with a guarded bridge member reconciled the bridge to
/// nothing and said `link.up on br0 needs action 4294967295, which belongs to
/// another interface` -- a sentence with two false claims in it.
#[test]
fn a_refused_action_is_not_something_to_wait_for() {
	let desired = document(
		r#"
		device br0 {
			bridge { members = "eth0" }
		}
		interface br0 {
			config = "10.0.0.1/24"
		}
		device eth0 {
			master = "br0"
		}
		interface eth0 {
			guard  = "nfs root"
		}
		"#,
	);
	let mut observed = observed_with(&["eth0"]);
	observed.links[0].up = true;

	// Not `settle`: the enslavement is refused, so this plan never converges --
	// which is the point of a guard and is what the refusal says.
	let plan = plan(&desired, &observed, &PlanOptions::default());

	assert_eq!(
		plan.refusals
			.iter()
			.map(|r| r.op.as_str())
			.collect::<Vec<_>>(),
		vec!["link.set_master"],
		"the guard should refuse the enslavement and nothing else"
	);

	// The wrapper above asserts the invariant for every fixture; this says it
	// explicitly for the one case that broke it, so the test is legible without
	// knowing the wrapper exists.
	let ids: Vec<u32> = plan.actions.iter().map(|action| action.id).collect();
	for action in &plan.actions {
		for id in &action.depends_on {
			assert!(
				ids.contains(id),
				"{} depends on action {id}, which does not exist",
				action.op.name()
			);
		}
	}

	// And the bridge is still brought into service. The guard is on `eth0`;
	// refusing to enslave a member is not a reason to leave the master bare,
	// and a fix that dropped the master's actions along with the edge would
	// pass every assertion above.
	assert!(names(&plan).contains(&"addr.add"), "{:?}", names(&plan));
	assert!(names(&plan).contains(&"link.up"), "{:?}", names(&plan));
}

/// Each kind that can be wedged is called by its own name.
///
/// 0085's warning had two arms and a fallback, and the fallback was correct
/// only because nothing but the access point's round trip set the field.
/// The supplicant's does now (0098), so an operator reading "the backend on
/// wlan0 is running and did not answer" would be told the least useful true
/// thing available -- on a machine that may be running both.
#[test]
fn a_wedged_supplicant_is_called_a_supplicant() {
	let desired = document(
		r#"
		interface wlan0 {
			config = "dhcp"
		}
		"#,
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.backends.push(netcfgd_model::ObservedBackend {
		kind: netcfgd_model::BackendKind::Supplicant,
		interface: "wlan0".to_owned(),
		running: true,
		answering: Some(false),
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let wedged: Vec<&str> = plan
		.warnings
		.iter()
		.filter(|warning| {
			warning
				.message
				.contains("did not answer its control socket")
		})
		.map(|warning| warning.message.as_str())
		.collect();

	assert_eq!(wedged.len(), 1, "{:?}", plan.warnings);
	assert!(
		wedged[0].starts_with("the supplicant on wlan0"),
		"a supplicant was not called one: {}",
		wedged[0]
	);
}

/// 0152: a SIM switch cycles the link, because `pre_up` -- where the hook that
/// drives the mux runs -- fires only on the way up, and a link whose probe is
/// failing is still up.
///
/// The order is the whole point. `link.down` has to come before `pre_up`, and
/// `pre_up` before `link.up`, or the hook selects a source on a modem that is
/// about to be reset back past it.
#[test]
fn cycling_takes_the_link_down_before_bringing_it_up() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"device wwan0 { modem { sim = [\"esim\", \"socket\"] } }\n\
		 interface wwan0 {\n\
		 \tconfig = \"dhcp\"\n\
		 \tpre_up {\nselect-sim\n}\n\
		 }\n",
	);
	let desired = compile(&sources, &mut TestHooks).expect("compiles");

	// The link must be *up*: a cycle is for an interface that is running and
	// running on the wrong SIM. An interface that is already down is brought
	// up by the ordinary path and needs no teardown first.
	let mut observed = observed_with(&["wwan0"]);
	observed.links[0].up = true;

	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			cycle: vec!["wwan0".to_owned()],
			..PlanOptions::default()
		},
	);

	let names = names(&plan);
	assert!(names.contains(&"link.down"), "{names:?}");
	assert!(names.contains(&"link.up"), "{names:?}");
	// Exactly one, so `position` below is unambiguous: the teardown emits its
	// own `pre_down`/`down`/`post_down` hooks, and this fixture defines none
	// of them precisely so that the one hook found is the `pre_up`.
	assert_eq!(
		names.iter().filter(|name| **name == "hook.run").count(),
		1,
		"{names:?}"
	);
	assert!(
		position(&plan, "link.down") < position(&plan, "hook.run"),
		"the teardown must precede pre_up: {names:?}"
	);
	assert!(
		position(&plan, "hook.run") < position(&plan, "link.up"),
		"pre_up must precede link.up: {names:?}"
	);
}

/// An interface nobody asked to cycle is left alone, so the option cannot
/// disrupt a link by being merely present.
#[test]
fn an_uncycled_link_is_not_taken_down() {
	let desired = document("interface wwan0 { config = \"dhcp\" }");
	let observed = observed_with(&["wwan0"]);

	let plan = plan(&desired, &observed, &PlanOptions::default());
	assert!(
		!names(&plan).contains(&"link.down"),
		"nothing asked for a cycle: {:?}",
		names(&plan)
	);
}

/// The reason a cycle goes through the planner at all: `managed = false` is
/// enforced at the action choke point, so an unmanaged device cannot be
/// cycled by a code path that never asked. A hand-built action handed
/// straight to an executor would have missed this.
#[test]
fn cycling_an_unmanaged_device_changes_nothing() {
	let desired = document(
		"device wwan0 {\n\
		 \tmanaged = false\n\
		 \tmodem { sim = [\"esim\", \"socket\"] }\n\
		 }\n\
		 interface wwan0 { config = \"dhcp\" }\n",
	);
	let observed = observed_with(&["wwan0"]);

	let plan = plan(
		&desired,
		&observed,
		&PlanOptions {
			cycle: vec!["wwan0".to_owned()],
			..PlanOptions::default()
		},
	);
	assert!(
		!names(&plan).contains(&"link.down"),
		"an unmanaged device must not be cycled: {:?}",
		names(&plan)
	);
}

/// Ranking a wifi *network* against an ethernet interface, which is the thing
/// an interface's `preference` alone could not say.
///
/// A radio carries one preference whichever network it joined, so "the office
/// wifi beats this ethernet, the cafe wifi does not" was inexpressible. The
/// unit on the wireless side has to be the network, because that is the thing
/// that changes.
#[test]
fn an_associated_networks_metric_outranks_the_interfaces_preference() {
	let desired = document(
		"interface eth0 {\n\
		 \tconfig = \"192.0.2.10/24\"\n\
		 \troutes = \"default via 192.0.2.1\"\n\
		 \tpreference = 100\n\
		 }\n\
		 interface wlan0 {\n\
		 \tconfig = \"10.0.0.5/24\"\n\
		 \troutes = \"default via 10.0.0.1\"\n\
		 \tpreference = 600\n\
		 }\n\
		 network \"Office\" {\n\
		 \tmetric = 50\n\
		 \twifi { psk = \"@secret:office\" }\n\
		 }\n",
	);
	let mut observed = observed_with(&["eth0", "wlan0"]);
	for link in &mut observed.links {
		link.up = true;
	}
	// The radio is on `Office`, which the document ranks ahead of the cable.
	observed.links[1].network = Some("Office".to_owned());

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let metrics: Vec<Option<u32>> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { iface, route } if iface == "wlan0" => Some(route.metric),
			_ => None,
		})
		.collect();
	assert_eq!(
		metrics,
		vec![Some(50)],
		"the network's metric should win over the interface's 600: {:?}",
		names(&plan)
	);
}

/// The same radio on a network that names no metric keeps the interface's
/// preference, which is what every machine that never needed this gets.
#[test]
fn a_network_with_no_metric_leaves_the_preference_alone() {
	let desired = document(
		"interface wlan0 {\n\
		 \tconfig = \"10.0.0.5/24\"\n\
		 \troutes = \"default via 10.0.0.1\"\n\
		 \tpreference = 600\n\
		 }\n\
		 network \"Cafe\" {\n\
		 \twifi { psk = \"@secret:cafe\" }\n\
		 }\n",
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.links[0].network = Some("Cafe".to_owned());

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let metrics: Vec<Option<u32>> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { route, .. } => Some(route.metric),
			_ => None,
		})
		.collect();
	assert_eq!(metrics, vec![Some(600)], "{:?}", names(&plan));
}

/// An association to a network the document does not describe is a real state
/// -- somebody joined something by hand -- and falls back rather than failing.
#[test]
fn an_unknown_association_falls_back_to_the_preference() {
	let desired = document(
		"interface wlan0 {\n\
		 \tconfig = \"10.0.0.5/24\"\n\
		 \troutes = \"default via 10.0.0.1\"\n\
		 \tpreference = 600\n\
		 }\n",
	);
	let mut observed = observed_with(&["wlan0"]);
	observed.links[0].up = true;
	observed.links[0].network = Some("SomethingElse".to_owned());

	let plan = plan(&desired, &observed, &PlanOptions::default());
	let metrics: Vec<Option<u32>> = plan
		.actions
		.iter()
		.filter_map(|action| match &action.op {
			Op::RouteAdd { route, .. } => Some(route.metric),
			_ => None,
		})
		.collect();
	assert_eq!(metrics, vec![Some(600)], "{:?}", names(&plan));
}

/// A `bluetooth` block is read and says so.
///
/// **The silence this catches is the one `warn_unapplied` exists for.** A
/// bluetooth device compiles, canonicalises, appears in `ncfg show` and is in
/// the frozen schema, and the planner does nothing with it -- so a plan
/// described everything else the machine would do and never mentioned the
/// headphones somebody wrote down. 0061 settled that a recognised-and-inert
/// key is warned about at plan time rather than refused at compile time.
///
/// One per device, asserted by count rather than by presence: a warning for
/// the list would name neither, and it is the id an operator looks for.
#[test]
fn a_bluetooth_block_is_warned_about_rather_than_silently_ignored() {
	let desired = document(
		r#"bluetooth "headphones" { address = "AA:BB:CC:DD:EE:FF"; profile = "a2dp-sink" }
		   bluetooth "phone" { address = "11:22:33:44:55:66"; profile = "pan" }"#,
	);
	let plan = plan(&desired, &Observed::default(), &PlanOptions::default());

	let named: Vec<&str> = plan
		.warnings
		.iter()
		.filter(|w| w.message.contains("is understood and not acted on"))
		.map(|w| w.message.as_str())
		.collect();
	assert_eq!(named.len(), 2, "one per device, got {:?}", plan.warnings);
	assert!(
		named.iter().any(|m| m.contains("headphones")) && named.iter().any(|m| m.contains("phone")),
		"each warning names its own device: {named:?}"
	);
}
