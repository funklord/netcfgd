//! Why is it like this?
//!
//! The question the whole project exists to answer. Design section 1.1 calls
//! the inability to answer it Pain 1, and everything else -- plain-text
//! config, greppable `/run`, a plan you can read -- is machinery in service of
//! it.
//!
//! Pure: four artifacts in, an [`Explanation`] out. No sockets, no kernel. The
//! CLI answers locally and the daemon answers over the socket, and they
//! produce the same words because they run the same function.

use netcfgd_compile::Provenance;
use netcfgd_model::{AddressSource, Document, Observed, Origin, Ownership};
use netcfgd_plan::{plan, PlanOptions};
use netcfgd_proto::{Explanation, Fact, Subject};

/// Explain something.
#[must_use]
pub fn explain(
	subject: &Subject,
	desired: Option<&Document>,
	observed: &Observed,
	provenance: &Provenance,
) -> Explanation {
	match subject {
		Subject::Interface { name } => interface(name, desired, observed, provenance),
		Subject::Address { interface, address } => {
			self::address(interface, address, desired, observed, provenance)
		}
		Subject::Route {
			interface,
			destination,
		} => route(interface, destination, desired, observed, provenance),
	}
}

fn fact(topic: &str, detail: impl Into<String>) -> Fact {
	Fact {
		topic: topic.to_owned(),
		detail: detail.into(),
		source: None,
	}
}

fn sourced(topic: &str, detail: impl Into<String>, source: Option<String>) -> Fact {
	Fact {
		topic: topic.to_owned(),
		detail: detail.into(),
		source,
	}
}

fn location(provenance: &Provenance, path: &str) -> Option<String> {
	provenance
		.lookup(path)
		.map(netcfgd_compile::provenance::Entry::location)
}

/// How ownership was decided, which decision 0002 requires to be reported.
///
/// The two mechanisms are not equally strong, and an operator deciding whether
/// to trust a drift report needs to know which one produced it. Saying only
/// "foreign" hides that on a pre-5.18 kernel the answer is a guess from
/// recorded state.
fn ownership_fact(observed: &Observed, ownership: Ownership, proto: Option<u8>) -> Fact {
	let mechanism = if observed.address_proto_supported {
		match proto {
			Some(value) => format!("the kernel reports IFA_PROTO {value}"),
			None => "the kernel reports no IFA_PROTO on it".to_owned(),
		}
	} else {
		"no address here carries IFA_PROTO, so this comes from recorded state \
		 in /run and is the weaker answer"
			.to_owned()
	};
	Fact {
		topic: "ownership".to_owned(),
		detail: format!("{ownership:?}: {mechanism}"),
		source: Some(if observed.address_proto_supported {
			"kernel".to_owned()
		} else {
			"/run/netcfgd/owned.json".to_owned()
		}),
	}
}

fn interface(
	name: &str,
	desired: Option<&Document>,
	observed: &Observed,
	provenance: &Provenance,
) -> Explanation {
	let mut facts = Vec::new();
	let path = netcfgd_compile::provenance::interface_path(name);

	match desired.and_then(|document| {
		document
			.interfaces
			.iter()
			.find(|interface| interface.name == name)
	}) {
		Some(interface) => {
			facts.push(sourced(
				"desired",
				"declared in the configuration",
				location(provenance, &path),
			));
			if let Some(mtu) = interface.mtu {
				facts.push(sourced(
					"desired",
					format!("mtu {mtu}"),
					location(
						provenance,
						&netcfgd_compile::provenance::field_path(name, "mtu"),
					),
				));
			}
			for (index, source) in interface.addressing.iter().enumerate() {
				facts.push(sourced(
					"desired",
					format!("addressing[{index}] is {}", render_source(source)),
					location(
						provenance,
						&netcfgd_compile::provenance::field_path(
							name,
							&format!("addressing[{index}]"),
						),
					),
				));
			}
			if let Some(guard) = &interface.guard {
				facts.push(sourced(
					"guard",
					format!(
						"{} depends on this interface, so disruptive changes are refused",
						guard.reason
					),
					location(
						provenance,
						&netcfgd_compile::provenance::field_path(name, "guard"),
					),
				));
			}
			let policy = interface.on_drift.map_or_else(
				|| {
					format!(
						"{:?} (from globals)",
						desired
							.map(|d| d.globals.on_drift_default)
							.unwrap_or_default()
					)
				},
				|policy| format!("{policy:?}"),
			);
			facts.push(fact("drift", format!("on_drift is {policy}")));
		}
		None => facts.push(fact(
			"desired",
			"not mentioned in the configuration; netcfgd does not manage it",
		)),
	}

	match observed.link(name) {
		Some(link) => {
			facts.push(sourced(
				"observed",
				format!(
					"{}, {}, mtu {}",
					if link.up { "up" } else { "down" },
					if link.carrier {
						"carrier"
					} else {
						"no carrier"
					},
					link.mtu
				),
				Some("kernel".to_owned()),
			));
			for address in observed.addresses_on(name) {
				facts.push(ownership_fact(observed, address.ownership, address.proto));
				facts.push(sourced(
					"observed",
					format!("address {}", address.address),
					Some("kernel".to_owned()),
				));
			}
		}
		None => facts.push(fact("observed", "no such interface is present")),
	}

	facts.extend(pending(name, desired, observed));

	Explanation {
		subject: format!("interface {name}"),
		facts,
	}
}

fn address(
	interface: &str,
	address: &str,
	desired: Option<&Document>,
	observed: &Observed,
	provenance: &Provenance,
) -> Explanation {
	let mut facts = Vec::new();

	let wanted = desired
		.and_then(|document| {
			document
				.interfaces
				.iter()
				.find(|candidate| candidate.name == interface)
		})
		.and_then(|candidate| {
			candidate.addressing.iter().enumerate().find(
				|(_, source)| matches!(source, AddressSource::Static(s) if s.address == address),
			)
		});

	match wanted {
		Some((index, _)) => facts.push(sourced(
			"desired",
			"the configuration asks for this address",
			location(
				provenance,
				&netcfgd_compile::provenance::field_path(
					interface,
					&format!("addressing[{index}]"),
				),
			),
		)),
		None => facts.push(fact(
			"desired",
			"the configuration does not ask for this address",
		)),
	}

	match observed
		.addresses_on(interface)
		.find(|candidate| candidate.address == address)
	{
		Some(found) => {
			facts.push(sourced(
				"observed",
				"present on the interface",
				Some("kernel".to_owned()),
			));
			facts.push(ownership_fact(observed, found.ownership, found.proto));
			facts.push(fact(
				"origin",
				match found.origin {
					Some(Origin::Static) => "netcfgd installed it from the configuration",
					Some(Origin::Dhcp4 | Origin::Dhcp6) => {
						"it came from a lease, so the backend owns it, not the planner"
					}
					Some(Origin::Slaac) => "it came from a router advertisement",
					Some(Origin::LinkLocal) => "it is link-local autoconfiguration",
					Some(Origin::Delegated) => "it was built from a delegated prefix",
					None => "netcfgd has no record of installing it",
				},
			));
			if !found.ownership.may_remove() {
				facts.push(fact(
					"safety",
					"netcfgd will never remove this address, because it is not \
					 recorded as its own",
				));
			}
		}
		None => facts.push(fact("observed", "not present on the interface")),
	}

	facts.extend(pending(interface, desired, observed));

	Explanation {
		subject: format!("address {address} on {interface}"),
		facts,
	}
}

fn route(
	interface: &str,
	destination: &str,
	desired: Option<&Document>,
	observed: &Observed,
	provenance: &Provenance,
) -> Explanation {
	let mut facts = Vec::new();

	let wanted = desired
		.and_then(|document| {
			document
				.interfaces
				.iter()
				.find(|candidate| candidate.name == interface)
		})
		.and_then(|candidate| {
			candidate
				.routes
				.iter()
				.find(|route| route.destination == destination)
		});

	match wanted {
		Some(route) => facts.push(sourced(
			"desired",
			format!(
				"the configuration asks for it{}",
				route
					.via
					.map_or_else(String::new, |gateway| format!(" via {gateway}"))
			),
			location(
				provenance,
				&netcfgd_compile::provenance::field_path(
					interface,
					&format!("routes[{destination}]"),
				),
			),
		)),
		None => facts.push(fact("desired", "the configuration does not ask for it")),
	}

	match observed
		.routes_on(interface)
		.find(|route| route.destination == destination)
	{
		Some(found) => {
			facts.push(sourced(
				"observed",
				format!(
					"present{}",
					found
						.via
						.map_or_else(String::new, |gateway| format!(" via {gateway}"))
				),
				Some("kernel".to_owned()),
			));
			facts.push(Fact {
				topic: "ownership".to_owned(),
				detail: match found.proto {
					Some(value) if value == netcfgd_model::route::NETCFGD_PROTO => format!(
						"{:?}: rtm_protocol {value} is netcfgd's own tag",
						found.ownership
					),
					Some(value) => format!(
						"{:?}: rtm_protocol {value} belongs to something else",
						found.ownership
					),
					None => format!("{:?}: no protocol tag", found.ownership),
				},
				// Unlike addresses, a route's protocol comes straight from the
				// kernel on every supported version, so this needs no fallback
				// and no caveat.
				source: Some("kernel".to_owned()),
			});
		}
		None => facts.push(fact("observed", "not present")),
	}

	facts.extend(pending(interface, desired, observed));

	Explanation {
		subject: format!("route {destination} on {interface}"),
		facts,
	}
}

/// What netcfgd would do next, which is half of "why is it like this".
///
/// An explanation that describes only the present tense leaves the reader
/// asking the obvious follow-up. Planning here is cheap -- it is a pure
/// function of two things already in hand.
fn pending(interface: &str, desired: Option<&Document>, observed: &Observed) -> Vec<Fact> {
	let Some(document) = desired else {
		return vec![fact(
			"next",
			"there is no compiled configuration, so nothing is planned",
		)];
	};
	let plan = plan(document, observed, &PlanOptions::default());

	let mut facts: Vec<Fact> = plan
		.actions
		.iter()
		.filter(|action| action.op.interface() == Some(interface))
		.map(|action| {
			fact(
				"next",
				format!(
					"{} because {} is {} and should be {}",
					action.op.name(),
					action.reason.field,
					action.reason.observed,
					action.reason.desired
				),
			)
		})
		.collect();

	for refusal in plan
		.refusals
		.iter()
		.filter(|refusal| refusal.interface == interface)
	{
		facts.push(fact(
			"next",
			format!(
				"{} is refused because {} depends on this interface; allow it with `{}`",
				refusal.op, refusal.guard, refusal.override_with
			),
		));
	}

	if facts.is_empty() {
		facts.push(fact("next", "nothing; the interface matches its config"));
	}
	facts
}

fn render_source(source: &AddressSource) -> String {
	match source {
		AddressSource::Static(address) => address.address.clone(),
		AddressSource::Delegated(delegated) => {
			format!("a prefix delegated to {}", delegated.prefix.source)
		}
		other => other.kind_name().to_owned(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::{Guard, Interface, InterfaceKind, ObservedAddress, ObservedLink, Static};

	fn interface_named(name: &str) -> Interface {
		Interface {
			name: name.to_owned(),
			kind: InterfaceKind::Physical,
			enabled: true,
			mtu: None,
			mac: None,
			addressing: vec![AddressSource::Static(Static {
				address: "10.0.0.1/24".to_owned(),
				peer: None,
				preferred_lifetime: None,
				valid_lifetime: None,
			})],
			routes: Vec::new(),
			dns: None,
			hooks: Vec::new(),
			on_drift: None,
			master: None,
			dot1x: None,
			advertise: None,
			forwarding: None,
			nat: None,
			qdisc: None,
			ingress_redirect: None,
			guard: None,
			ipv6_token: None,
			link_settings: None,
			preference: None,
			bridge_vlans: Vec::new(),
		}
	}

	fn document_with(interface: Interface) -> Document {
		Document {
			interfaces: vec![interface],
			..Document::default()
		}
	}

	fn observed_with(address: ObservedAddress, proto_supported: bool) -> Observed {
		Observed {
			links: vec![ObservedLink {
				name: "eth0".to_owned(),
				index: 2,
				kind: String::new(),
				up: true,
				carrier: true,
				mtu: 1500,
				mac: None,
				master: None,
				ipv6_token: None,
				qdisc: None,
				qdisc_bandwidth_bits: None,
				qdisc_ingress: false,
				ingress_redirect: None,
				forwarding: None,
				ownership: Ownership::Unknown,
			}],
			addresses: vec![address],
			address_proto_supported: proto_supported,
			..Observed::default()
		}
	}

	fn ours(origin: Origin) -> ObservedAddress {
		ObservedAddress {
			interface: "eth0".to_owned(),
			address: "10.0.0.1/24".to_owned(),
			proto: Some(netcfgd_model::route::NETCFGD_PROTO),
			ownership: Ownership::Ours,
			origin: Some(origin),
		}
	}

	fn detail(explanation: &Explanation, topic: &str) -> String {
		explanation
			.facts
			.iter()
			.filter(|fact| fact.topic == topic)
			.map(|fact| fact.detail.clone())
			.collect::<Vec<_>>()
			.join(" | ")
	}

	#[test]
	fn an_address_we_installed_says_so_and_says_how_we_know() {
		let document = document_with(interface_named("eth0"));
		let observed = observed_with(ours(Origin::Static), true);
		let explanation = explain(
			&Subject::Address {
				interface: "eth0".to_owned(),
				address: "10.0.0.1/24".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);

		assert!(detail(&explanation, "ownership").contains("IFA_PROTO"));
		assert!(detail(&explanation, "origin").contains("from the configuration"));
	}

	/// Decision 0002 requires `explain` to say which mechanism produced the
	/// ownership answer, because the fallback is weaker and an operator
	/// deciding whether to trust a drift report needs to know.
	#[test]
	fn the_weaker_mechanism_is_named_as_weaker() {
		let document = document_with(interface_named("eth0"));
		let mut address = ours(Origin::Static);
		address.proto = None;
		address.ownership = Ownership::Unknown;
		let observed = observed_with(address, false);

		let explanation = explain(
			&Subject::Address {
				interface: "eth0".to_owned(),
				address: "10.0.0.1/24".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);

		let ownership = detail(&explanation, "ownership");
		assert!(ownership.contains("recorded state"), "got: {ownership}");
		assert!(ownership.contains("weaker"), "got: {ownership}");
		// And it must say netcfgd will not remove it, which is the
		// consequence the operator actually cares about.
		assert!(detail(&explanation, "safety").contains("never remove"));
	}

	/// Decision 0006 rule 7 in words: a lease's address belongs to the
	/// backend, and explaining it any other way invites somebody to delete it.
	#[test]
	fn a_lease_address_says_the_backend_owns_it() {
		let document = document_with(interface_named("eth0"));
		let observed = observed_with(ours(Origin::Dhcp4), true);
		let explanation = explain(
			&Subject::Address {
				interface: "eth0".to_owned(),
				address: "10.0.0.1/24".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		assert!(detail(&explanation, "origin").contains("backend owns it"));
	}

	/// A guard is the reason a change is not happening, so explaining an
	/// interface has to mention both the guard and the refusal it causes.
	#[test]
	fn a_guarded_interface_explains_what_is_blocked_and_how_to_allow_it() {
		let mut interface = interface_named("eth0");
		interface.guard = Some(Guard {
			reason: "nfs root".to_owned(),
		});
		// An address netcfgd owns that the config no longer wants: teardown
		// would remove it, and the guard refuses.
		let mut stale = ours(Origin::Static);
		stale.address = "10.0.0.99/24".to_owned();
		let mut observed = observed_with(ours(Origin::Static), true);
		observed.addresses.push(stale);

		let explanation = explain(
			&Subject::Interface {
				name: "eth0".to_owned(),
			},
			Some(&document_with(interface)),
			&observed,
			&Provenance::default(),
		);

		assert!(detail(&explanation, "guard").contains("nfs root"));
		let next = detail(&explanation, "next");
		assert!(next.contains("refused"), "got: {next}");
		assert!(next.contains("--allow-disruption"), "got: {next}");
	}

	/// An interface netcfgd does not manage should say so plainly, rather than
	/// producing an explanation that reads like it is managed and idle.
	#[test]
	fn an_unmanaged_interface_says_it_is_unmanaged() {
		let observed = observed_with(ours(Origin::Static), true);
		let explanation = explain(
			&Subject::Interface {
				name: "eth0".to_owned(),
			},
			Some(&Document::default()),
			&observed,
			&Provenance::default(),
		);
		assert!(detail(&explanation, "desired").contains("does not manage it"));
	}

	/// Explaining without a compiled configuration must still work, because
	/// the moment somebody reaches for `explain` is often the moment the
	/// config has stopped compiling.
	#[test]
	fn explaining_without_a_configuration_still_answers() {
		let observed = observed_with(ours(Origin::Static), true);
		let explanation = explain(
			&Subject::Interface {
				name: "eth0".to_owned(),
			},
			None,
			&observed,
			&Provenance::default(),
		);
		assert!(!explanation.facts.is_empty());
		assert!(detail(&explanation, "next").contains("no compiled configuration"));
	}
}
