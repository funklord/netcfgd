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

/// What the configuration says about this interface.
///
/// Split from the observation half so that neither grows past the point where a
/// reader can hold it: an explanation is a list of facts from two different
/// worlds, and the code should read that way too.
fn declared(
	name: &str,
	interface: &netcfgd_model::Interface,
	document: &Document,
	provenance: &Provenance,
) -> Vec<Fact> {
	let mut facts = Vec::new();
	let path = netcfgd_compile::provenance::interface_path(name);
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
				&netcfgd_compile::provenance::field_path(name, &format!("addressing[{index}]")),
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
		|| format!("{:?} (from globals)", document.globals.on_drift_default),
		|policy| format!("{policy:?}"),
	);
	facts.push(fact("drift", format!("on_drift is {policy}")));
	facts
}

fn interface(
	name: &str,
	desired: Option<&Document>,
	observed: &Observed,
	provenance: &Provenance,
) -> Explanation {
	let mut facts = Vec::new();
	match desired.and_then(|document| {
		document
			.interfaces
			.iter()
			.find(|interface| interface.name == name)
			.map(|interface| (document, interface))
	}) {
		Some((document, interface)) => {
			facts.extend(declared(name, interface, document, provenance));
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

	facts.extend(backends_on(name, observed));

	facts.extend(pending(name, desired, observed));

	Explanation {
		subject: format!("interface {name}"),
		facts,
	}
}

/// What a report says about this interface, where the document asked for one.
///
/// `ncfg explain` answers "why is this here", and until this existed it
/// answered "the configuration does not ask for it" about an address netcfgd
/// had installed itself and would withdraw itself. The document names a
/// *source* rather than a value for these (decisions 0045, 0047), so the
/// explanation has to follow the indirection the way the planner does --
/// through `netcfgd_plan::takes_reports`, so the two cannot disagree about
/// which reports are believed.
fn report_for<'a>(
	interface: &str,
	desired: Option<&Document>,
	observed: &'a Observed,
) -> Option<&'a netcfgd_model::ObservedReport> {
	let asked = desired
		.and_then(|document| {
			document
				.interfaces
				.iter()
				.find(|candidate| candidate.name == interface)
		})
		.is_some_and(netcfgd_plan::takes_reports);
	if !asked {
		return None;
	}
	observed
		.reports
		.iter()
		.find(|report| report.interface == interface)
}

/// The indirection that produced an address, where one did.
///
/// Two of the six addressing sources name a *source* rather than a value, and
/// both used to explain as "the configuration does not ask for this address"
/// about an address netcfgd had installed itself and would withdraw itself:
///
/// - a **report**, whose value is in a file something else wrote
///   (decisions 0045, 0047), and
/// - a **delegated prefix**, whose value did not exist until an ISP handed one
///   out (decision 0009).
///
/// Following the indirection is the whole of what `ncfg explain` is for on
/// these two. Naming the file it ends at is the other half: the next question
/// after "why is this here" is "where does that come from", and an answer that
/// stops at "a report" has only moved the question.
fn indirect_source(
	interface: &str,
	address: &str,
	desired: Option<&Document>,
	observed: &Observed,
) -> Option<(String, Option<String>)> {
	if report_for(interface, desired, observed)
		.is_some_and(|report| report.addresses.iter().any(|held| held == address))
	{
		return Some((
			"the configuration takes this interface's addresses from a report, and the \
			 report names this one"
				.to_owned(),
			Some(report_source(interface)),
		));
	}

	// A delegated address is derived rather than reported, so the check is the
	// derivation the planner performs -- the same function, so the two cannot
	// disagree about which address a reference produces.
	let interface_block = desired?
		.interfaces
		.iter()
		.find(|candidate| candidate.name == interface)?;
	for source in &interface_block.addressing {
		let AddressSource::Delegated(delegated) = source else {
			continue;
		};
		let Some(delegation) = observed.delegation(&delegated.prefix.source) else {
			continue;
		};
		let Some(prefix) = delegation.prefixes.get(delegated.prefix.index as usize) else {
			continue;
		};
		if netcfgd_model::derive_from_delegation(prefix, &delegated.prefix, &delegated.suffix)
			.is_ok_and(|derived| derived == address)
		{
			return Some((
				format!(
					"the configuration builds it from `{}`, which {} was delegated as {prefix}",
					delegated.suffix, delegated.prefix.source
				),
				Some(format!("/run/netcfgd/prefixes/{}", delegated.prefix.source)),
			));
		}
	}
	None
}

/// The file a report was read from, for a fact's source.
fn report_source(interface: &str) -> String {
	format!("/run/netcfgd/reported/{interface}")
}

/// What netcfgd started on this interface, and whether it is still current.
///
/// The interface's own facts come from the kernel; a backend's cannot. hostapd
/// and radvd read a file once and report almost nothing back, so what netcfgd
/// knows is what it wrote -- and decisions 0052 and 0053 turned that into three
/// answers worth surfacing here, because "why did my access point restart" is
/// the question `ncfg explain` exists for and the plan alone answers it only
/// while the restart is still pending.
fn backends_on(interface: &str, observed: &Observed) -> Vec<Fact> {
	let mut facts = Vec::new();
	for backend in observed
		.backends
		.iter()
		.filter(|backend| backend.interface == interface && backend.running)
	{
		facts.push(sourced(
			"backend",
			format!("{:?} is running", backend.kind),
			Some("/run/netcfgd/owned.json".to_owned()),
		));
		if let Some(started) = &backend.started_with {
			facts.push(fact(
				"backend",
				format!(
					"started with ssid {}{}{}",
					started.ssid.to_hex(),
					started
						.channel
						.map_or_else(String::new, |channel| format!(", channel {channel}")),
					started
						.band
						.as_ref()
						.map_or_else(String::new, |band| format!(", {band} GHz")),
				),
			));
		}
		// Only the answers that mean something is wrong. "Still current" is the
		// ordinary case and would be a line every reader learns to skip, which
		// is how the one line that matters gets skipped with it.
		if backend.secret_matches == Some(false) {
			facts.push(fact(
				"backend",
				"the passphrase in the secret store is not the one it was started with, so it \
				 will be restarted",
			));
		}
		if backend.config_matches == Some(false) {
			facts.push(fact(
				"backend",
				"the configuration file it was started from has changed since, so it will be \
				 restarted",
			));
		}
		if !backend.advertised.is_empty() {
			facts.push(fact(
				"backend",
				format!("advertising {}", backend.advertised.join(" ")),
			));
		}
	}
	facts
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
		// The document names a source rather than a value, so "does not ask
		// for it" would be wrong about an address netcfgd installed itself.
		None => match indirect_source(interface, address, desired, observed) {
			Some((detail, source)) => facts.push(sourced("desired", detail, source)),
			None => facts.push(fact(
				"desired",
				"the configuration does not ask for this address",
			)),
		},
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
		// Same indirection as an address: a reported gateway becomes a
		// default route and a reported `route=` line names its own
		// destination, and neither appears in the document.
		None => match report_for(interface, desired, observed).and_then(|report| {
			if destination == "default" && !report.gateways.is_empty() {
				return Some("a gateway, which becomes this default route");
			}
			report
				.routes
				.iter()
				.any(|route| route.destination == destination)
				.then_some("this route")
		}) {
			Some(what) => facts.push(sourced(
				"desired",
				format!("the configuration takes this interface's routes from a report, and the report names {what}"),
				Some(report_source(interface)),
			)),
			None => facts.push(fact("desired", "the configuration does not ask for it")),
		},
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
				offloads: Vec::new(),
				ipv6_token: None,
				qdisc: None,
				qdisc_bandwidth_bits: None,
				qdisc_ingress: false,
				ingress_redirect: None,
				forwarding: None,
				ownership: Ownership::Unknown,
				private_key_loaded: false,
				wireguard: None,
				bridge: None,
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
	/// And so does one built from a delegated prefix.
	///
	/// The other of the two sources the document names by reference rather than
	/// by value (decision 0009). It explained as "the configuration does not
	/// ask for this address" about an address netcfgd derived itself -- and the
	/// answer an operator wants is which delegation it came from, because that
	/// is where the next question goes.
	#[test]
	fn a_delegated_address_names_the_delegation_it_came_from() {
		let mut interface = interface_named("lan0");
		interface.addressing = vec![AddressSource::Delegated(netcfgd_model::Delegated {
			prefix: netcfgd_model::PrefixRef {
				source: "wan0".to_owned(),
				index: 0,
				subnet: 0,
			},
			suffix: "::1/64".to_owned(),
		})];
		let document = document_with(interface);

		let mut observed = observed_with(
			ObservedAddress {
				interface: "lan0".to_owned(),
				address: "2001:db8:1234::1/64".to_owned(),
				proto: Some(110),
				ownership: Ownership::Ours,
				origin: Some(Origin::Delegated),
			},
			true,
		);
		observed.delegations.push(netcfgd_model::Delegation {
			interface: "wan0".to_owned(),
			prefixes: vec!["2001:db8:1234::/56".to_owned()],
		});

		let explanation = explain(
			&Subject::Address {
				interface: "lan0".to_owned(),
				address: "2001:db8:1234::1/64".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		let desired = detail(&explanation, "desired");
		assert!(desired.contains("2001:db8:1234::/56"), "got {desired}");
		assert!(desired.contains("wan0"), "got {desired}");
		assert!(
			explanation
				.facts
				.iter()
				.any(|item| item.source.as_deref() == Some("/run/netcfgd/prefixes/wan0")),
			"the fact should name the file: {:?}",
			explanation.facts
		);
	}

	/// An access point that is about to be restarted says why, and says it
	/// where somebody asking about the interface will see it.
	///
	/// The plan answers this too, and only while the restart is pending. What
	/// an operator asks after the fact is "what is this thing running", and
	/// hostapd cannot be asked -- so netcfgd's own record is the answer
	/// (decisions 0052, 0053).
	#[test]
	fn a_stale_backend_says_so_on_the_interface() {
		let document = document_with(interface_named("wlan0"));
		let mut observed = Observed::default();
		observed.backends.push(netcfgd_model::ObservedBackend {
			kind: netcfgd_model::BackendKind::AccessPoint,
			interface: "wlan0".to_owned(),
			running: true,
			access_control: None,
			started_with: Some(netcfgd_model::ObservedAccessPoint {
				ssid: netcfgd_model::Ssid::new(b"home".to_vec()).expect("an ssid"),
				band: None,
				channel: Some(6),
			}),
			secret_matches: Some(false),
			config_matches: None,
			advertised: Vec::new(),
		});

		let explanation = explain(
			&Subject::Interface {
				name: "wlan0".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		let backend = detail(&explanation, "backend");
		assert!(backend.contains("686f6d65"), "got {backend}");
		assert!(backend.contains("channel 6"), "got {backend}");
		assert!(backend.contains("passphrase"), "got {backend}");
	}

	/// An address netcfgd installed from a report explains itself.
	///
	/// It used to answer "the configuration does not ask for this address"
	/// about an address netcfgd had installed itself and would withdraw
	/// itself, because the document names a source rather than a value and the
	/// explanation only looked for values.
	#[test]
	fn a_reported_address_says_where_the_value_came_from() {
		let mut interface = interface_named("wwan0");
		interface.addressing = vec![AddressSource::Reported(netcfgd_model::Reported::default())];
		let document = document_with(interface);

		let mut observed = observed_with(
			ObservedAddress {
				interface: "wwan0".to_owned(),
				address: "10.64.1.23/30".to_owned(),
				proto: Some(110),
				ownership: Ownership::Ours,
				origin: None,
			},
			true,
		);
		observed.reports.push(netcfgd_model::ObservedReport {
			interface: "wwan0".to_owned(),
			addresses: vec!["10.64.1.23/30".to_owned()],
			gateways: vec!["10.64.1.24".to_owned()],
			nameservers: Vec::new(),
			routes: Vec::new(),
		});

		let explanation = explain(
			&Subject::Address {
				interface: "wwan0".to_owned(),
				address: "10.64.1.23/30".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		let desired = detail(&explanation, "desired");
		assert!(desired.contains("from a report"), "got {desired}");
		assert!(
			explanation
				.facts
				.iter()
				.any(|item| item.source.as_deref() == Some("/run/netcfgd/reported/wwan0")),
			"the fact should name the file: {:?}",
			explanation.facts
		);
	}

	/// And so does the default route a reported gateway implies.
	#[test]
	fn a_reported_gateway_explains_the_default_route_it_implies() {
		let mut interface = interface_named("wwan0");
		interface.addressing = vec![AddressSource::Reported(netcfgd_model::Reported::default())];
		let document = document_with(interface);

		let mut observed = Observed::default();
		observed.reports.push(netcfgd_model::ObservedReport {
			interface: "wwan0".to_owned(),
			addresses: Vec::new(),
			gateways: vec!["10.64.1.24".to_owned()],
			nameservers: Vec::new(),
			routes: Vec::new(),
		});

		let explanation = explain(
			&Subject::Route {
				interface: "wwan0".to_owned(),
				destination: "default".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		let desired = detail(&explanation, "desired");
		assert!(desired.contains("a gateway"), "got {desired}");
	}

	/// A report for an interface the document says nothing about is still not
	/// an answer. The explanation follows the planner's gate rather than the
	/// existence of a file, or it would explain routes netcfgd never installed.
	#[test]
	fn a_report_the_document_never_asked_for_explains_nothing() {
		let document = document_with(interface_named("wwan0"));
		let mut observed = Observed::default();
		observed.reports.push(netcfgd_model::ObservedReport {
			interface: "wwan0".to_owned(),
			addresses: Vec::new(),
			gateways: vec!["10.64.1.24".to_owned()],
			nameservers: Vec::new(),
			routes: Vec::new(),
		});

		let explanation = explain(
			&Subject::Route {
				interface: "wwan0".to_owned(),
				destination: "default".to_owned(),
			},
			Some(&document),
			&observed,
			&Provenance::default(),
		);
		assert!(
			detail(&explanation, "desired").contains("does not ask"),
			"got {}",
			detail(&explanation, "desired")
		);
	}

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
