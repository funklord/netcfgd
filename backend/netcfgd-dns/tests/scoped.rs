//! The scope-capable backends.
//!
//! Decision 0007's premise is that `~corp.example` in resolved,
//! `server=/corp.example/10.0.0.1` in dnsmasq and a named `forward-zone` in
//! unbound are three spellings of one thing. These check that netcfgd produces
//! all three from one model -- and, more importantly, that none of them
//! quietly loses the routing and sends an internal query to a public resolver.

use netcfgd_dns::render::{dnsmasq_conf, scopes_json, unbound_conf};
use netcfgd_dns::Scope;
use netcfgd_model::dns::{DnsMode, DnsPolicy, DnsServer, DnsTransport, RoutingDomain};

fn server(address: &str) -> DnsServer {
	DnsServer {
		addr: address.parse().expect("an address"),
		port: None,
		sni: None,
	}
}

fn split(mode: DnsMode) -> (DnsPolicy, DnsPolicy) {
	let globals = DnsPolicy {
		mode: mode.clone(),
		servers: vec![server("1.1.1.1")],
		search: vec!["home.example".to_owned()],
		..DnsPolicy::default()
	};
	let vpn = DnsPolicy {
		mode,
		servers: vec![server("10.0.0.53")],
		domains: vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	};
	(globals, vpn)
}

/// The property the whole module exists to protect: an exclusive routing
/// domain must reach the resolver as routing. If it is flattened, queries for
/// `corp.example` go to 1.1.1.1 -- which is a disclosure of internal names to
/// a public resolver, not a degradation of service.
#[test]
fn an_exclusive_domain_never_flattens() {
	let (globals, vpn) = split(DnsMode::Dnsmasq);
	let scopes = vec![
		Scope {
			name: "globals",
			policy: &globals,
		},
		Scope {
			name: "vpn0",
			policy: &vpn,
		},
	];

	let dnsmasq = dnsmasq_conf(&scopes);
	assert!(
		dnsmasq.contains("server=/corp.example/10.0.0.53"),
		"the suffix must be routed: {dnsmasq}"
	);
	assert!(
		!dnsmasq.contains("server=10.0.0.53\n"),
		"an exclusive scope's server must not also be general: {dnsmasq}"
	);
	assert!(dnsmasq.contains("server=1.1.1.1"), "got: {dnsmasq}");

	let unbound = unbound_conf(&scopes);
	assert!(unbound.contains("name: \"corp.example\""), "got: {unbound}");
	assert!(
		unbound.contains("forward-addr: 10.0.0.53"),
		"got: {unbound}"
	);
	// The catch-all is a zone too, and it is the globals scope's.
	assert!(unbound.contains("name: \".\""), "got: {unbound}");
}

/// A non-exclusive domain is a preference rather than a restriction, and
/// neither forwarder has a spelling for that -- so the server is routed *and*
/// left general, which is the closest either can get.
#[test]
fn a_non_exclusive_domain_stays_generally_usable() {
	let policy = DnsPolicy {
		mode: DnsMode::Dnsmasq,
		servers: vec![server("10.0.0.53")],
		domains: vec![RoutingDomain {
			suffix: "lan.example".to_owned(),
			exclusive: false,
		}],
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "eth0",
		policy: &policy,
	}];

	let text = dnsmasq_conf(&scopes);
	assert!(
		text.contains("server=/lan.example/10.0.0.53"),
		"got: {text}"
	);
	assert!(text.contains("server=10.0.0.53\n"), "got: {text}");
}

/// A scope with no routing domain contributes plain forwarding, so a document
/// mixing scoped and unscoped produces a file that does both.
#[test]
fn a_scope_without_domains_forwards_everything() {
	let policy = DnsPolicy {
		mode: DnsMode::Dnsmasq,
		servers: vec![server("9.9.9.9")],
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "globals",
		policy: &policy,
	}];
	assert!(dnsmasq_conf(&scopes).contains("server=9.9.9.9"));
	assert!(unbound_conf(&scopes).contains("name: \".\""));
}

/// unbound is one of the two backends that can do `DoT`, which is why decision
/// 0007 let `transport` into the model at all.
#[test]
fn unbound_carries_the_transport() {
	let policy = DnsPolicy {
		mode: DnsMode::Unbound,
		servers: vec![server("1.1.1.1")],
		transport: Some(DnsTransport::Tls),
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "globals",
		policy: &policy,
	}];
	assert!(unbound_conf(&scopes).contains("forward-tls-upstream: yes"));

	let plain = DnsPolicy {
		transport: None,
		..policy
	};
	let scopes = vec![Scope {
		name: "globals",
		policy: &plain,
	}];
	assert!(!unbound_conf(&scopes).contains("forward-tls-upstream"));
}

/// The exec mode receives scopes, not a flattening of them -- that is the
/// whole point of it being the escape hatch.
#[test]
fn the_exec_mode_receives_structure() {
	let (globals, vpn) = split(DnsMode::Exec("/usr/local/bin/dns".to_owned()));
	let scopes = vec![
		Scope {
			name: "globals",
			policy: &globals,
		},
		Scope {
			name: "vpn0",
			policy: &vpn,
		},
	];

	let json = scopes_json(&scopes);
	assert!(json.contains("\"name\":\"vpn0\""), "got: {json}");
	assert!(json.contains("\"suffix\":\"corp.example\""), "got: {json}");
	assert!(json.contains("\"exclusive\":true"), "got: {json}");
	assert!(
		json.contains("\"search\":[\"home.example\"]"),
		"got: {json}"
	);
	// Two scopes, distinguishable. A flattened blob would have one.
	assert_eq!(json.matches("\"name\":").count(), 2);
}

/// The JSON is hand-rolled, so the escaping is this file's responsibility. A
/// search domain is text from a config, and a config is not always careful.
#[test]
fn the_exec_json_escapes_what_json_requires() {
	let policy = DnsPolicy {
		mode: DnsMode::Exec("cat".to_owned()),
		search: vec!["a\"b\\c\nd\te".to_owned()],
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "globals",
		policy: &policy,
	}];

	let json = scopes_json(&scopes);
	assert!(json.contains(r#"a\"b\\c\nd\te"#), "got: {json}");
	// Every control character, not only the ones with short forms.
	let policy = DnsPolicy {
		mode: DnsMode::Exec("cat".to_owned()),
		search: vec!["bell\u{7}".to_owned()],
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "globals",
		policy: &policy,
	}];
	assert!(
		scopes_json(&scopes).contains("\\u0007"),
		"got: {}",
		scopes_json(&scopes)
	);
}

/// A trailing dot is how a fully qualified suffix is written, and dnsmasq does
/// not want it. Leaving it produces a zone that matches nothing.
#[test]
fn a_trailing_dot_is_stripped_for_dnsmasq() {
	let policy = DnsPolicy {
		mode: DnsMode::Dnsmasq,
		servers: vec![server("10.0.0.53")],
		domains: vec![RoutingDomain {
			suffix: "corp.example.".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	};
	let scopes = vec![Scope {
		name: "vpn0",
		policy: &policy,
	}];
	assert!(
		dnsmasq_conf(&scopes).contains("server=/corp.example/10.0.0.53"),
		"got: {}",
		dnsmasq_conf(&scopes)
	);
}
