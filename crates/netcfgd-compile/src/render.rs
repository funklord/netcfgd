//! The document, back as configuration text.
//!
//! The compiler goes one way and everything else here renders one block it
//! already knows about -- a wifi network, a control policy, an NM connection.
//! This is the other direction for a whole document, which is what
//! `ncfg profile save` needs: a profile has to mean later exactly what the
//! machine is running now, and the only exact form of that is the document
//! itself written back out.
//!
//! **Coverage is partial and refusal is explicit.** What this cannot render it
//! names, rather than leaving out -- a renderer that silently drops a field is
//! worse than none, because the field is gone from a profile nobody will read
//! again until they need it. The caller then has the round trip as a second
//! net: render, compile the result, and compare. Between the two, a lost field
//! is a refusal rather than a surprise.
//!
//! Lives beside the parser deliberately, so that a key added to one is under
//! the nose of whoever adds it to the other.

use netcfgd_model::control::Principal;
use netcfgd_model::dns::{DnsMode, DnsPolicy};
use netcfgd_model::interface::InterfaceKind;
use netcfgd_model::secret::{SecretProvider, SecretRef};
use netcfgd_model::security::Security;
use netcfgd_model::wifi::WifiNetwork;
use netcfgd_model::{AddressSource, Device, Document, DriftPolicy, HostnamePolicy, Interface};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Blocks that must be written as `override`.
///
/// A profile layers over `conf.d`, so a block the base already defines has to
/// say `override` -- and one it does not must not, because `override` with
/// nothing to override is a compile error. Only the caller knows which is
/// which, so it says, keyed as `"<kind> <name>"`.
pub type Overrides = BTreeSet<String>;

/// What could not be rendered, so the caller can say so precisely.
pub type Unrenderable = Vec<String>;

/// Render a whole document as configuration text.
///
/// # Errors
///
/// Every part that has no rendering here, named. The list is returned whole
/// rather than one at a time, so that somebody looking at an exotic
/// configuration learns everything that is in the way at once.
pub fn render(document: &Document, overrides: &Overrides) -> Result<String, Unrenderable> {
	let mut missing = Vec::new();
	let mut text = String::new();

	text.push_str(
		"# Written by netcfgd from what this machine was running.\n\
		 #\n\
		 # This is ordinary netcfgd configuration: edit it, diff it, commit it.\n\
		 # It is a snapshot rather than a hand-written profile, so it says\n\
		 # everything explicitly -- including things a person would have left to\n\
		 # a default.\n",
	);

	render_globals(document, &mut text, &mut missing);
	for interface in &document.interfaces {
		render_interface(interface, overrides, &mut text, &mut missing);
	}
	for network in &document.networks {
		render_network(network, overrides, &mut text, &mut missing);
	}
	for device in &document.devices {
		render_device(device, overrides, &mut text, &mut missing);
	}

	// Named rather than skipped, per the header: these have no rendering yet
	// and a profile that quietly lacked them would be wrong in a way nobody
	// would see until the rule or the access point was needed.
	if !document.rules.is_empty() {
		missing.push(format!("{} routing rule(s)", document.rules.len()));
	}
	if !document.access_points.is_empty() {
		missing.push(format!(
			"{} access_point block(s)",
			document.access_points.len()
		));
	}
	if !document.bluetooth.is_empty() {
		missing.push(format!("{} bluetooth block(s)", document.bluetooth.len()));
	}

	if missing.is_empty() {
		Ok(text)
	} else {
		Err(missing)
	}
}

/// A string as the lexer reads it back.
///
/// A quote or a backslash left raw would end the string early and produce a
/// file that does not compile -- which takes every other block with it, since
/// the loader compiles the directory as one document.
fn quote(value: &str) -> String {
	format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `override ` when the base defines this block, nothing when it does not.
fn opening(kind: &str, name: &str, overrides: &Overrides) -> String {
	if overrides.contains(&format!("{kind} {name}")) {
		format!("override {kind}")
	} else {
		kind.to_owned()
	}
}

fn render_globals(document: &Document, text: &mut String, missing: &mut Unrenderable) {
	let globals = &document.globals;
	let mut body = String::new();

	// The selection is deliberately not written. `ncfg profile save` selects
	// the profile afterwards by its own drop-in, and a profile that named
	// itself would make the loader choose again -- which the loader refuses.
	if let Some(confirm) = globals.confirm_default {
		let _ = writeln!(body, "\tconfirm = {confirm}");
	}
	if globals.on_drift_default != DriftPolicy::default() {
		let _ = writeln!(
			body,
			"\ton_drift = {}",
			quote(drift_name(globals.on_drift_default))
		);
	}
	if globals.networking != netcfgd_model::Networking::default() {
		body.push_str("\tnetworking = \"off\"\n");
	}
	match &globals.hostname_policy {
		HostnamePolicy::None => {}
		HostnamePolicy::FromDhcp => body.push_str("\thostname = \"from_dhcp\"\n"),
		HostnamePolicy::Static(name) => {
			let _ = writeln!(body, "\thostname = {}", quote(name));
		}
	}
	render_dns(&globals.dns, "\t", &mut body, missing, "global");

	let control = &globals.control;
	if *control != netcfgd_model::control::Control::default() {
		body.push_str("\tcontrol {\n");
		for (key, principal) in [
			("observe", &control.observe),
			("wifi", &control.wifi),
			("admin", &control.admin),
		] {
			let _ = writeln!(body, "\t\t{key} = {}", quote(&principal_name(principal)));
		}
		body.push_str("\t}\n");
	}

	let remote = &globals.remote;
	if *remote != netcfgd_model::control::RemotePolicy::default() {
		body.push_str("\tremote {\n");
		for (key, allowed) in [
			("observe", remote.observe),
			("wifi", remote.wifi),
			("admin", remote.admin),
		] {
			let _ = writeln!(body, "\t\t{key} = {allowed}");
		}
		body.push_str("\t}\n");
	}

	if !body.is_empty() {
		// `global` is a singleton whose sub-blocks merge (0147), so this is
		// never `override`: writing one that replaced the block would discard
		// whatever the base said about the parts this does not mention.
		text.push_str("\nglobal {\n");
		text.push_str(&body);
		text.push_str("}\n");
	}
}

fn render_dns(
	dns: &DnsPolicy,
	indent: &str,
	body: &mut String,
	missing: &mut Unrenderable,
	whose: &str,
) {
	if !dns.options.is_empty() {
		missing.push(format!("{whose}: dns options"));
	}
	if dns.dnssec.is_some() {
		missing.push(format!("{whose}: dnssec"));
	}
	if dns.transport.is_some() {
		missing.push(format!("{whose}: dns transport"));
	}
	let servers: Vec<String> = dns
		.servers
		.iter()
		.map(|server| {
			if server.port.is_some() || server.sni.is_some() {
				missing.push(format!("{whose}: a dns server with a port or sni"));
			}
			quote(&server.addr.to_string())
		})
		.collect();
	let domains: Vec<String> = dns
		.domains
		.iter()
		.map(|domain| {
			let prefix = if domain.exclusive { "~" } else { "" };
			quote(&format!("{prefix}{}", domain.suffix))
		})
		.collect();

	let mode = match &dns.mode {
		DnsMode::None => Some("none"),
		DnsMode::WriteResolvConf => Some("write_resolv_conf"),
		DnsMode::Resolvconf => Some("resolvconf"),
		DnsMode::Openresolv => Some("openresolv"),
		DnsMode::Resolved => Some("resolved"),
		DnsMode::Dnsmasq => Some("dnsmasq"),
		DnsMode::Unbound => Some("unbound"),
		DnsMode::Exec(_) => {
			missing.push(format!("{whose}: dns mode exec"));
			None
		}
	};

	let default = DnsPolicy::default();
	let mode_differs = dns.mode != default.mode;
	if servers.is_empty() && dns.search.is_empty() && domains.is_empty() && !mode_differs {
		return;
	}
	let _ = writeln!(body, "{indent}dns {{");
	if let Some(mode) = mode {
		if mode_differs {
			let _ = writeln!(body, "{indent}\tmode = {}", quote(mode));
		}
	}
	if !servers.is_empty() {
		let _ = writeln!(body, "{indent}\tservers = [{}]", servers.join(", "));
	}
	if !dns.search.is_empty() {
		let list: Vec<String> = dns.search.iter().map(|name| quote(name)).collect();
		let _ = writeln!(body, "{indent}\tsearch = [{}]", list.join(", "));
	}
	if !domains.is_empty() {
		let _ = writeln!(body, "{indent}\tdomains = [{}]", domains.join(", "));
	}
	let _ = writeln!(body, "{indent}}}");
}

fn render_interface(
	interface: &Interface,
	overrides: &Overrides,
	text: &mut String,
	missing: &mut Unrenderable,
) {
	let name = &interface.name;
	let mut body = String::new();

	match &interface.kind {
		InterfaceKind::Physical => {}
		InterfaceKind::Dummy => body.push_str("\tkind = \"dummy\"\n"),
		other => missing.push(format!("interface {name}: kind {}", kind_name(other))),
	}

	// Every one of these has a block or a key of its own that this does not
	// write yet. Named so the operator knows what to keep by hand.
	for (present, what) in [
		(!interface.hooks.is_empty(), "hooks"),
		(interface.dot1x.is_some(), "dot1x"),
		(interface.advertise.is_some(), "advertise"),
		(interface.nat.is_some(), "nat"),
		(interface.qdisc.is_some(), "qdisc"),
		(interface.ingress_redirect.is_some(), "ingress_redirect"),
		(interface.guard.is_some(), "guard"),
		(interface.ipv6_token.is_some(), "ipv6_token"),
		(interface.link_settings.is_some(), "ethtool settings"),
		(interface.preference.is_some(), "preference"),
		(interface.probe.is_some(), "probe"),
	] {
		if present {
			missing.push(format!("interface {name}: {what}"));
		}
	}

	if !interface.enabled {
		body.push_str("\tenabled = false\n");
	}
	if let Some(mtu) = interface.mtu {
		let _ = writeln!(body, "\tmtu = {mtu}");
	}
	if let Some(mac) = &interface.mac {
		let _ = writeln!(body, "\tmac = {}", quote(mac));
	}
	if let Some(master) = &interface.master {
		let _ = writeln!(body, "\tmaster = {}", quote(master));
	}
	if let Some(forwarding) = interface.forwarding {
		let _ = writeln!(body, "\tforwarding = {forwarding}");
	}
	if let Some(policy) = interface.on_drift {
		let _ = writeln!(body, "\ton_drift = {}", quote(drift_name(policy)));
	}

	let config: Vec<String> = interface
		.addressing
		.iter()
		.filter_map(|source| match source {
			AddressSource::Static(address) => {
				if address.peer.is_some()
					|| address.preferred_lifetime.is_some()
					|| address.valid_lifetime.is_some()
				{
					missing.push(format!(
						"interface {name}: an address with lifetimes or a peer"
					));
				}
				Some(quote(&address.address))
			}
			AddressSource::Dhcp4(_) => Some(quote("dhcp")),
			AddressSource::Dhcp6(_) => Some(quote("dhcp6")),
			AddressSource::Slaac(_) => Some(quote("slaac")),
			AddressSource::LinkLocal => Some(quote("link_local")),
			other => {
				missing.push(format!(
					"interface {name}: {} addressing",
					other.kind_name()
				));
				None
			}
		})
		.collect();
	if !config.is_empty() {
		let _ = writeln!(body, "\tconfig = {}", list_or_scalar(&config));
	}

	let routes: Vec<String> = interface
		.routes
		.iter()
		.map(|route| {
			let mut phrase = route.destination.clone();
			if let Some(via) = route.via {
				let _ = write!(phrase, " via {via}");
			}
			if let Some(metric) = route.metric {
				let _ = write!(phrase, " metric {metric}");
			}
			if let Some(table) = route.table {
				let _ = write!(phrase, " table {table}");
			}
			quote(&phrase)
		})
		.collect();
	if !routes.is_empty() {
		let _ = writeln!(body, "\troutes = {}", list_or_scalar(&routes));
	}

	if let Some(dns) = &interface.dns {
		render_dns(dns, "\t", &mut body, missing, &format!("interface {name}"));
	}

	let head = opening("interface", name, overrides);
	let _ = write!(text, "\n{head} {name} {{\n{body}}}\n");
}

fn render_network(
	network: &WifiNetwork,
	overrides: &Overrides,
	text: &mut String,
	missing: &mut Unrenderable,
) {
	let id = &network.id;
	let mut body = String::new();

	if let Some(ssid) = &network.ssid {
		if ssid.as_bytes() != id.as_bytes() {
			let _ = writeln!(body, "\tssid = {}", quote(&ssid.to_hex()));
		}
	}
	if network.hidden {
		body.push_str("\thidden = true\n");
	}
	if network.metered {
		body.push_str("\tmetered = true\n");
	}

	body.push_str("\twifi {\n");
	match &network.security {
		Security::Open => body.push_str("\t\topen = true\n"),
		Security::Owe => body.push_str("\t\towe = true\n"),
		Security::Psk(psk) => {
			let _ = writeln!(body, "\t\tpsk = {}", quote(&secret_ref(&psk.passphrase)));
		}
		Security::Eap(_) => missing.push(format!("network {id}: eap")),
	}
	if network.priority != 0 {
		let _ = writeln!(body, "\t\tpriority = {}", network.priority);
	}
	if !network.autoconnect {
		body.push_str("\t\tautoconnect = false\n");
	}
	body.push_str("\t}\n");

	let head = opening("network", id, overrides);
	let _ = write!(text, "\n{head} {} {{\n{body}}}\n", quote(id));
}

fn render_device(
	device: &Device,
	overrides: &Overrides,
	text: &mut String,
	missing: &mut Unrenderable,
) {
	let name = &device.name;
	if device.r#match.is_some() {
		missing.push(format!("device {name}: a match block"));
	}
	if device.wifi.is_some() {
		missing.push(format!("device {name}: a wifi policy"));
	}

	let mut body = String::new();
	if !device.managed {
		body.push_str("\tmanaged = false\n");
	}
	if body.is_empty() {
		return;
	}
	let head = opening("device", name, overrides);
	let _ = write!(text, "\n{head} {name} {{\n{body}}}\n");
}

/// One value bare, several as a list.
///
/// Both are legal and the compiler reads either. A single-element list is
/// noise in a file somebody has to read.
fn list_or_scalar(values: &[String]) -> String {
	if let [only] = values {
		only.clone()
	} else {
		format!("[{}]", values.join(", "))
	}
}

fn drift_name(policy: DriftPolicy) -> &'static str {
	match policy {
		DriftPolicy::Report => "report",
		DriftPolicy::Reconcile => "reconcile",
		DriftPolicy::Ignore => "ignore",
	}
}

fn principal_name(principal: &Principal) -> String {
	match principal {
		Principal::Root => "root".to_owned(),
		Principal::Any => "any".to_owned(),
		Principal::User(name) => format!("user:{name}"),
		Principal::Group(name) => format!("group:{name}"),
	}
}

fn kind_name(kind: &InterfaceKind) -> &'static str {
	match kind {
		InterfaceKind::Physical => "physical",
		InterfaceKind::Dummy => "dummy",
		InterfaceKind::Bridge(_) => "bridge",
		InterfaceKind::Bond(_) => "bond",
		InterfaceKind::Vlan(_) => "vlan",
		InterfaceKind::Vxlan(_) => "vxlan",
		InterfaceKind::WireGuard(_) => "wireguard",
		InterfaceKind::Pppoe(_) => "pppoe",
		InterfaceKind::OpenVpn(_) => "openvpn",
		InterfaceKind::Veth(_) => "veth",
		InterfaceKind::Vrf(_) => "vrf",
		InterfaceKind::Macvlan(_) => "macvlan",
		InterfaceKind::Tunnel(_) => "tunnel",
		InterfaceKind::Tun(_) => "tun",
		InterfaceKind::Ifb => "ifb",
	}
}

/// A credential as the document refers to it -- never as its value.
///
/// The provider is written only when it is not the default, which is what
/// keeps an ordinary `psk` reading as `@secret:home-wifi` rather than as
/// something with machinery in it.
fn secret_ref(reference: &SecretRef) -> String {
	match reference.provider {
		SecretProvider::File => format!("@secret:{}", reference.name),
		SecretProvider::Keyring => format!("@secret:keyring:{}", reference.name),
		SecretProvider::Pass => format!("@secret:pass:{}", reference.name),
		SecretProvider::Exec => format!("@secret:exec:{}", reference.name),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::diag::SourceMap;

	/// Compile one file of configuration.
	fn compile(text: &str) -> netcfgd_model::Document {
		let mut sources = SourceMap::new();
		sources.add("test.conf", text);
		match crate::compile(&sources, &mut crate::NoHooks) {
			Ok(document) => document,
			Err(diagnostics) => panic!("{}", diagnostics.render(&sources)),
		}
	}

	/// The gate this module exists behind: render, read it back, and the
	/// document must be the same one.
	///
	/// Written as text in and text out rather than by building model values by
	/// hand, because it then also proves the renderer against what the parser
	/// actually accepts -- a rendering the compiler rejects fails here loudly
	/// instead of at somebody's next `ncfg apply`.
	fn round_trips(text: &str) {
		let before = compile(text);
		let rendered = match render(&before, &Overrides::new()) {
			Ok(rendered) => rendered,
			Err(missing) => panic!("cannot render: {}", missing.join("; ")),
		};
		let after = compile(&rendered);
		assert_eq!(before, after, "rendered as:\n{rendered}");
	}

	#[test]
	fn a_dhcp_interface_round_trips() {
		round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	}

	#[test]
	fn an_address_and_its_routes_round_trip() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = [\"192.0.2.10/24\", \"2001:db8::10/64\"]\n\
			 \troutes = [\"default via 192.0.2.1\", \"default via 2001:db8::1\"]\n\
			 \tmtu = 9000\n\
			 }\n",
		);
	}

	#[test]
	fn a_route_with_a_metric_and_a_table_round_trips() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
			 \troutes = \"10.0.0.0/8 via 192.0.2.1 metric 300 table 42\"\n\
			 }\n",
		);
	}

	#[test]
	fn the_globals_round_trip() {
		round_trips(
			"global {\n\
			 \thostname = \"host.example\"\n\
			 \tconfirm = 90\n\
			 \ton_drift = \"reconcile\"\n\
			 \tdns {\n\
			 \t\tmode = \"resolved\"\n\
			 \t\tservers = [\"192.0.2.53\", \"2001:db8::53\"]\n\
			 \t\tsearch = [\"example.invalid\"]\n\
			 \t}\n\
			 \tcontrol {\n\
			 \t\tobserve = \"any\"\n\
			 \t\twifi = \"group:netdev\"\n\
			 \t\tadmin = \"root\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// The off switch survives a save. A profile that turns networking off is
	/// exactly the profile somebody most needs to come back unchanged.
	#[test]
	fn networking_off_round_trips() {
		round_trips(
			"global {\n\tnetworking = \"off\"\n}\ninterface eth0 {\n\tconfig = \"dhcp\"\n}\n",
		);
	}

	#[test]
	fn a_wifi_network_round_trips() {
		round_trips(
			"network \"Cafe\" {\n\
			 \twifi {\n\
			 \t\tpsk = \"@secret:cafe\"\n\
			 \t\tpriority = 5\n\
			 \t}\n\
			 }\n\
			 network \"Open Hotspot\" {\n\
			 \thidden = true\n\
			 \tmetered = true\n\
			 \twifi {\n\
			 \t\topen = true\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A name that is not a bare word, and one with a quote in it. The escape
	/// is what stops a rendered profile from ending a string early and taking
	/// every other block in the file with it.
	#[test]
	fn a_name_needing_escapes_round_trips() {
		round_trips(
			"network \"say \\\"hello\\\"\" {\n\
			 \twifi {\n\
			 \t\topen = true\n\
			 \t}\n\
			 }\n",
		);
	}

	/// The refusal, which is the other half of the contract. A wireguard
	/// interface has no rendering here, and saying so by name is the whole
	/// difference between a partial renderer and a lossy one.
	#[test]
	fn what_cannot_be_rendered_is_named() {
		let document = compile(
			"interface wg0 {\n\
			 \twireguard {\n\
			 \t\tprivate_key = \"@secret:wg\"\n\
			 \t}\n\
			 \tconfig = \"10.0.0.2/32\"\n\
			 }\n",
		);
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing.iter().any(|what| what.contains("wireguard")),
			"{missing:?}"
		);
	}

	/// A block the base defines is written as `override`, and one it does not
	/// is not -- `override` with nothing to override is a compile error, so
	/// getting this wrong makes a profile that cannot load.
	#[test]
	fn override_is_written_only_where_the_caller_says() {
		let document = compile("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
		let plain = render(&document, &Overrides::new()).expect("renders");
		assert!(plain.contains("\ninterface eth0 {"), "{plain}");

		let mut overrides = Overrides::new();
		overrides.insert("interface eth0".to_owned());
		let overridden = render(&document, &overrides).expect("renders");
		assert!(
			overridden.contains("\noverride interface eth0 {"),
			"{overridden}"
		);
	}
}
