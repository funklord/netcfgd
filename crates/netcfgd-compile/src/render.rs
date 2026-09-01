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
use netcfgd_model::interface::{BridgeVlan, InterfaceKind, ProbePolicy};
use netcfgd_model::secret::{SecretProvider, SecretRef};
use netcfgd_model::security::{CertSource, EapConfig, EapMethod, Security};
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
		render_network(network, overrides, &mut text);
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

	render_kind(&interface.kind, name, &mut body, missing);

	// Every one of these has a block or a key of its own that this does not
	// write yet. Named so the operator knows what to keep by hand.
	//
	// `ingress_redirect` is here and cannot leave: it is not a config key at
	// all. The compiler synthesises it, and the `ifb` device it points at,
	// from `ingress_bandwidth` -- so rendering it would make the next compile
	// synthesise a *second* one on top. What a snapshot would have to write
	// back is the `ingress_bandwidth` it came from, which the document no
	// longer holds by the time this sees it.
	for (present, what) in [
		(!interface.hooks.is_empty(), "hooks"),
		(interface.advertise.is_some(), "advertise"),
		(interface.qdisc.is_some(), "qdisc"),
		(interface.ingress_redirect.is_some(), "ingress_redirect"),
		(interface.guard.is_some(), "guard"),
		(interface.link_settings.is_some(), "ethtool settings"),
	] {
		if present {
			missing.push(format!("interface {name}: {what}"));
		}
	}

	render_interface_keys(interface, &mut body);

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

	render_bridge_vlans(&interface.bridge_vlans, &mut body);

	if let Some(dns) = &interface.dns {
		render_dns(dns, "\t", &mut body, missing, &format!("interface {name}"));
	}

	let head = opening("interface", name, overrides);
	let _ = write!(text, "\n{head} {name} {{\n{body}}}\n");
}

/// What kind of link this is, as its own block.
///
/// The topology kinds are here and the tunnels are not yet. They are separated
/// by what they carry rather than by effort: a bridge, a bond, a VLAN and a
/// macvlan say who they are made of and nothing secret, while `wireguard` has
/// peers and a private key and `openvpn` names an operator's file, so those
/// need decisions about what a snapshot is allowed to contain rather than more
/// keys.
///
/// A default is written only where the parser's default differs, so a bond
/// that never named a mode does not acquire one -- the round trip compares
/// documents, and a written default is equal to an absent one, but a person
/// reading the profile afterwards cannot tell what was chosen from what was
/// merely true.
fn render_kind(kind: &InterfaceKind, name: &str, body: &mut String, missing: &mut Unrenderable) {
	match kind {
		InterfaceKind::Physical => {}
		InterfaceKind::Dummy => body.push_str("\tkind = \"dummy\"\n"),
		InterfaceKind::Bridge(bridge) => {
			body.push_str("\tbridge {\n");
			if !bridge.members.is_empty() {
				let members: Vec<String> = bridge.members.iter().map(|m| quote(m)).collect();
				let _ = writeln!(body, "\t\tmembers = {}", list_or_scalar(&members));
			}
			if bridge.stp {
				body.push_str("\t\tstp = true\n");
			}
			for (value, key) in [
				(bridge.forward_delay, "forward_delay"),
				(bridge.hello_time, "hello_time"),
				(bridge.ageing_time, "ageing_time"),
			] {
				if let Some(value) = value {
					let _ = writeln!(body, "\t\t{key} = {value}");
				}
			}
			if let Some(priority) = bridge.priority {
				let _ = writeln!(body, "\t\tpriority = {priority}");
			}
			if bridge.vlan_filtering {
				body.push_str("\t\tvlan_filtering = true\n");
			}
			body.push_str("\t}\n");
		}
		InterfaceKind::Bond(bond) => {
			body.push_str("\tbond {\n");
			if !bond.members.is_empty() {
				let members: Vec<String> = bond.members.iter().map(|m| quote(m)).collect();
				let _ = writeln!(body, "\t\tmembers = {}", list_or_scalar(&members));
			}
			// Always, unlike every other default here: the *parser* requires a
			// mode even though the model has one, so a bond whose mode happens
			// to equal `BondMode::default()` would render as a block that no
			// longer compiles. A model default and a language default are not
			// the same fact, and this is the one place they differ.
			let _ = writeln!(body, "\t\tmode = {}", quote(bond.mode.name()));
			if let Some(miimon) = bond.miimon {
				let _ = writeln!(body, "\t\tmiimon = {miimon}");
			}
			body.push_str("\t}\n");
		}
		InterfaceKind::Vlan(vlan) => {
			body.push_str("\tvlan {\n");
			let _ = writeln!(body, "\t\tparent = {}", quote(&vlan.parent));
			let _ = writeln!(body, "\t\tid = {}", vlan.id);
			if vlan.protocol != netcfgd_model::interface::VlanProtocol::default() {
				let _ = writeln!(body, "\t\tprotocol = {}", quote(vlan.protocol.name()));
			}
			body.push_str("\t}\n");
		}
		InterfaceKind::Vxlan(vxlan) => {
			body.push_str("\tvxlan {\n");
			let _ = writeln!(body, "\t\tid = {}", vxlan.id);
			if let Some(parent) = &vxlan.parent {
				let _ = writeln!(body, "\t\tparent = {}", quote(parent));
			}
			for (address, key) in [(vxlan.local, "local"), (vxlan.remote, "remote")] {
				if let Some(address) = address {
					let _ = writeln!(body, "\t\t{key} = {}", quote(&address.to_string()));
				}
			}
			if let Some(port) = vxlan.port {
				let _ = writeln!(body, "\t\tport = {port}");
			}
			body.push_str("\t}\n");
		}
		InterfaceKind::Macvlan(macvlan) => {
			body.push_str("\tmacvlan {\n");
			let _ = writeln!(body, "\t\tparent = {}", quote(&macvlan.parent));
			if macvlan.mode != netcfgd_model::interface::MacvlanMode::default() {
				let _ = writeln!(body, "\t\tmode = {}", quote(macvlan.mode.name()));
			}
			body.push_str("\t}\n");
		}
		InterfaceKind::Vrf(vrf) => {
			let _ = writeln!(body, "\tvrf {{ table = {} }}", vrf.table);
		}
		InterfaceKind::Veth(veth) => {
			let _ = writeln!(body, "\tveth {{ peer = {} }}", quote(&veth.peer));
		}
		other => missing.push(format!("interface {name}: kind {}", kind_name(other))),
	}
}

/// The interface keys that are neither addressing nor topology.
///
/// Grouped into a function because `render_interface` has a line limit, which
/// is the same reason its siblings are functions -- not because these belong
/// together as an idea.
fn render_interface_keys(interface: &Interface, body: &mut String) {
	if let Some(preference) = interface.preference {
		let _ = writeln!(body, "\tpreference = {preference}");
	}
	if let Some(token) = &interface.ipv6_token {
		let _ = writeln!(body, "\tipv6_token = {}", quote(token));
	}
	if let Some(nat) = interface.nat {
		let _ = writeln!(body, "\tnat = {nat}");
	}
	if let Some(dot1x) = &interface.dot1x {
		// The same eight keys a wireless network's EAP uses, which is why
		// `lower_dot1x_key` shares `WifiKeys` with the wifi parser -- so this
		// shares the renderer for the same reason, and the two cannot drift
		// into spelling one thing two ways. The nesting depth is the same as a
		// network's `wifi` block, so render_eap's indentation is already right.
		body.push_str("\tdot1x {\n");
		render_eap(dot1x, body);
		body.push_str("\t}\n");
	}
	if let Some(probe) = &interface.probe {
		render_probe(probe, body);
	}
}

/// How the link is judged to be working, as its own block.
///
/// The numbers are omitted where they equal the parser's own defaults, which
/// is this file's convention rather than a claim that they do not matter --
/// see the note on that convention against the header's wording.
///
/// `command` is unconditional because a probe without one is not a probe: the
/// parser refuses the block outright, so a rendered profile that left it out
/// would be one that no longer compiles.
fn render_probe(probe: &ProbePolicy, body: &mut String) {
	body.push_str("\tprobe {\n");
	let _ = writeln!(body, "\t\tcommand = {}", quote(&probe.command));
	if !probe.args.is_empty() {
		let args: Vec<String> = probe.args.iter().map(|arg| quote(arg)).collect();
		let _ = writeln!(body, "\t\targs = {}", list_or_scalar(&args));
	}
	for (value, default, key) in [
		(probe.interval, 30, "interval"),
		(probe.timeout, 5, "timeout"),
		(
			probe.down_after,
			ProbePolicy::default_down_after(),
			"down_after",
		),
		(probe.up_after, ProbePolicy::default_up_after(), "up_after"),
		(probe.hold_down, 0, "hold_down"),
	] {
		if value != default {
			let _ = writeln!(body, "\t\t{key} = {value}");
		}
	}
	body.push_str("\t}\n");
}

/// A port's VLAN membership, as the phrases the parser reads back.
///
/// One phrase per VLAN rather than the ranges the parser also accepts: a range
/// is expanded on the way in, so the individual ids are all this has to write.
/// The round trip compares documents rather than text, so re-compacting them
/// would be work nothing checks.
///
/// A function of its own because `render_interface` is at its line limit, and
/// because this is the field that was being dropped in silence -- it is easier
/// to notice missing when it has a name.
fn render_bridge_vlans(vlans: &[BridgeVlan], body: &mut String) {
	let phrases: Vec<String> = vlans
		.iter()
		.map(|vlan| {
			let mut phrase = vlan.vid.to_string();
			if vlan.pvid {
				phrase.push_str(" pvid");
			}
			// `tagged` is the absence of `untagged` and the parser's default,
			// so writing it would be noise that reads as a setting.
			if vlan.untagged {
				phrase.push_str(" untagged");
			}
			quote(&phrase)
		})
		.collect();
	if !phrases.is_empty() {
		let _ = writeln!(body, "\tvlans = {}", list_or_scalar(&phrases));
	}
}

fn render_network(network: &WifiNetwork, overrides: &Overrides, text: &mut String) {
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
		Security::Eap(eap) => render_eap(eap, &mut body),
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

/// The keys of an 802.1X network, inside an open `wifi` block.
///
/// Every value is quoted rather than written bare. An identity is
/// `you@example.ac.uk` and a certificate is a path, and neither is guaranteed
/// to be a word the lexer reads back as itself.
///
/// `identity` is unconditional because the model requires it -- a `String` and
/// not an `Option`, since no method authenticates without one. The rest are
/// written only when set, so a PEAP network does not acquire empty `ca_cert`
/// and `client_cert` lines that say nothing and invite an answer.
fn render_eap(eap: &EapConfig, body: &mut String) {
	let _ = writeln!(body, "\t\teap = {}", quote(eap_method_name(eap.method)));
	let _ = writeln!(body, "\t\tidentity = {}", quote(&eap.identity));
	if let Some(anonymous) = &eap.anonymous_identity {
		let _ = writeln!(body, "\t\tanonymous_identity = {}", quote(anonymous));
	}
	if let Some(password) = &eap.password {
		let _ = writeln!(body, "\t\tpassword = {}", quote(&secret_ref(password)));
	}
	for (source, key) in [
		(&eap.ca_cert, "ca_cert"),
		(&eap.client_cert, "client_cert"),
		(&eap.private_key, "private_key"),
	] {
		if let Some(source) = source {
			let _ = writeln!(body, "\t\t{key} = {}", quote(&cert_source(source)));
		}
	}
	if let Some(phase2) = &eap.phase2 {
		let _ = writeln!(body, "\t\tphase2 = {}", quote(phase2));
	}
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

fn eap_method_name(method: EapMethod) -> &'static str {
	match method {
		EapMethod::Peap => "peap",
		EapMethod::Ttls => "ttls",
		EapMethod::Tls => "tls",
		EapMethod::Pwd => "pwd",
	}
}

/// A certificate or key as the document names it.
///
/// The two sources read back differently and the parser tells them apart by
/// the `@secret:` prefix alone (`as_cert_source`), so a stored one must go
/// through [`secret_ref`] and a path must not: a path that happened to begin
/// with `@secret:` would come back as stored content, and stored content
/// written bare would come back as a filename that does not exist.
fn cert_source(source: &CertSource) -> String {
	match source {
		CertSource::Path(path) => path.clone(),
		CertSource::Stored(reference) => secret_ref(reference),
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

	/// The per-interface keys a laptop's profile is actually about.
	///
	/// `preference` is which uplink wins and `probe` is how the link is judged
	/// to be working -- the two settings whose whole purpose is to differ
	/// between the office and home, and so the two a profile most needs to be
	/// able to save. Both were refused.
	#[test]
	fn the_interface_keys_round_trip() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tpreference = 100\n\
			 \tnat = true\n\
			 \tipv6_token = \"::5\"\n\
			 \tprobe {\n\
			 \t\tcommand = \"/usr/bin/ping\"\n\
			 \t\targs = [\"-c\", \"1\", \"-I\", \"eth0\", \"198.51.100.1\"]\n\
			 \t\tinterval = 15\n\
			 \t\ttimeout = 3\n\
			 \t\tdown_after = 5\n\
			 \t\tup_after = 3\n\
			 \t\thold_down = 60\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A probe with nothing but its command, so the defaults stay unwritten
	/// and the block still compiles.
	#[test]
	fn a_bare_probe_round_trips() {
		round_trips(
			"interface eth1 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tprobe { command = \"/usr/bin/true\" }\n\
			 }\n",
		);
	}

	/// 802.1X on a wired port, which shares its eight keys with a wireless
	/// network's EAP -- the parser shares `WifiKeys` between them, so the
	/// renderer shares `render_eap` for the same reason.
	#[test]
	fn a_wired_dot1x_port_round_trips() {
		round_trips(
			"interface eth2 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tdot1x {\n\
			 \t\teap = \"tls\"\n\
			 \t\tidentity = \"desk.corp\"\n\
			 \t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n\
			 \t\tclient_cert = \"/etc/ssl/certs/desk.pem\"\n\
			 \t\tprivate_key = \"@secret:desk-key\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// The topology kinds, each with every key it has set.
	///
	/// One document rather than one per kind, because the thing most likely to
	/// go wrong is a block written at the wrong nesting or without its closing
	/// brace, and that breaks the *next* block rather than its own.
	#[test]
	fn the_link_kinds_round_trip() {
		round_trips(
			"interface br0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
			 \tbridge {\n\
			 \t\tmembers = [\"eth0\", \"eth1\"]\n\
			 \t\tstp = true\n\
			 \t\tforward_delay = 4\n\
			 \t\thello_time = 2\n\
			 \t\tageing_time = 300\n\
			 \t\tpriority = 4096\n\
			 \t\tvlan_filtering = true\n\
			 \t}\n\
			 }\n\
			 interface bond0 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tbond {\n\
			 \t\tmembers = [\"eth2\", \"eth3\"]\n\
			 \t\tmode = \"802.3ad\"\n\
			 \t\tmiimon = 100\n\
			 \t}\n\
			 }\n\
			 interface vlan10 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tvlan {\n\
			 \t\tparent = \"eth0\"\n\
			 \t\tid = 10\n\
			 \t\tprotocol = \"dot1ad\"\n\
			 \t}\n\
			 }\n\
			 interface vx0 {\n\
			 \tconfig = \"10.20.0.1/24\"\n\
			 \tvxlan {\n\
			 \t\tid = 100\n\
			 \t\tparent = \"eth0\"\n\
			 \t\tlocal = \"192.0.2.10\"\n\
			 \t\tremote = \"198.51.100.10\"\n\
			 \t\tport = 4789\n\
			 \t}\n\
			 }\n\
			 interface mv0 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tmacvlan {\n\
			 \t\tparent = \"eth0\"\n\
			 \t\tmode = \"bridge\"\n\
			 \t}\n\
			 }\n\
			 interface mgmt {\n\
			 \tconfig = \"192.0.2.11/24\"\n\
			 \tvrf { table = 100 }\n\
			 }\n",
		);
	}

	/// The same kinds with every optional key absent, which is the case a
	/// renderer gets wrong in the other direction: writing a default back as
	/// though somebody had chosen it.
	#[test]
	fn the_link_kinds_round_trip_bare() {
		round_trips(
			"interface br1 {\n\
			 \tconfig = \"null\"\n\
			 \tbridge { members = \"eth4\" }\n\
			 }\n\
			 interface bond1 {\n\
			 \tconfig = \"null\"\n\
			 \tbond { members = \"eth5\"; mode = \"active-backup\" }\n\
			 }\n\
			 interface vlan20 {\n\
			 \tconfig = \"null\"\n\
			 \tvlan { parent = \"eth0\"; id = 20 }\n\
			 }\n\
			 interface mv1 {\n\
			 \tconfig = \"null\"\n\
			 \tmacvlan { parent = \"eth0\" }\n\
			 }\n",
		);
	}

	/// Per-port VLAN membership, which was being dropped in silence.
	///
	/// It was neither rendered nor refused, so `ncfg profile save` wrote a
	/// switch port's configuration back without its VLANs and reported
	/// success. That is the one failure the renderer's header rules out, and
	/// nothing caught it because no round trip had ever carried a `vlans` key.
	/// The consequence is not cosmetic: a port whose PVID is lost takes
	/// untagged ingress to a different VLAN than before.
	#[test]
	fn per_port_vlans_round_trip() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
			 \tvlans = [\"10 pvid untagged\", \"20\", \"30 untagged\"]\n\
			 }\n",
		);
	}

	/// The tunnelled methods, with everything optional set.
	///
	/// Written as text rather than as model values, so it proves the renderer
	/// against what the parser actually accepts rather than against what this
	/// file believes it accepts.
	#[test]
	fn an_enterprise_network_round_trips() {
		round_trips(
			"network \"Campus\" {\n\
			 \twifi {\n\
			 \t\teap = \"peap\"\n\
			 \t\tidentity = \"someone@example.ac.uk\"\n\
			 \t\tanonymous_identity = \"anonymous@example.ac.uk\"\n\
			 \t\tpassword = \"@secret:campus\"\n\
			 \t\tca_cert = \"/etc/ssl/certs/campus.pem\"\n\
			 \t\tphase2 = \"mschapv2\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// EAP-TLS, which presents a certificate instead of a password.
	#[test]
	fn a_certificate_network_round_trips() {
		round_trips(
			"network \"Corp\" {\n\
			 \twifi {\n\
			 \t\teap = \"tls\"\n\
			 \t\tidentity = \"laptop.corp\"\n\
			 \t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n\
			 \t\tclient_cert = \"/etc/ssl/certs/laptop.pem\"\n\
			 \t\tprivate_key = \"@secret:laptop-key\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A stored certificate and a path are told apart by the `@secret:` prefix
	/// alone, so rendering one as the other is a silent corruption rather than
	/// a compile error: `private_key` here is content netcfgd holds, and
	/// `ca_cert` is a file already on the machine. The round trip is what
	/// catches a renderer that writes stored content as a bare filename.
	#[test]
	fn a_stored_certificate_stays_stored() {
		round_trips(
			"network \"Corp\" {\n\
			 \twifi {\n\
			 \t\teap = \"tls\"\n\
			 \t\tidentity = \"laptop.corp\"\n\
			 \t\tca_cert = \"/etc/ssl/certs/corp.pem\"\n\
			 \t\tprivate_key = \"@secret:laptop-key\"\n\
			 \t}\n\
			 }\n",
		);
		let document = compile(
			"network \"Corp\" {\n\
			 \twifi {\n\
			 \t\teap = \"tls\"\n\
			 \t\tidentity = \"laptop.corp\"\n\
			 \t\tprivate_key = \"@secret:laptop-key\"\n\
			 \t}\n\
			 }\n",
		);
		let rendered = render(&document, &Overrides::new()).expect("rendered");
		assert!(
			rendered.contains("private_key = \"@secret:laptop-key\""),
			"{rendered}"
		);
	}

	/// EAP-PWD, which is the one method carrying neither a certificate nor a
	/// phase 2, so it proves the optional keys are genuinely optional rather
	/// than written empty.
	#[test]
	fn a_password_only_network_round_trips() {
		round_trips(
			"network \"Pwd\" {\n\
			 \twifi {\n\
			 \t\teap = \"pwd\"\n\
			 \t\tidentity = \"someone\"\n\
			 \t\tpassword = \"@secret:pwd\"\n\
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
