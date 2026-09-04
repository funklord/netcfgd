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
use netcfgd_model::device::OnUnmanage;
use netcfgd_model::dns::{DnsMode, DnsPolicy};
use netcfgd_model::interface::{BridgeVlan, InterfaceKind, ProbePolicy};
use netcfgd_model::secret::{SecretProvider, SecretRef};
use netcfgd_model::security::{CertSource, EapConfig, EapMethod, Security};
use netcfgd_model::wifi::WifiNetwork;
use netcfgd_model::{
	AddressSource, Device, Document, DriftPolicy, HostnamePolicy, Interface, Route,
};
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
	for device in &document.bluetooth {
		render_bluetooth(device, overrides, &mut text);
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
	let _ = render_dns(&globals.dns, "\t", &mut body, missing, "global");

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
) -> bool {
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
		return false;
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
	true
}

fn render_interface(
	interface: &Interface,
	overrides: &Overrides,
	text: &mut String,
	missing: &mut Unrenderable,
) {
	let name = &interface.name;
	let mut body = String::new();

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
		(interface.guard.is_some(), "guard"),
	] {
		if present {
			missing.push(format!("interface {name}: {what}"));
		}
	}

	render_interface_keys(interface, &mut body);

	if !interface.enabled {
		body.push_str("\tenabled = false\n");
	}
	if let Some(forwarding) = interface.forwarding {
		let _ = writeln!(body, "\tforwarding = {forwarding}");
	}
	if let Some(policy) = interface.on_drift {
		let _ = writeln!(body, "\ton_drift = {}", quote(drift_name(policy)));
	}

	let whose = &format!("interface {name}");
	render_addressing(&interface.addressing, whose, &mut body, missing);
	render_routes(&interface.routes, whose, &mut body, missing);

	if let Some(dns) = &interface.dns {
		// **An empty `dns { }` is not nothing, and dropping it changed what
		// the interface does.** On an interface it means "use the nameservers
		// this network hands out" -- 0007 makes a per-interface policy a scope
		// in its own right rather than an overlay -- so the difference between
		// the block being absent and being empty is the difference between
		// ignoring a lease's resolvers and taking them. `render_dns` writes
		// nothing when every field is at its default, which is right for
		// `global`, where the block carries no meaning of its own.
		if !render_dns(dns, "\t", &mut body, missing, &format!("interface {name}")) {
			body.push_str("\tdns { }\n");
		}
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

/// Addressing, shared by an interface and by a wireless network.
///
/// A `network` block takes the same `config` key an interface does, so this is
/// one function rather than two: the network side was rendering nothing at
/// all, and writing a second copy is how the two would come to disagree about
/// what `slaac` spells.
fn render_addressing(
	sources: &[AddressSource],
	whose: &str,
	body: &mut String,
	missing: &mut Unrenderable,
) {
	let config: Vec<String> = sources
		.iter()
		.filter_map(|source| match source {
			AddressSource::Static(address) => {
				if address.peer.is_some()
					|| address.preferred_lifetime.is_some()
					|| address.valid_lifetime.is_some()
				{
					missing.push(format!("{whose}: an address with lifetimes or a peer"));
				}
				Some(quote(&address.address))
			}
			AddressSource::Dhcp4(_) => Some(quote("dhcp")),
			AddressSource::Dhcp6(_) => Some(quote("dhcp6")),
			AddressSource::Slaac(_) => Some(quote("slaac")),
			AddressSource::LinkLocal => Some(quote("link_local")),
			other => {
				missing.push(format!("{whose}: {} addressing", other.kind_name()));
				None
			}
		})
		.collect();
	if !config.is_empty() {
		let _ = writeln!(body, "\tconfig = {}", list_or_scalar(&config));
	}
}

/// Routes, shared by an interface and by a wireless network, for the reason
/// [`render_addressing`] is shared.
fn render_routes(routes: &[Route], whose: &str, body: &mut String, missing: &mut Unrenderable) {
	let phrases: Vec<String> = routes
		.iter()
		.map(|route| {
			let mut phrase = route.destination.clone();
			if let Some(via) = route.via {
				let _ = write!(phrase, " via {via}");
			}
			// Was dropped in silence. A preferred source is what decides which
			// address a machine with several is seen as coming from, so losing
			// it moves traffic to a different identity rather than breaking it
			// -- which is the kind of change nothing notices until a firewall
			// somewhere else does.
			if let Some(src) = route.src {
				let _ = write!(phrase, " src {src}");
			}
			if let Some(metric) = route.metric {
				let _ = write!(phrase, " metric {metric}");
			}
			if let Some(table) = route.table {
				let _ = write!(phrase, " table {table}");
			}
			// Also dropped in silence, and it is not merely descriptive: it
			// exempts the route from the ordering rule that installs addresses
			// before routes, so a route that needs it fails to install without
			// it.
			if route.onlink {
				phrase.push_str(" onlink");
			}
			// No route phrase can express these two -- the keywords are `via`,
			// `metric`, `table`, `src` and `onlink` -- so they are named
			// rather than written. Reachable only from a document some other
			// producer built, which is exactly when a silent drop would be
			// hardest to trace.
			if route.scope.is_some() {
				missing.push(format!("{whose}: a route with a scope"));
			}
			if route.proto.is_some() {
				missing.push(format!("{whose}: a route with a proto"));
			}
			quote(&phrase)
		})
		.collect();
	if !phrases.is_empty() {
		let _ = writeln!(body, "\troutes = {}", list_or_scalar(&phrases));
	}
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
	// Network level, beside `metered`, and deliberately not inside `wifi`
	// where `priority` sits. The two are different scales: `priority` is the
	// supplicant's, higher wins, and it chooses which network in range to
	// join; `metric` is the kernel's, lower wins, and it ranks this network's
	// routes against every other link once joined. A profile keeping only one
	// would come back ranking differently from the machine it was saved on.
	if let Some(metric) = network.metric {
		let _ = writeln!(body, "\tmetric = {metric}");
	}
	// Was dropped in silence. A bssid list is how an operator pins a network
	// to the access points that are actually theirs, so losing it widens the
	// network to any radio broadcasting the same name -- which is the thing
	// the key exists to prevent.
	if !network.bssid.is_empty() {
		let pins: Vec<String> = network.bssid.iter().map(|bssid| quote(bssid)).collect();
		let _ = writeln!(body, "\tbssid = {}", list_or_scalar(&pins));
	}

	body.push_str("\twifi {\n");
	match &network.security {
		Security::Open => body.push_str("\t\topen = true\n"),
		Security::Owe => body.push_str("\t\towe = true\n"),
		Security::Psk(psk) => {
			let _ = writeln!(body, "\t\tpsk = {}", quote(&secret_ref(&psk.passphrase)));
			// **Dropped in silence until 2026-09-04, and it is the one field
			// here whose loss weakens a network rather than merely changing
			// it.** The default is WPA2 and WPA3 together, so a profile saved
			// from a `proto = "wpa3"` network came back accepting WPA2 -- a
			// downgrade an operator had deliberately excluded. `profile save`
			// refused rather than writing it, because the round-trip proof
			// caught the difference, so nothing was ever lost on disk; what
			// was lost was the ability to save such a profile at all.
			if psk.proto != netcfgd_model::security::PskProto::default() {
				let _ = writeln!(body, "\t\tproto = {}", quote(proto_name(psk.proto)));
			}
		}
		Security::Eap(eap) => render_eap(eap, &mut body),
	}
	if !network.autoconnect {
		body.push_str("\t\tautoconnect = false\n");
	}
	// Also dropped in silence, and it lives inside `wifi` rather than beside
	// it. Every value is written whenever the block exists, because the
	// parser's defaults are supplied when the block is *absent* -- a roam
	// block that rendered only its non-defaults could come back empty, and an
	// empty block is not the same document as no block at all.
	if let Some(roam) = &network.roam {
		let _ = write!(
			body,
			"\t\troam {{\n\
			 \t\t\tsignal = {}\n\
			 \t\t\tinterval = {}\n\
			 \t\t\tslow_interval = {}\n\
			 \t\t}}\n",
			roam.signal, roam.interval, roam.slow_interval
		);
	}
	body.push_str("\t}\n");

	// All four were dropped in silence. A `network` block takes the same
	// `config`, `routes` and `dns` an interface does -- that is how a machine
	// says "on this SSID, use this static address and this resolver" -- and a
	// profile that lost them would come back on DHCP against the wrong DNS.
	let whose = &format!("network {id}");
	render_addressing(&network.addressing, whose, &mut body, missing);
	render_routes(&network.routes, whose, &mut body, missing);
	if let Some(dns) = &network.dns {
		// Present and empty says the same thing here as on an interface.
		if !render_dns(dns, "\t", &mut body, missing, whose) {
			body.push_str("\tdns { }\n");
		}
	}
	// Refused rather than rendered, matching an interface's hooks: the phase
	// blocks have a shape of their own and neither side writes them yet.
	if !network.hooks.is_empty() {
		missing.push(format!("{whose}: hooks"));
	}

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

	if device.link_settings.is_some() {
		missing.push(format!("device {name}: ethtool settings"));
	}

	let mut body = String::new();
	if !device.managed {
		body.push_str("\tmanaged = false\n");
	}
	// What to create, and what it is a port of: moved here by 0155 pass 1b.
	render_kind(&device.kind, name, &mut body, missing);
	if let Some(master) = &device.master {
		let _ = writeln!(body, "\tmaster = {}", quote(master));
	}
	render_bridge_vlans(&device.bridge_vlans, &mut body);
	if device.qdisc.is_some() {
		missing.push(format!("device {name}: qdisc"));
	}
	if device.ingress_redirect.is_some() {
		missing.push(format!("device {name}: ingress_redirect"));
	}
	// Settings of the adapter, which moved here from `interface` with 0155
	// pass 1a. Rendered from the day they arrived rather than joining the list
	// of things a profile silently loses.
	if let Some(mtu) = device.mtu {
		let _ = writeln!(body, "\tmtu = {mtu}");
	}
	if let Some(mac) = &device.mac {
		let _ = writeln!(body, "\tmac = {}", quote(mac));
	}
	// Was dropped in silence, and this is the expensive one to lose. `Clear`
	// exists because walking away from a device otherwise strands credentials
	// -- a WireGuard key stays loaded in the kernel, a supplicant keeps its
	// passphrases, a running hostapd keeps its generated configuration. A
	// profile that lost it would put the machine back on `Leave`, which is the
	// default and the opposite intent, with nothing said.
	if device.on_unmanage != OnUnmanage::default() {
		body.push_str("\ton_unmanage = \"clear\"\n");
	}
	// Rendered from the day the field arrived, rather than joining the list of
	// things a profile silently loses. A cellular machine is the one most
	// likely to want a profile at all -- the APN differs per SIM and the SIM
	// order is the whole point of switching between them.
	if let Some(modem) = &device.modem {
		body.push_str("\tmodem {\n");
		if !modem.sim.is_empty() {
			let sources: Vec<String> = modem.sim.iter().map(|name| quote(name)).collect();
			let _ = writeln!(body, "\t\tsim = {}", list_or_scalar(&sources));
		}
		if let Some(apn) = &modem.apn {
			let _ = writeln!(body, "\t\tapn = {}", quote(apn));
		}
		body.push_str("\t}\n");
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

/// A PSK generation, spelled as the parser reads it back.
///
/// `wpa2+wpa3` and `wpa2wpa3` both parse; the first is written because it is
/// the one the example file and the diagnostics use.
fn proto_name(proto: netcfgd_model::security::PskProto) -> &'static str {
	match proto {
		netcfgd_model::security::PskProto::Wpa2 => "wpa2",
		netcfgd_model::security::PskProto::Wpa3 => "wpa3",
		netcfgd_model::security::PskProto::Wpa2Wpa3 => "wpa2+wpa3",
	}
}

/// One `bluetooth` block, as configuration text.
///
/// **Refused wholesale until 2026-09-04**, which meant `ncfg profile save`
/// could not save any machine that had one -- and a machine with a pair of
/// headphones written down is exactly a laptop, which is what profiles are
/// for. Four fields and a closed set of five profiles, so the refusal was
/// costing more than the rendering does.
///
/// `autoconnect` defaults to true, like a `network`'s, so only `false` is
/// written: a block that restated every default would be one nobody can read
/// for what is unusual.
fn render_bluetooth(
	device: &netcfgd_model::bluetooth::BluetoothDevice,
	overrides: &Overrides,
	text: &mut String,
) {
	let head = opening("bluetooth", &device.id, overrides);
	let _ = write!(text, "\n{head} {} {{\n", quote(&device.id));
	let _ = writeln!(text, "\taddress = {}", quote(&device.address));
	let _ = writeln!(
		text,
		"\tprofile = {}",
		quote(bluetooth_profile(device.profile))
	);
	if !device.autoconnect {
		text.push_str("\tautoconnect = false\n");
	}
	text.push_str("}\n");
}

/// A Bluetooth profile, spelled as the parser reads it back.
///
/// Hyphenated rather than `snake_case` because these are the profile names
/// `BlueZ` uses, and a foreign vocabulary is spelled the way its owner spells
/// it -- the same rule that keeps `wpa_supplicant`'s own words intact.
fn bluetooth_profile(profile: netcfgd_model::bluetooth::BluetoothProfile) -> &'static str {
	use netcfgd_model::bluetooth::BluetoothProfile;
	match profile {
		BluetoothProfile::A2dpSink => "a2dp-sink",
		BluetoothProfile::A2dpSource => "a2dp-source",
		BluetoothProfile::Hfp => "hfp",
		BluetoothProfile::Pan => "pan",
		BluetoothProfile::Nap => "nap",
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

	/// The diagnostics a file produces, for a case that must not compile.
	///
	/// Panics when it *does* compile, because a test asserting on a refusal
	/// that silently stopped happening would otherwise pass by finding no text
	/// it was looking for in an empty string.
	fn compile_errors(text: &str) -> String {
		let mut sources = SourceMap::new();
		sources.add("test.conf", text);
		match crate::compile(&sources, &mut crate::NoHooks) {
			Ok(_) => panic!("this was supposed to be refused, and compiled"),
			Err(diagnostics) => diagnostics.render(&sources),
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

	/// The adapter's settings round-trip from the device block they moved to.
	///
	/// Worth its own case because a profile save renders the whole document:
	/// a field that moved type and was not taught to the renderer would be
	/// silently dropped from every saved profile, which is the failure mode
	/// 0155 pass 1a most easily creates.
	#[test]
	fn a_devices_hardware_settings_round_trip() {
		round_trips(
			"device eth0 {\n\
			 \tmtu = 9000\n\
			 \tmac = \"02:00:00:00:00:01\"\n\
			 }\n\
			 interface eth0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n",
		);
	}

	/// The structural keys are named too, and every one of them.
	///
	/// A list rather than one case, because the message is produced by two
	/// arms -- assignments and blocks -- and a reader of either only finds out
	/// which by being told. Pass 1b moved thirteen block spellings and four
	/// keys; a test covering one arm would leave the other free to go quiet.
	#[test]
	fn structural_keys_in_an_interface_say_where_they_went() {
		for text in [
			"interface br0 { bridge { members = \"eth0\" } }\n",
			"interface bond0 { bond { members = \"eth0\" } }\n",
			"interface v10 { vlan { parent = \"eth0\"; id = 10 } }\n",
			"interface wg0 { wireguard { private_key = \"@secret:w\" } }\n",
			"interface eth0 { config = \"dhcp\"; master = \"br0\" }\n",
			"interface eth0 { config = \"dhcp\"; kind = \"dummy\" }\n",
			"interface eth0 { config = \"dhcp\"; vlans = \"10\" }\n",
			"interface eth0 { qdisc { kind = \"cake\" } }\n",
		] {
			let diagnostics = compile_errors(text);
			assert!(
				diagnostics.contains("device"),
				"the refusal must name the new home: {diagnostics}"
			);
		}
	}

	/// The retired spelling is named, not left to "unknown interface key".
	///
	/// An operator who wrote `mtu` inside `interface` had a working
	/// configuration, and the fix is to move a line rather than to delete it
	/// -- so the refusal says where it goes (0155 pass 1a).
	#[test]
	fn hardware_keys_in_an_interface_say_where_they_went() {
		for text in [
			"interface eth0 { config = \"dhcp\"; mtu = 9000 }\n",
			"interface eth0 { config = \"dhcp\"; mac = \"02:00:00:00:00:01\" }\n",
			"interface eth0 { config = \"dhcp\"; ethtool { gro = \"off\" } }\n",
		] {
			let diagnostics = compile_errors(text);
			assert!(
				diagnostics.contains("device"),
				"the refusal must name the new home: {diagnostics}"
			);
		}
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

	/// The metric belongs beside `metered` and not inside `wifi`, and a
	/// renderer that writes it in the wrong place produces a profile the parser
	/// refuses. Worth its own case because the two halves of the block are
	/// written by different functions.
	#[test]
	fn a_networks_metric_round_trips() {
		round_trips(
			"network \"Office\" {\n\
			 \tmetric = 50\n\
			 \twifi {\n\
			 \t\tpsk = \"@secret:office\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// The retired key is refused, and refused with the one thing an operator
	/// needs: that the replacement runs the other way up. A message saying only
	/// that the key was unknown would leave inverting the number to chance, and
	/// getting it backwards is silent -- the machine simply prefers the wrong
	/// network (0154).
	#[test]
	fn the_retired_priority_says_what_to_write_instead() {
		let text = "network \"Office\" {\n\twifi { psk = \"@secret:o\"; priority = 9 }\n}\n";
		let diagnostics = compile_errors(text);
		assert!(
			diagnostics.contains("metric"),
			"the refusal must name the replacement: {diagnostics}"
		);
		assert!(
			diagnostics.contains("lower"),
			"and say which way it ranks, or the number gets copied: {diagnostics}"
		);
	}

	#[test]
	fn a_wifi_network_round_trips() {
		round_trips(
			"network \"Cafe\" {\n\
			 \tmetric = 5\n\
			 \twifi {\n\
			 \t\tpsk = \"@secret:cafe\"\n\
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

	/// A network's own addressing, routes and resolver, all dropped in
	/// silence.
	///
	/// A `network` block takes the same `config`, `routes` and `dns` keys an
	/// interface does -- that is how a machine says "on this SSID use this
	/// static address and this resolver". A profile that lost them brought the
	/// machine back on DHCP against the wrong nameserver, which looks like a
	/// working network until something internal fails to resolve.
	#[test]
	fn a_networks_own_addressing_round_trips() {
		round_trips(
			"network \"Lab\" {\n\
			 \tconfig = \"10.4.0.9/24\"\n\
			 \troutes = \"default via 10.4.0.1\"\n\
			 \tdns {\n\
			 \t\tmode = \"write_resolv_conf\"\n\
			 \t\tservers = [\"10.4.0.53\"]\n\
			 \t\tsearch = [\"lab.example\"]\n\
			 \t}\n\
			 \twifi { psk = \"@secret:lab\" }\n\
			 }\n",
		);
	}

	/// A route's `src` and `onlink`, both dropped in silence.
	///
	/// `onlink` is the one with teeth: it exempts the route from the ordering
	/// rule that installs addresses before routes, so a route that needs it
	/// fails to install without it. `src` decides which address the machine is
	/// seen as coming from, which moves traffic to another identity rather
	/// than breaking it.
	#[test]
	fn a_routes_source_and_onlink_round_trip() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
			 \troutes = [\"default via 192.0.2.1 src 192.0.2.10 metric 100\", \
			 \"198.51.100.0/24 via 192.0.2.99 onlink\"]\n\
			 }\n",
		);
	}

	/// A network's pinned access points and its roaming policy, both dropped
	/// in silence. Losing the bssid list widens the network to any radio
	/// broadcasting the same name, which is what the key exists to prevent.
	#[test]
	fn a_networks_bssid_and_roam_round_trip() {
		round_trips(
			"network \"Office\" {\n\
			 \tbssid = [\"00:11:22:33:44:55\", \"00:11:22:33:44:66\"]\n\
			 \twifi {\n\
			 \t\tpsk = \"@secret:office\"\n\
			 \t\troam {\n\
			 \t\t\tsignal = -65\n\
			 \t\t\tinterval = 20\n\
			 \t\t\tslow_interval = 240\n\
			 \t\t}\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A roam block whose every value is the parser's default. It must still
	/// render as a block: the defaults are what an *absent* block means, so
	/// rendering nothing would turn "roam with the usual settings" into "do
	/// not roam", which is a different document.
	#[test]
	fn a_default_roam_block_survives() {
		round_trips(
			"network \"Cafe\" {\n\
			 \twifi {\n\
			 \t\tpsk = \"@secret:cafe\"\n\
			 \t\troam { signal = -70; interval = 30; slow_interval = 300 }\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A modem's SIM order and APN, 0150's vocabulary.
	#[test]
	fn a_modem_policy_round_trips() {
		round_trips(
			"device wwan0 {\n\
			 \tmodem {\n\
			 \t\tsim = [\"esim\", \"socket\"]\n\
			 \t\tapn = \"im.cxn\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// One source and no APN: the ordinary single-SIM board, where the list is
	/// a list of one rather than a different shape.
	#[test]
	fn a_single_sim_modem_round_trips() {
		round_trips("device wwan0 { modem { sim = \"socket\" } }\n");
	}

	/// `on_unmanage`, the second field found being dropped in silence.
	///
	/// Worse to lose than the VLANs: `clear` is chosen when the hardware is
	/// leaving your hands, and the default it silently reverts to strands
	/// credentials -- a `WireGuard` key stays loaded in the kernel, a
	/// supplicant keeps its passphrases. A profile that quietly downgraded it
	/// to `leave` would leave those behind on every machine restored from it.
	#[test]
	fn a_devices_unmanage_policy_round_trips() {
		round_trips(
			"device wlan0 {\n\
			 \tmanaged = false\n\
			 \ton_unmanage = \"clear\"\n\
			 }\n",
		);
	}

	/// The same policy on a device that is otherwise entirely default, which
	/// is the case `render_device`'s early return would have swallowed whole.
	#[test]
	fn an_unmanage_policy_alone_still_renders_its_device() {
		round_trips("device wlan1 { on_unmanage = \"clear\" }\n");
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
			"device br0 {\n\
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
			 device bond0 {\n\
			 \tbond {\n\
			 \t\tmembers = [\"eth2\", \"eth3\"]\n\
			 \t\tmode = \"802.3ad\"\n\
			 \t\tmiimon = 100\n\
			 \t}\n\
			 }\n\
			 device vlan10 {\n\
			 \tvlan { parent = \"eth0\"; id = 10 }\n\
			 }\n\
			 device vx0 {\n\
			 \tvxlan { id = 42; parent = \"eth0\" }\n\
			 }\n\
			 device mgmt {\n\
			 \tvrf { table = 100 }\n\
			 }\n\
			 device mv0 {\n\
			 \tmacvlan { parent = \"eth0\"; mode = \"bridge\" }\n\
			 }\n\
			 interface br0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
			 }\n\
			 interface bond0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n",
		);
	}

	/// The same kinds written in the one-line form, which the renderer emits
	/// only when a block has few enough keys -- a different path through
	/// `render_kind` and one that has broken on its own.
	#[test]
	fn the_link_kinds_round_trip_bare() {
		round_trips(
			"device br1 {\n\
			 \tbridge { members = \"eth4\" }\n\
			 }\n\
			 device bond1 {\n\
			 \tbond { members = \"eth5\"; mode = \"active-backup\" }\n\
			 }\n\
			 device vlan20 {\n\
			 \tvlan { parent = \"eth0\"; id = 20 }\n\
			 }\n\
			 device mv1 {\n\
			 \tmacvlan { parent = \"eth0\"; mode = \"private\" }\n\
			 }\n\
			 interface br1 { config = \"null\" }\n",
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
			"device eth0 {\n\
			 \tvlans = [\"10 pvid untagged\", \"20\", \"30 untagged\"]\n\
			 }\n\
			 interface eth0 {\n\
			 \tconfig = \"192.0.2.10/24\"\n\
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

	/// **Every PSK generation, because the default is the permissive one.**
	/// `proto` was dropped here until 2026-09-04, and it is the one wifi field
	/// whose loss weakens a network: the default is WPA2 and WPA3 together, so
	/// a `proto = "wpa3"` network came back accepting WPA2 -- a downgrade the
	/// operator had deliberately excluded. Asserting the round trip for all
	/// three is what stops the default silently absorbing the other two.
	#[test]
	fn every_psk_generation_round_trips() {
		for proto in ["wpa2", "wpa3", "wpa2+wpa3"] {
			round_trips(&format!(
				"network \"H\" {{\n\twifi {{ psk = \"@secret:h\"; proto = \"{proto}\" }}\n}}\n"
			));
		}
	}

	/// A wifi network carrying everything a network can carry, because the
	/// fields were added one at a time and each was rendered by whoever added
	/// it. One block asserts they all survive together.
	#[test]
	fn a_fully_populated_network_round_trips() {
		round_trips(
			"network \"Home\" {\n\
			 \tssid = \"486f6d65204e6574\"\n\
			 \thidden = true\n\
			 \tmetered = true\n\
			 \tmetric = 250\n\
			 \tbssid = [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"]\n\
			 \twifi { psk = \"@secret:home\"; proto = \"wpa3\" }\n\
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

	/// **An empty `dns { }` is a statement, not an absence.** On an interface
	/// or a network it says "use the nameservers this network hands out" --
	/// 0007 makes a per-interface policy a scope in its own right -- so the
	/// block being present and empty differs from its being absent, and a
	/// profile that lost it would come back ignoring the lease's resolvers.
	/// The renderer writes nothing when every field is at its default, which
	/// is right for `global` and was wrong for these two.
	#[test]
	fn an_empty_dns_block_survives_where_it_means_something() {
		round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tdns { }\n}\n");
		round_trips("network \"H\" {\n\twifi { open = true }\n\tdns { }\n}\n");
	}

	/// Every Bluetooth profile, and both sides of `autoconnect`.
	///
	/// The block was refused wholesale until 2026-09-04, so `ncfg profile
	/// save` could not save a machine with headphones written down. Five
	/// profiles is a closed set worth walking rather than sampling: the
	/// spellings are `BlueZ`'s and hyphenated, which is the kind of detail a
	/// renderer gets subtly wrong.
	#[test]
	fn every_bluetooth_profile_round_trips() {
		for profile in ["a2dp-sink", "a2dp-source", "hfp", "pan", "nap"] {
			round_trips(&format!(
				"bluetooth \"d\" {{\n\taddress = \"AA:BB:CC:DD:EE:FF\"\n\tprofile = \"{profile}\"\n}}\n"
			));
		}
		round_trips(
			"bluetooth \"d\" {\n\taddress = \"AA:BB:CC:DD:EE:FF\"\n\tprofile = \"pan\"\n\tautoconnect = false\n}\n",
		);
	}

	/// The refusal, which is the other half of the contract. A wireguard
	/// interface has no rendering here, and saying so by name is the whole
	/// difference between a partial renderer and a lossy one.
	#[test]
	fn what_cannot_be_rendered_is_named() {
		let document = compile(
			"device wg0 {\n\
			 \twireguard {\n\
			 \t\tprivate_key = \"@secret:wg\"\n\
			 \t}\n\
			 }\n\
			 interface wg0 {\n\
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
