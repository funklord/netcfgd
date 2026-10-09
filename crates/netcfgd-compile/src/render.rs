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
use netcfgd_model::device::{AccessPoint, AclPolicy};
use netcfgd_model::device::{MacPolicy, OnUnmanage, Powersave, WifiBackend, WifiDevicePolicy};
use netcfgd_model::dns::{DnsMode, DnsPolicy};
use netcfgd_model::interface::{
	BridgeVlan, InterfaceKind, LinkSettings, OpenVpnConfig, PppoeConfig, ProbePolicy, QdiscKind,
	QdiscPolicy, RaBackend, RaPolicy, Toggle, TunConfig, TunMode, TunnelConfig, WireGuardConfig,
};
use netcfgd_model::rule::{RoutingRule, RuleAction, RuleFamily};
use netcfgd_model::secret::{SecretProvider, SecretRef};
use netcfgd_model::security::{CertSource, EapConfig, EapMethod, Security};
use netcfgd_model::wifi::WifiNetwork;
use netcfgd_model::{
	AddressSource, Device, Dhcp4, Dhcp6, Document, DriftPolicy, HostnamePolicy, Interface, Route,
	Slaac, SlaacPrivacy,
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

/// Whether rendering this document and compiling the result gives it back.
///
/// **The property `ncfg profile save` rests on, available to any test that
/// happens to hold a document.** The daemon proves it before keeping a
/// snapshot, so a renderer that writes something subtly different refuses the
/// save rather than producing a wrong file -- which means every such refusal is
/// a defect here, and the operator sees it rather than a test does.
///
/// Public and here rather than copied into each test file, because it is now
/// called from three corpora -- the example manual, `netcfgd-compile`'s own
/// suite and `netcfgd-plan`'s fixtures -- and three copies of this would drift.
/// Two of the three defects it has found were visible to only one of those
/// corpora, which is the argument for pointing it at all of them.
///
/// Returns the complaint rather than panicking, so a caller can say whose test
/// it is and what an operator would have met.
///
/// # Errors
///
/// If the document cannot be rendered, if what was rendered does not compile,
/// or if it compiles to a different document.
pub fn round_trip(document: &Document) -> Result<(), String> {
	let overrides = Overrides::new();
	let rendered = render(document, &overrides)
		.map_err(|missing| format!("it cannot be rendered at all: {}", missing.join(", ")))?;
	let mut back = crate::SourceMap::new();
	back.add("rendered.conf", &rendered);
	match crate::compile(&back, &mut crate::NoHooks) {
		Ok(again) if again == *document => Ok(()),
		Ok(_) => Err(format!(
			"what it wrote compiles to a DIFFERENT document.\nrendered:\n{rendered}"
		)),
		Err(diagnostics) => Err(format!(
			"what it wrote does not compile.\nrendered:\n{rendered}\n{}",
			diagnostics.render(&back)
		)),
	}
}

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
	let ingress = IngressShaping::of(document, &mut missing);
	for device in &document.devices {
		if ingress.derived.contains(&device.name) {
			continue;
		}
		let _ = render_device(device, overrides, &ingress, &mut text, &mut missing);
	}

	// Named rather than skipped, per the header: these have no rendering yet
	// and a profile that quietly lacked them would be wrong in a way nobody
	// would see until the rule or the access point was needed.
	for rule in &document.rules {
		render_rule(rule, overrides, &mut text);
	}
	for point in &document.access_points {
		render_access_point(point, overrides, &mut text);
	}
	for device in &document.bluetooth {
		render_bluetooth(device, overrides, &mut text);
	}
	for set in &document.linksets {
		render_linkset(set, overrides, &mut text);
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
/// A block label: bare where the lexer would read it back as one, quoted where
/// it would not.
///
/// **Found by mutation, and the names are not hypothetical.** An `interface` and
/// a `device` label were always written bare, so a name the compiler accepts --
/// through a quoted label, or as a string in a bond's `members` -- could render
/// to text that does not parse. The mutation sweep over the example corpus hit
/// it with a bond member called `.th0`, and `.th0` is a name the kernel creates
/// happily: `ip link add .th0 type dummy` succeeds.
///
/// The lexer's rule is that a label starts with a letter or `_` and continues
/// with letters, digits, `.`, `-` or `_` -- which is why `eth0.42`, the
/// universal spelling of a VLAN interface, is deliberately bare. What it
/// refuses is a leading dot, a leading digit and anything else: `.th0` and
/// `2eth` are both legal kernel names, and a leading digit is an entirely
/// ordinary way to name a mobile interface (`4g0`). On such a machine
/// `ncfg profile save` refused, because the snapshot it rendered would not
/// compile -- the round-trip proof catching the renderer, which is what that
/// proof is for, but the operator got no profile.
///
/// Asked of `lex`'s own predicates rather than re-stating them here. A second
/// copy of the identifier rule is a second thing to be wrong, and it would go
/// wrong silently: the renderer would keep emitting bare labels the lexer had
/// stopped accepting.
fn label(name: &str) -> String {
	let mut bytes = name.bytes();
	let bare = match bytes.next() {
		Some(first) => {
			crate::lex::is_ident_start(first) && bytes.all(crate::lex::is_ident_continue)
		}
		// An empty label cannot be bare, and quoting says so where writing
		// nothing would silently produce `device {`.
		None => false,
	};
	if bare {
		name.to_owned()
	} else {
		quote(name)
	}
}

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
		// **`dhcp`, which is the word the language has.** It wrote
		// `from_dhcp` -- the variant's own name -- and `lower_globals` reads
		// anything that is not `dhcp` as a literal hostname, so the profile
		// did not merely lose the setting: it failed to parse, with
		// "`from_dhcp` is not a hostname" pointing at a line netcfgd wrote
		// itself. Found by rendering every example in `netcfgd.conf.example`.
		HostnamePolicy::FromDhcp => body.push_str("\thostname = \"dhcp\"\n"),
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
	// **This comment used to say `ingress_redirect` was here and "cannot
	// leave", and it was wrong twice.** It was wrong about the place: 0155
	// pass 1a moved that field to `device` and the sentence stayed behind, so
	// it described an entry this list has not had for some time. And it was
	// wrong about the impossibility, by one step. The analysis above it was
	// exactly right -- the compiler synthesises the redirect and the `ifb`
	// from `ingress_bandwidth`, and rendering the redirect would make the next
	// compile synthesise a second one -- and it closed with "the rate the
	// snapshot would have to write back is one the document no longer holds".
	// The document does hold it. It holds it on the derived device, which is
	// not visible from here, and `IngressShaping` recovers it from there.
	//
	// Worth keeping as a warning about the shape rather than the instance: a
	// refusal justified as permanent is read by the next person as a reason
	// not to try, and this one was scoped to what one function could see while
	// being written as a fact about the document.
	if !interface.hooks.is_empty() {
		// **Not a key this renderer has not got round to.** A `HookRef` holds
		// a path and a sha256, not the shell: `lower` hands the body to
		// `hooks.record(...)`, which materialises it to a file and returns a
		// reference. So the body the config said is not in the document at
		// all, and there is no path syntax to write instead -- a hook is only
		// ever a brace body. Rendering one needs either a read of the
		// materialised file, checked against the recorded hash, or new
		// grammar, and both are decisions rather than fixes.
		missing.push(format!("interface {name}: hooks"));
	}

	render_interface_keys(interface, &mut body);

	if !interface.enabled {
		body.push_str("\tenabled = false\n");
	}
	// The operator's own sentence about what depends on this interface, which
	// `ncfg` quotes back when something would take it down. Losing it in a
	// profile would turn a deliberate refusal into a link that goes down
	// without comment, which is the opposite of what it was written for.
	if let Some(guard) = &interface.guard {
		let _ = writeln!(body, "\tguard = {}", quote(&guard.reason));
	}
	if let Some(advertise) = &interface.advertise {
		render_advertise(advertise, name, &mut body, missing);
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
	let _ = write!(text, "\n{head} {} {{\n{body}}}\n", label(name));
}

/// What kind of link this is, as its own block.
///
/// The topology kinds are here, and `pppoe` with them. What is still refused
/// is `wireguard`, whose peer list and private key are a bigger question than
/// more keys, and `openvpn`, which names an operator's file. Those need
/// decisions about what a snapshot is allowed to contain.
///
/// `pppoe` was refused on that same reasoning and should not have been: its
/// password is a [`SecretRef`], a type incapable of carrying the value, and
/// rendering one as `@secret:name` is what a network's `psk` has always done.
/// The refusal cost a whole `ncfg profile save` on any machine whose WAN is
/// DSL or fibre, which is exactly the machine profiles exist for.
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
		// **PPPoE, which the paragraph above used to defer.** Its reason was
		// that a kind carrying a secret needs a decision about what a snapshot
		// may contain -- and for a `SecretRef` that decision is already made
		// and already relied on: a network's `psk` renders as `@secret:name`,
		// because the type is incapable of carrying the value. A password here
		// is the same type and gets the same answer.
		//
		// It matters because a DSL or fibre WAN is exactly the machine a
		// profile is for, and refusing the kind meant `ncfg profile save`
		// failed outright on one -- not the WAN saved wrongly, the whole save
		// refused.
		InterfaceKind::Pppoe(pppoe) => render_pppoe(pppoe, body),
		InterfaceKind::WireGuard(wireguard) => render_wireguard(wireguard, body),
		InterfaceKind::OpenVpn(openvpn) => render_openvpn(openvpn, body),
		InterfaceKind::Tunnel(tunnel) => render_tunnel(tunnel, body),
		InterfaceKind::Tun(tun) => render_tun(tun, body),
		// Named rather than left as `_`, so a kind added later is a compile
		// error here instead of a refusal somebody meets at `profile save`.
		// `Ifb` is the only one left and is unreachable from the language:
		// `expand_ingress_shapers` makes it, and `IngressShaping` skips the
		// one it made -- so reaching this means a document that did not come
		// through this compiler.
		other @ InterfaceKind::Ifb => {
			missing.push(format!("device {name}: kind {}", kind_name(other)));
		}
	}
}

/// An `OpenVPN` tunnel, which is a path and an optional credential.
///
/// Decision 0046's choice shows through here: what netcfgd holds is the path
/// to the operator's `.ovpn`, not a rendering of one, so a profile carries the
/// path and whatever is inside the file stays the operator's. That is also
/// what makes this arm short -- `openvpn --help` lists 253 options and none of
/// them is netcfgd's to write.
/// A `PPPoE` session.
///
/// Moved out of `render_kind` rather than rewritten, when that function went
/// past the line limit after learning four more kinds. `parent`, `username`
/// and `password` are unconditional because the model requires all three: a
/// session with no credential is one that cannot authenticate, which `lower`
/// refuses rather than defaulting.
fn render_pppoe(pppoe: &PppoeConfig, body: &mut String) {
	body.push_str("\tpppoe {\n");
	let _ = writeln!(body, "\t\tparent = {}", quote(&pppoe.parent));
	let _ = writeln!(body, "\t\tusername = {}", quote(&pppoe.username));
	let _ = writeln!(
		body,
		"\t\tpassword = {}",
		quote(&secret_ref(&pppoe.password))
	);
	if let Some(service) = &pppoe.service {
		let _ = writeln!(body, "\t\tservice = {}", quote(service));
	}
	if let Some(ac) = &pppoe.ac {
		let _ = writeln!(body, "\t\tac = {}", quote(ac));
	}
	body.push_str("\t}\n");
}

fn render_openvpn(openvpn: &OpenVpnConfig, body: &mut String) {
	body.push_str("\topenvpn {\n");
	let _ = writeln!(body, "\t\tconfig = {}", quote(&openvpn.config));
	if let Some(username) = &openvpn.username {
		let _ = writeln!(body, "\t\tusername = {}", quote(username));
	}
	if let Some(password) = &openvpn.password {
		let _ = writeln!(body, "\t\tpassword = {}", quote(&secret_ref(password)));
	}
	body.push_str("\t}\n");
}

/// An encapsulating tunnel.
///
/// The key is `mode` and not `kind`, which the model's own comment explains:
/// [`InterfaceKind`] serialises with an internal tag named `kind`, so a
/// variant whose inner struct also had one produced JSON with the field twice.
/// The parser accepts both spellings and this writes the one the model uses.
fn render_tunnel(tunnel: &TunnelConfig, body: &mut String) {
	body.push_str("\ttunnel {\n");
	let _ = writeln!(body, "\t\tmode = {}", quote(tunnel.mode.name()));
	if let Some(local) = &tunnel.local {
		let _ = writeln!(body, "\t\tlocal = {}", quote(&local.to_string()));
	}
	if let Some(remote) = &tunnel.remote {
		let _ = writeln!(body, "\t\tremote = {}", quote(&remote.to_string()));
	}
	if let Some(parent) = &tunnel.parent {
		let _ = writeln!(body, "\t\tparent = {}", quote(parent));
	}
	if let Some(ttl) = tunnel.ttl {
		let _ = writeln!(body, "\t\tttl = {ttl}");
	}
	if let Some(key) = tunnel.key {
		let _ = writeln!(body, "\t\tkey = {key}");
	}
	body.push_str("\t}\n");
}

/// A persistent tun or tap device.
///
/// **The mode is the block head, not a key.** `lower_link_kind` reads `tun`
/// and `tap` as two spellings of one parser, so a `mode` written inside the
/// block would be an unknown key -- and a renderer emitting `tun { }` for a
/// tap device loses layer 2 in silence.
fn render_tun(tun: &TunConfig, body: &mut String) {
	let head = match tun.mode {
		TunMode::Tun => "tun",
		TunMode::Tap => "tap",
	};
	let _ = writeln!(body, "\t{head} {{");
	if let Some(owner) = &tun.owner {
		let _ = writeln!(body, "\t\towner = {}", quote(owner));
	}
	if let Some(group) = &tun.group {
		let _ = writeln!(body, "\t\tgroup = {}", quote(group));
	}
	body.push_str("\t}\n");
}

/// A `WireGuard` interface and its peers.
///
/// **A VPN is the thing a profile is most likely to be about**, and this was
/// the broadest kind left refusing a save: the office tunnel is up at the
/// office and not at home, which is the whole shape of a profile.
///
/// Every credential is written as the reference it came in as -- the private
/// key and each peer's optional preshared key -- for the reason the access
/// point's psk is: a `SecretRef` holds a provider and a name and no value, so
/// the exposure is not a leak but a prefix, and a name written bare reads back
/// as a literal key.
///
/// A peer's `public_key` goes through [`netcfgd_model::Key`]'s own rendering
/// rather than being formatted here, so the spelling the parser accepts and
/// the spelling written are one function. `allowed_ips` is written even when
/// empty is impossible -- `lower_wg_peer` requires at least one, a peer with
/// none being a tunnel that carries nothing.
fn render_wireguard(wireguard: &WireGuardConfig, body: &mut String) {
	body.push_str("\twireguard {\n");
	let _ = writeln!(
		body,
		"\t\tprivate_key = {}",
		quote(&secret_ref(&wireguard.private_key))
	);
	if let Some(port) = wireguard.listen_port {
		let _ = writeln!(body, "\t\tlisten_port = {port}");
	}
	if let Some(fwmark) = wireguard.fwmark {
		let _ = writeln!(body, "\t\tfwmark = {fwmark}");
	}
	for peer in &wireguard.peers {
		let _ = writeln!(body, "\t\tpeer {} {{", quote(&peer.name));
		let _ = writeln!(
			body,
			"\t\t\tpublic_key = {}",
			quote(&peer.public_key.to_string())
		);
		if let Some(preshared) = &peer.preshared_key {
			let _ = writeln!(
				body,
				"\t\t\tpreshared_key = {}",
				quote(&secret_ref(preshared))
			);
		}
		if let Some(endpoint) = &peer.endpoint {
			let _ = writeln!(body, "\t\t\tendpoint = {}", quote(endpoint));
		}
		let allowed: Vec<String> = peer.allowed_ips.iter().map(|ip| quote(ip)).collect();
		let _ = writeln!(body, "\t\t\tallowed_ips = {}", list_or_scalar(&allowed));
		if let Some(keepalive) = peer.keepalive {
			let _ = writeln!(body, "\t\t\tkeepalive = {keepalive}");
		}
		body.push_str("\t\t}\n");
	}
	body.push_str("\t}\n");
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
	// **Dropped in silence until the example corpus was rendered**, and it
	// defaults to ON -- so the key only ever appears to say "probe even with
	// no lease", which is what a modem needs. `lower_probe`'s own comment
	// gives the reason the default is that way round: an interface that asked
	// for DHCP and has no lease has nothing a reachability probe could succeed
	// over. A profile losing it turns a modem's working probe into one that
	// waits for a lease it may never get.
	if !probe.require_lease {
		body.push_str("\t\trequire_lease = false\n");
	}
	body.push_str("\t}\n");
}

/// One static address, with the modifier words that follow it.
///
/// **The modifiers are part of the `config` string, not keys of their own**,
/// which is why this is a `format!` and not three `writeln!`s: netcfgd's
/// addressing syntax takes netifrc's shape, so a peer and a lifetime are
/// trailing words that `address_entries` splits back out using its `MODIFIERS`
/// table. The spellings here are that table's -- `peer`, `preferred_lft`,
/// `valid_lft` -- and not the model's field names, which are
/// `preferred_lifetime` and `valid_lifetime`.
///
/// All three were refusing the save until now, which made a point-to-point
/// link and a deprecated address both profile-proof: `preferred_lft 0` is how
/// an address is kept reachable while no longer being chosen as a source, and
/// it is exactly the sort of thing that differs between one network and the
/// next.
fn static_address(address: &netcfgd_model::address::Static) -> String {
	let mut text = address.address.clone();
	if let Some(peer) = &address.peer {
		text.push_str(" peer ");
		text.push_str(peer);
	}
	if let Some(seconds) = address.preferred_lifetime {
		let _ = write!(text, " preferred_lft {seconds}");
	}
	if let Some(seconds) = address.valid_lifetime {
		let _ = write!(text, " valid_lft {seconds}");
	}
	text
}

/// Addressing, shared by an interface and by a wireless network.
///
/// A `network` block takes the same `config` key an interface does, so this is
/// one function rather than two: the network side was rendering nothing at
/// all, and writing a second copy is how the two would come to disagree about
/// what `slaac` spells.
///
/// **The match is exhaustive and deliberately has no catch-all.** It had one
/// until every [`AddressSource`] variant was handled, at which point the arm
/// was dead -- and a dead catch-all is worse than none, because an eighth
/// variant would be absorbed into a refusal somebody meets at `profile save`
/// rather than a compile error somebody meets while adding it. Whoever adds
/// one decides here what a profile says about it.
fn render_addressing(
	sources: &[AddressSource],
	whose: &str,
	body: &mut String,
	missing: &mut Unrenderable,
) {
	let config: Vec<String> = sources
		.iter()
		.filter_map(|source| match source {
			AddressSource::Static(address) => Some(quote(&static_address(address))),
			// **These three wrote the bare word and dropped everything else**,
			// which is how `dhcp6 pd_length 56` became `dhcp6` and a
			// delegation request vanished from a saved profile. Not a refusal
			// either: `render` returned `Ok`, so only the daemon's round-trip
			// proof stood between that and a profile missing the prefix the
			// whole inside network is numbered from.
			//
			// Each arm now compares against the default it would have written
			// and refuses anything else, rather than listing the fields it
			// knows. That is the part worth keeping: a field added to `Dhcp4`
			// tomorrow is refused by name instead of being silently dropped by
			// a renderer nobody remembered to update, which is the failure
			// this whole list exists to prevent and the one it kept having.
			AddressSource::Dhcp4(dhcp4) => {
				// `dhcp` takes no modifiers at all -- `address_source` runs it
				// through `no_modifiers` -- so every field here is unreachable
				// from the language and a non-default one did not come from a
				// configuration file.
				if *dhcp4 != Dhcp4::default() {
					missing.push(format!("{whose}: a dhcp4 lease carrying options"));
					return None;
				}
				Some(quote("dhcp"))
			}
			AddressSource::Dhcp6(dhcp6) => {
				let plain = Dhcp6 {
					prefix_delegation: dhcp6.prefix_delegation.clone(),
					..Dhcp6::default()
				};
				if *dhcp6 != plain {
					missing.push(format!("{whose}: a dhcp6 lease carrying options"));
					return None;
				}
				let mut text = String::from("dhcp6");
				if let Some(request) = &dhcp6.prefix_delegation {
					// Each of `pd_hint` and `pd_length` implies `pd`, so the
					// bare word is written only when neither is set -- which
					// is also the spelling the example file uses.
					if request.hint.is_none() && request.length.is_none() {
						text.push_str(" pd");
					}
					if let Some(hint) = &request.hint {
						let _ = write!(text, " pd_hint {hint}");
					}
					if let Some(length) = request.length {
						let _ = write!(text, " pd_length {length}");
					}
				}
				Some(quote(&text))
			}
			AddressSource::Slaac(slaac) => {
				// **Destructured rather than compared, and clippy is why.**
				// This was written as `Slaac { privacy, ..default }` and a
				// `!=` against it, copying the `Dhcp6` arm above -- and
				// `privacy` is Slaac's only field, so that compared the value
				// with itself and could never fire. A guard that cannot fail
				// is this tree's oldest lesson and it was written here anyway.
				//
				// The destructuring is what the guard was reaching for and is
				// better than it was: a field added to `Slaac` does not fail
				// at `profile save`, it fails to compile for whoever adds it.
				let Slaac { privacy } = slaac;
				let mut text = String::from("slaac");
				if *privacy == SlaacPrivacy::PreferTemporary {
					text.push_str(" privacy prefer_temporary");
				}
				Some(quote(&text))
			}
			AddressSource::LinkLocal => Some(quote("link_local")),
			// `@pd:wan0`, `@pd:wan0/2`, `@pd:wan0=::1/64` -- the same shape as
			// `@secret:`, and for the same reason: an indirection the document
			// carries instead of a value, because no config file can know what
			// an ISP will delegate. The suffix is written only where it differs
			// from the `::1/64` the parser supplies, and `index` keeps a
			// refusal: it selects between several delegations in one lease and
			// `delegated_source` pins it to 0, so no spelling exists.
			AddressSource::Delegated(delegated) => {
				if delegated.prefix.index != 0 {
					missing.push(format!("{whose}: a delegated prefix selected by index"));
					return None;
				}
				let mut text = format!("@pd:{}", delegated.prefix.source);
				if delegated.prefix.subnet != 0 {
					let _ = write!(text, "/{}", delegated.prefix.subnet);
				}
				if delegated.suffix != "::1/64" {
					let _ = write!(text, "={}", delegated.suffix);
				}
				Some(quote(&text))
			}
			// A value with nothing in it: the modem's own report is the
			// address, so the word is the whole of what a document says.
			AddressSource::Reported(_) => Some(quote("reported")),
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

	// **`None` is a statement and not an absence**, which is what the first
	// version of this read it as. The model says so: `None` means "whatever the
	// access points in `bssid` call themselves" (0090), while omitting the key
	// makes the SSID the label -- so a network written `ssid = "@bssid"`
	// rendered with no `ssid` line at all and came back as a network named
	// after its own label. `ncfg profile save` refused on any machine with a
	// network pinned by access point, with its own honest message: *"That is a
	// fault in the snapshot rather than in your configuration."* It was.
	//
	// The spelling comes from the lowerer that defines it rather than being
	// retyped, so the two cannot disagree about what the marker is.
	match &network.ssid {
		// Equal to the label is what omitting the key means, so omitting it is
		// the faithful rendering and the shorter one.
		Some(ssid) if ssid.as_bytes() == id.as_bytes() => {}
		Some(ssid) => {
			let _ = writeln!(body, "\tssid = {}", quote(&ssid.to_hex()));
		}
		None => {
			let _ = writeln!(body, "\tssid = {}", quote(crate::lower::SSID_FROM_BSSID));
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
	render_security(&network.security, &mut body);
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

/// The security of a network or an access point, inside an open `wifi` block.
///
/// **Shared because the parser shares it.** `lower_access_point` reads an
/// access point's `wifi` block with `lower_network_wifi` through a throwaway
/// station -- *"an access point's security is the same shape as a station's, so
/// it is parsed by the same code"* -- and a second copy here would be the one
/// place the two could drift. The depth is the same either way: a `wifi` block
/// sits one level in, so its keys sit two.
///
/// A passphrase is written as the reference it came from and never as a value,
/// which `secret_ref` is for: section 2 keeps secrets out of the document, and a
/// profile is a document.
fn render_security(security: &Security, body: &mut String) {
	match security {
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
		Security::Eap(eap) => render_eap(eap, body),
	}
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
	// **The one field here whose loss weakens a network rather than changing
	// it**, which is `proto`'s lesson in a worse place. It is what stops the
	// supplicant authenticating to a rogue RADIUS server presenting a
	// certificate some trusted CA signed: without it the chain is checked and
	// the *name* is not, so any certificate from any CA in the store is
	// accepted. A profile that dropped it came back weaker than the
	// configuration it was saved from, and said nothing.
	//
	// It was the one field of nine `render_eap` did not write, and the round
	// trip over `netcfgd.conf.example` is what found it -- three of that
	// file's enterprise examples set it.
	if let Some(domain) = &eap.domain_suffix_match {
		let _ = writeln!(body, "\t\tdomain_suffix_match = {}", quote(domain));
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

/// Returns whether the block was written, which `round_trip` asks about.
///
/// **Asked of the renderer rather than recomputed.** The condition is "this
/// device has nothing to say", and a predicate spelling that out elsewhere
/// would enumerate `Device`'s fields and go stale the next time one is added --
/// silently, and in the direction that makes the round trip look sound.
fn render_device(
	device: &Device,
	overrides: &Overrides,
	ingress: &IngressShaping,
	text: &mut String,
	missing: &mut Unrenderable,
) -> bool {
	let name = &device.name;
	if device.r#match.is_some() {
		missing.push(format!("device {name}: a match block"));
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
	// Settings of the adapter, which moved here from `interface` with 0155
	// pass 1a. Rendered from the day they arrived rather than joining the list
	// of things a profile silently loses.
	if let Some(mtu) = device.mtu {
		let _ = writeln!(body, "\tmtu = {mtu}");
	}
	if let Some(mac) = &device.mac {
		let _ = writeln!(body, "\tmac = {}", quote(mac));
	}
	// **After the scalars, which is a byte-for-byte agreement rather than a
	// preference.** Both programs gained qdisc and ethtool rendering
	// independently -- this one on master, the C port on its own branch -- and
	// put them on opposite sides of `mtu`. Neither was a porting error and
	// neither output was wrong, but `agree` compares the two profiles byte for
	// byte, so one had to move. This one did: `device eth0 { mtu = 1492;
	// qdisc { ... } }` is the order the configuration is written in, a plain
	// key before a nested block, and under 0266 the C is what ships -- so the
	// shipped spelling is the one the oracle follows.
	if let Some(qdisc) = &device.qdisc {
		render_qdisc(
			qdisc,
			ingress.rates.get(name).copied(),
			name,
			&mut body,
			missing,
		);
	}
	if let Some(settings) = &device.link_settings {
		render_ethtool(settings, &mut body);
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
	render_wifi_device(device.wifi.as_ref(), &mut body);
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
	// **A device with nothing to say is not written at all, and the skip is
	// load-bearing.** It was removed here on the reading that 10.21's
	// "present and empty is not absent" covered a `device` block as it covers
	// `dns { }`, and that broke `ncfg profile save` for an ordinary
	// configuration: the document holds a synthesised all-default device for
	// every interface, `overrides` claims that synthesised device is declared
	// in the base, so the renderer wrote `override device eth0 { }` for a
	// block the base config never had -- and `override` on something with
	// nothing to override cannot compile. Measured on
	// `tests/footprint/etc`, which declares one interface and no device:
	//
	//     ncfg: that would stop the configuration compiling, so it was not
	//     kept: .../00-saved.conf:13:10: `override device eth0` has nothing
	//     to override
	//
	// 10.21's criterion is whether a block carries meaning of its own, which
	// is why an empty `dns { }` on an interface must be written and the same
	// block in `global` must not. A `device` block measures as the `global`
	// case: it changes no plan, and netcfgd says so itself -- a device block
	// alone is policy about hardware nobody asked it to configure.
	//
	// **Unless somebody wrote it**, which `declared` is what records. Until
	// the model carried that, an invented all-default device and a written
	// empty one were byte-identical here, so a written one was lost: a
	// `device wlan0 { }` beside an `access_point` naming it has nothing else
	// to recreate its entry, and the save refused for not reproducing the
	// machine. 10.418 for the measurement, 10.438 for the field.
	if body.is_empty() && !device.declared.0 {
		return false;
	}
	let head = opening("device", name, overrides);
	let _ = write!(text, "\n{head} {} {{\n{body}}}\n", label(name));
	true
}

/// The `wifi` block of a device: what the radio itself is told to do.
///
/// **Present and empty is not absent**, which is 10.21's lesson for `dns { }`
/// arriving in a second block. `device.wifi` being `Some` is what makes a radio
/// netcfgd's to drive, and netcfgd writes
/// `device <iface> { wifi { autoconnect = true } }` into every radio
/// `ncfg wifi activate` touches -- so a policy at every default still renders
/// `wifi { }`. Writing nothing would turn every managed radio into one netcfgd
/// has no policy for, which is a bigger change than any single key here.
///
/// Until this existed the whole save was refused, because a wifi policy went on
/// the unrenderable list: honest, and it meant profiles were unavailable to
/// exactly the people who use wifi. Each value is written only where it differs
/// from the default, which is this renderer's rule everywhere, and the three
/// enums are quoted because `lower_wifi_device` reads them with `as_string`.
fn render_wifi_device(wifi: Option<&WifiDevicePolicy>, body: &mut String) {
	let Some(wifi) = wifi else {
		return;
	};
	body.push_str("\twifi {\n");
	if wifi.backend != WifiBackend::default() {
		let _ = writeln!(
			body,
			"\t\tbackend = {}",
			quote(wifi_backend_name(wifi.backend))
		);
	}
	if !wifi.autoconnect {
		body.push_str("\t\tautoconnect = false\n");
	}
	if let Some(url) = &wifi.portal_check {
		let _ = writeln!(body, "\t\tportal_check = {}", quote(url));
	}
	// Already uppercase: `lower_regdom` upcases on the way in, so this is the
	// spelling that reads back as the same value rather than one the parser
	// would have to normalise again.
	if let Some(regdom) = &wifi.regdom {
		let _ = writeln!(body, "\t\tregdom = {}", quote(regdom));
	}
	if wifi.powersave != Powersave::default() {
		let _ = writeln!(
			body,
			"\t\tpowersave = {}",
			quote(powersave_name(wifi.powersave))
		);
	}
	if wifi.mac_policy != MacPolicy::default() {
		let _ = writeln!(
			body,
			"\t\tmac_policy = {}",
			quote(mac_policy_name(wifi.mac_policy))
		);
	}
	if wifi.scan_randomization {
		body.push_str("\t\tscan_randomization = true\n");
	}
	body.push_str("\t}\n");
}

/// A wifi backend, spelled as the parser reads it back.
///
/// `iwd` is rendered like any other. The compiler accepts it and netcfgd
/// refuses it at use (0014), so a profile that dropped it would turn a
/// configuration netcfgd explains itself about into one it silently approves.
fn wifi_backend_name(backend: WifiBackend) -> &'static str {
	match backend {
		WifiBackend::Auto => "auto",
		WifiBackend::WpaSupplicant => "wpa_supplicant",
		WifiBackend::Iwd => "iwd",
	}
}

/// A powersave setting, spelled as the parser reads it back.
fn powersave_name(powersave: Powersave) -> &'static str {
	match powersave {
		Powersave::Default => "default",
		Powersave::On => "on",
		Powersave::Off => "off",
	}
}

/// A hardware-address policy, spelled as the parser reads it back.
fn mac_policy_name(policy: MacPolicy) -> &'static str {
	match policy {
		MacPolicy::Permanent => "permanent",
		MacPolicy::PerNetwork => "per_network",
		MacPolicy::PerConnection => "per_connection",
	}
}

/// Router advertisements, which this machine sends on an interface it serves.
///
/// `prefixes` is written unconditionally because `lower_advertise` refuses a
/// block without one -- a router advertising nothing is a configuration
/// mistake rather than a default -- and each entry is written as the `@pd:`
/// reference it came in as. **A prefix is never a literal in this language**,
/// deliberately: it names the interface whose delegation supplies it, because
/// no config file can know what an ISP will hand out.
///
/// `dns` is the one key whose default is *true*, so the omit-at-default rule
/// writes it only when it is off. Getting that backwards would turn a router
/// that advertises a resolver into one that does not, which looks like
/// working DNS right up until the moment the host has no other source.
///
/// Two things keep a refusal, and both are spellings the language does not
/// have. `RaBackend::Exec` is a fourth backend `lower_advertise` will not
/// accept -- `netcfgd-ra` implements it, nothing can ask for it -- and
/// `PrefixRef::index`, which selects between several delegations in one
/// lease, is hardcoded to 0 by the parser. Writing either as a guess would be
/// a profile that does not reload.
fn render_advertise(policy: &RaPolicy, name: &str, body: &mut String, missing: &mut Unrenderable) {
	let backend = match &policy.backend {
		RaBackend::Auto => None,
		RaBackend::Odhcpd => Some("odhcpd"),
		RaBackend::Radvd => Some("radvd"),
		RaBackend::Exec(_) => {
			missing.push(format!(
				"interface {name}: an advertise backend handed to a script"
			));
			return;
		}
	};
	let mut prefixes = Vec::new();
	for prefix in &policy.prefixes {
		if prefix.index != 0 {
			missing.push(format!(
				"interface {name}: an advertised prefix selected by index"
			));
			return;
		}
		prefixes.push(quote(&if prefix.subnet == 0 {
			format!("@pd:{}", prefix.source)
		} else {
			format!("@pd:{}/{}", prefix.source, prefix.subnet)
		}));
	}

	body.push_str("\tadvertise {\n");
	if let Some(backend) = backend {
		let _ = writeln!(body, "\t\tbackend = {}", quote(backend));
	}
	let _ = writeln!(body, "\t\tprefixes = {}", list_or_scalar(&prefixes));
	if policy.managed {
		body.push_str("\t\tmanaged = true\n");
	}
	if policy.other_config {
		body.push_str("\t\tother_config = true\n");
	}
	if !policy.dns {
		body.push_str("\t\tdns = false\n");
	}
	if let Some(lifetime) = policy.lifetime {
		let _ = writeln!(body, "\t\tlifetime = {lifetime}");
	}
	body.push_str("\t}\n");
}

/// Ingress shaping, undone back into the operator's own spelling.
///
/// **This is the one place the renderer reconstructs an input rather than
/// describing the document**, and it has to, because `expand_ingress_shapers`
/// does not merely add to what the operator wrote -- it moves it. One
/// `ingress_bandwidth` on a device's qdisc becomes three things: the rate is
/// `take`n off that qdisc, the device gains an `ingress_redirect`, and a
/// second device `ifb-<name>` is synthesised to carry the rate on a `cake` of
/// its own, flagged `ingress`. The kernel cannot queue what has already
/// arrived, so the traffic is redirected onto an `ifb` where it has become
/// egress; decision 0023's amendment covers why.
///
/// Rendering that faithfully would be wrong in both directions. The rate is no
/// longer on the device the operator put it on, so writing each device as it
/// stands loses it from one and invents a device for it in the other -- and
/// recompiling the result would synthesise a *second* `ifb` for a document
/// that already had one. So the derived device is skipped and its rate written
/// back where it came from, and the round trip is what proves the inversion
/// exact: the second compile re-derives what the first one derived.
///
/// **Three refusals were firing at once before this**, which is why it is
/// worth the machinery rather than a fourth: `ingress_redirect`, `kind ifb`
/// and the `ingress` qdisc are all unreachable from the configuration
/// language *by name*, so each read as a field nothing could set -- and all
/// three are set by the compiler for any machine that shapes its inbound line,
/// which is most machines on a domestic connection. None of them could save a
/// profile.
struct IngressShaping {
	/// Devices the compiler synthesised, which are not written at all.
	derived: std::collections::HashSet<String>,
	/// Shaped device name to the rate recovered from its `ifb`.
	rates: std::collections::HashMap<String, u64>,
}

impl IngressShaping {
	/// Work out which devices are derived, refusing where the shape is not
	/// this compiler's.
	///
	/// **Strict on purpose.** A document reaches the renderer from the
	/// compiler today, but nothing in the type says so, and the inversion is
	/// only valid for a device that really is `expand_ingress_shapers`'
	/// output. So every field the synthesis leaves at its default is checked,
	/// and anything else -- an operator's own `ifb` with an MTU on it, a
	/// redirect pointing at a device that is not there -- keeps an honest
	/// refusal rather than being rendered wrongly. That is the same reason
	/// `render_wifi_device` keeps a `regdom` check the parser already makes.
	fn of(document: &netcfgd_model::Document, missing: &mut Unrenderable) -> Self {
		let mut derived = std::collections::HashSet::new();
		let mut rates = std::collections::HashMap::new();
		for device in &document.devices {
			let Some(target) = &device.ingress_redirect else {
				continue;
			};
			let found = document
				.devices
				.iter()
				.find(|candidate| candidate.name == *target)
				.filter(|candidate| candidate.name == format!("ifb-{}", device.name))
				.and_then(Self::rate_of);
			match found {
				Some(rate) => {
					derived.insert(target.clone());
					rates.insert(device.name.clone(), rate);
				}
				None => missing.push(format!(
					"device {}: an ingress redirect to `{target}`, which is not a \
					 device this build would have made for it",
					device.name
				)),
			}
		}
		Self { derived, rates }
	}

	/// The rate an `ifb` carries, if it is one this build would have made.
	///
	/// Everything `expand_ingress_shapers` leaves alone is required to still
	/// be alone: a field set on the synthesised device is operator intent that
	/// this inversion would discard, and discarding it silently is the failure
	/// the whole unrenderable list exists to avoid.
	fn rate_of(device: &Device) -> Option<u64> {
		let bare = device.kind == InterfaceKind::Ifb
			&& device.managed
			&& device.on_unmanage == OnUnmanage::default()
			&& device.r#match.is_none()
			&& device.wifi.is_none()
			&& device.modem.is_none()
			&& device.mtu.is_none()
			&& device.mac.is_none()
			&& device.link_settings.is_none()
			&& device.master.is_none()
			&& device.ingress_redirect.is_none()
			&& device.bridge_vlans.is_empty();
		if !bare {
			return None;
		}
		let qdisc = device.qdisc.as_ref()?;
		if !qdisc.ingress || qdisc.kind != QdiscKind::Cake || qdisc.ingress_bandwidth_bits.is_some()
		{
			return None;
		}
		qdisc.bandwidth_bits
	}
}

/// A device's ethtool settings.
///
/// Every field is written only where it differs from its default, which for
/// the five offloads and for `autoneg` means [`Toggle::Unmanaged`] -- *"whatever
/// the driver defaults to, or somebody else set"*. That is not the same as
/// `off`, and writing `unmanaged` explicitly would turn a block that declines
/// to touch an offload into one that says so at length.
///
/// The block is written whenever the device has one at all, because
/// `lower_device` only attaches it when `is_empty()` is false -- so a device
/// carrying `link_settings` carries at least one non-default key, and the
/// block cannot come out empty.
fn render_ethtool(settings: &LinkSettings, body: &mut String) {
	body.push_str("\tethtool {\n");
	for (value, key) in [
		(settings.autoneg, "autoneg"),
		(settings.gro, "gro"),
		(settings.gso, "gso"),
		(settings.tso, "tso"),
		(settings.rx_checksum, "rx_checksum"),
		(settings.tx_checksum, "tx_checksum"),
	] {
		if value != Toggle::default() {
			let _ = writeln!(body, "\t\t{key} = {}", quote(toggle_name(value)));
		}
	}
	if let Some(speed) = settings.speed {
		let _ = writeln!(body, "\t\tspeed = {speed}");
	}
	if let Some(duplex) = &settings.duplex {
		let _ = writeln!(body, "\t\tduplex = {}", quote(duplex));
	}
	if let Some(wol) = &settings.wol {
		let _ = writeln!(body, "\t\twol = {}", quote(wol));
	}
	if let Some(size) = settings.rx_ring {
		let _ = writeln!(body, "\t\trx_ring = {size}");
	}
	if let Some(size) = settings.tx_ring {
		let _ = writeln!(body, "\t\ttx_ring = {size}");
	}
	body.push_str("\t}\n");
}

/// A [`Toggle`] as the parser spells it.
fn toggle_name(toggle: Toggle) -> &'static str {
	match toggle {
		Toggle::Unmanaged => "unmanaged",
		Toggle::On => "on",
		Toggle::Off => "off",
	}
}

/// A device's root qdisc.
///
/// **Two spellings, and which one is written is decided by the content.** The
/// language takes `qdisc = "cake"` for a scheduler with nothing to configure
/// and a `qdisc { }` block where a rate is being set, and both come back as
/// the same `QdiscPolicy` -- so a kind on its own is written as the short form
/// it was almost certainly written in.
///
/// `ingress` is the one field with no key, and it keeps a refusal. Nothing in
/// the language sets it: the planner sets it on the `cake` it puts on an `ifb`
/// device of its own making, never on an interface an operator named. A
/// document carrying it did not come through this compiler, which is the same
/// reason `render_wifi_device` keeps its own `regdom` check.
fn render_qdisc(
	qdisc: &QdiscPolicy,
	recovered: Option<u64>,
	name: &str,
	body: &mut String,
	missing: &mut Unrenderable,
) {
	// A qdisc flagged `ingress` on a device this renderer is writing means the
	// device was NOT recognised as one the compiler synthesised -- a derived
	// one is skipped before it gets here. So the flag has arrived on an
	// operator's own device, which no configuration can say, and refusing is
	// the honest answer.
	if qdisc.ingress {
		missing.push(format!("device {name}: a qdisc metering arriving traffic"));
	}
	// `ingress_bandwidth_bits` is `take`n by `expand_ingress_shapers`, so a
	// compiled document never still carries it here. It is written where it
	// does survive, because the renderer is reachable from a document that did
	// not come through this compiler, and dropping a shaped rate quietly is
	// the one outcome worse than refusing.
	let inbound = qdisc.ingress_bandwidth_bits.or(recovered);
	if qdisc.bandwidth_bits.is_none() && inbound.is_none() {
		let _ = writeln!(body, "\tqdisc = {}", quote(qdisc.kind.name()));
		return;
	}
	let _ = writeln!(body, "\tqdisc {{");
	let _ = writeln!(body, "\t\tkind = {}", quote(qdisc.kind.name()));
	if let Some(bits) = qdisc.bandwidth_bits {
		let _ = writeln!(body, "\t\tbandwidth = {}", quote(&rate(bits)));
	}
	if let Some(bits) = inbound {
		let _ = writeln!(body, "\t\tingress_bandwidth = {}", quote(&rate(bits)));
	}
	body.push_str("\t}\n");
}

/// A rate in bits per second, in the largest unit that divides it exactly.
///
/// Exactness is the whole requirement: `rate_bits` multiplies, so any unit
/// that divides the number reads back as the same number, and one that does
/// not would lose a profile a few bits of its shaped rate every time it was
/// saved. 100 Mbit/s is written `100mbit` and 100,000,001 bit/s is written
/// `100000001bit`, which is ugly and correct.
fn rate(bits: u64) -> String {
	for (suffix, multiplier) in [
		("gbit", 1_000_000_000_u64),
		("mbit", 1_000_000),
		("kbit", 1_000),
	] {
		if bits % multiplier == 0 {
			return format!("{}{suffix}", bits / multiplier);
		}
	}
	format!("{bits}bit")
}

/// An access point this machine serves.
///
/// Until this existed one `access_point` block put `N access_point block(s)` on
/// the unrenderable list and refused the whole save, so a machine serving a
/// hotspot could save no profile -- and a machine that serves one is a machine
/// whose configuration changes with where it is, which is what profiles are for.
///
/// The `wifi` block is written unconditionally, which is the one sub-block here
/// that is not conditional: `lower_access_point` refuses an access point without
/// one rather than defaulting it, saying it *"would be open"* and declining to
/// guess. Everything else is written where it is set or differs from its
/// default.
fn render_access_point(point: &AccessPoint, overrides: &Overrides, text: &mut String) {
	let mut body = String::new();
	let _ = writeln!(body, "\tdevice = {}", quote(&point.device));
	// The label is the SSID unless the document said otherwise, exactly as a
	// network's is -- and then it is hex, because an SSID is 0..32 arbitrary
	// octets and the label is text.
	if point.ssid.as_bytes() != point.id.as_bytes() {
		let _ = writeln!(body, "\tssid = {}", quote(&point.ssid.to_hex()));
	}
	if let Some(channel) = point.channel {
		let _ = writeln!(body, "\tchannel = {channel}");
	}
	if let Some(band) = &point.band {
		let _ = writeln!(body, "\tband = {}", quote(band));
	}
	if let Some(regdom) = &point.regdom {
		let _ = writeln!(body, "\tregdom = {}", quote(regdom));
	}
	if point.hidden {
		body.push_str("\thidden = true\n");
	}
	body.push_str("\twifi {\n");
	render_security(&point.security, &mut body);
	body.push_str("\t}\n");
	// **One list, and which key it is under is the policy.** The compiler
	// refuses a block carrying both an `allow` and a `deny`, so the policy is
	// not a separate value to write -- and the list is written bracketed even
	// for one station, because `access_control` is where a reader most needs to
	// see that it is a list rather than a single permitted address.
	if let Some(acl) = &point.access_control {
		let key = match acl.policy {
			AclPolicy::Deny => "deny",
			AclPolicy::Allow => "allow",
		};
		let stations: Vec<String> = acl.stations.iter().map(|station| quote(station)).collect();
		let _ = writeln!(
			body,
			"\taccess_control {{ {key} = [{}] }}",
			stations.join(", ")
		);
	}
	let head = opening("access_point", &point.id, overrides);
	let _ = write!(text, "\n{head} {} {{\n{body}}}\n", quote(&point.id));
}

/// A policy routing rule, which belongs to no interface.
///
/// Every rule is written, and `priority` always: the model requires it because
/// an unnumbered rule lands wherever the kernel puts it, so a profile that
/// omitted it would restore a document that no longer describes the machine.
/// Everything else is written where it differs from the default, which is this
/// renderer's rule throughout.
///
/// Until this existed a single rule put `N routing rule(s)` on the unrenderable
/// list and refused the whole save, so policy routing and profiles were
/// mutually exclusive -- and policy routing is how a second uplink or a
/// one-subnet VPN is expressed, which is to say by the machines most likely to
/// want more than one profile.
fn render_rule(rule: &RoutingRule, overrides: &Overrides, text: &mut String) {
	let mut body = String::new();
	let _ = writeln!(body, "\tpriority = {}", rule.priority);
	if rule.family != RuleFamily::default() {
		let _ = writeln!(body, "\tfamily = {}", quote(rule_family_name(rule.family)));
	}
	for (value, key) in [
		(&rule.from, "from"),
		(&rule.to, "to"),
		(&rule.iif, "iif"),
		(&rule.oif, "oif"),
	] {
		if let Some(value) = value {
			let _ = writeln!(body, "\t{key} = {}", quote(value));
		}
	}
	for (value, key) in [
		(rule.fwmark, "fwmark"),
		(rule.fwmask, "fwmask"),
		(rule.table, "lookup"),
		(rule.suppress_prefixlength, "suppress_prefixlength"),
	] {
		if let Some(value) = value {
			let _ = writeln!(body, "\t{key} = {value}");
		}
	}
	// **Written as `lookup`, which is the spelling the example file uses.** The
	// compiler reads `table` as well and the model calls it that; a profile is
	// read by people, so it gets the one the documentation teaches.
	if rule.invert {
		body.push_str("\tinvert = true\n");
	}
	// **Dropped until an `l3mdev` rule could be written at all.** The compiler
	// required a `lookup` on every rule, which such a rule cannot have -- the
	// VRF supplies the table -- so no document reached here carrying one and
	// the gap was unreachable. It became reachable the moment that check
	// learned the exception, and the round trip over the example file caught it
	// in the same run: the rule came back as `rule "vrf-local" { priority }`,
	// which does not compile, because a rule with no lookup, no action and no
	// `l3mdev` is exactly what the compiler refuses.
	if rule.l3mdev {
		body.push_str("\tl3mdev = true\n");
	}
	if rule.action != RuleAction::default() {
		let _ = writeln!(body, "\taction = {}", quote(rule_action_name(rule.action)));
	}
	let head = opening("rule", &rule.id, overrides);
	let _ = write!(text, "\n{head} {} {{\n{body}}}\n", quote(&rule.id));
}

/// A rule's address family, spelled as the parser reads it back.
///
/// `inet` and `ipv4` both parse; the first is written because it is what the
/// kernel calls it and what `ip rule` prints.
fn rule_family_name(family: RuleFamily) -> &'static str {
	match family {
		RuleFamily::Inet => "inet",
		RuleFamily::Inet6 => "inet6",
	}
}

/// A rule's action, spelled as the parser reads it back.
fn rule_action_name(action: RuleAction) -> &'static str {
	match action {
		RuleAction::Lookup => "lookup",
		RuleAction::Blackhole => "blackhole",
		RuleAction::Unreachable => "unreachable",
		RuleAction::Prohibit => "prohibit",
	}
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

/// A `linkset`, which is a name and a ranked list.
///
/// **The list is written in its own order**, not sorted and not folded to a
/// scalar when there is one member: the order is the ranking, and a snapshot
/// that reordered it would describe a different machine from the one it was
/// taken of.
fn render_linkset(set: &netcfgd_model::linkset::Linkset, overrides: &Overrides, text: &mut String) {
	let head = opening("linkset", &set.name, overrides);
	let _ = write!(text, "\n{head} {} {{\n", quote(&set.name));
	let members: Vec<String> = set.members.iter().map(|member| quote(member)).collect();
	let _ = writeln!(text, "\tmembers = [{}]", members.join(", "));
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

	/// Every key of a routing rule round-trips.
	///
	/// Until `render_rule` existed one rule put `N routing rule(s)` on the
	/// unrenderable list and refused the whole save, so a machine using policy
	/// routing could save no profile at all. Each value here differs from its
	/// default, because a renderer that writes only non-defaults is tested by
	/// nothing where every value is the default one.
	#[test]
	fn a_routing_rules_keys_round_trip() {
		round_trips(
			"rule \"carved\" {\n\
			 \tpriority = 300\n\
			 \tfamily = \"inet6\"\n\
			 \tfrom = \"2001:db8:1::/64\"\n\
			 \tto = \"2001:db8:2::/64\"\n\
			 \tiif = \"eth0\"\n\
			 \toif = \"eth1\"\n\
			 \tfwmark = 7\n\
			 \tfwmask = 255\n\
			 \tlookup = 44\n\
			 \tsuppress_prefixlength = 0\n\
			 \tinvert = true\n\
			 \taction = \"prohibit\"\n\
			 }\n",
		);
	}

	/// And a rule that says the least it can round-trips too.
	///
	/// The compiler refuses a rule with no selector and no action, so the
	/// smallest legal one still carries a lookup. What this checks is the other
	/// direction from the case above: that a default family, a default action
	/// and an absent `invert` are **not** written, since writing them would be
	/// harmless here and a lie about what the operator asked for.
	#[test]
	fn a_minimal_routing_rule_gains_nothing() {
		let document = compile("rule \"plain\" {\n\tpriority = 400\n\tlookup = 45\n}\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(!rendered.contains("family"), "{rendered}");
		assert!(!rendered.contains("action"), "{rendered}");
		assert!(!rendered.contains("invert"), "{rendered}");
		assert_eq!(compile(&rendered), document, "rendered as:\n{rendered}");
	}

	/// Every key of a radio's own policy round-trips.
	///
	/// Until `render_wifi_device` existed this panicked on the refusal rather
	/// than failing an assertion -- a wifi policy was on the unrenderable list,
	/// so `ncfg profile save` was refused outright on any machine with an
	/// activated radio. Each value here differs from its default, because a
	/// renderer that writes only non-defaults is tested by nothing where every
	/// value is the default one.
	#[test]
	fn a_radios_policy_round_trips() {
		round_trips(
			"device wlan0 {\n\
			 \twifi {\n\
			 \t\tbackend = \"wpa_supplicant\"\n\
			 \t\tautoconnect = false\n\
			 \t\tportal_check = \"http://example.com/generate_204\"\n\
			 \t\tregdom = \"se\"\n\
			 \t\tpowersave = \"off\"\n\
			 \t\tmac_policy = \"per_network\"\n\
			 \t\tscan_randomization = true\n\
			 \t}\n\
			 }\n\
			 interface wlan0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n",
		);
	}

	/// **The block netcfgd writes itself survives a save**, which is the case
	/// that matters most and the one a non-default sweep would miss.
	///
	/// `ncfg wifi activate` writes `device <iface> { wifi { autoconnect = true
	/// } }`, every value of it the default. `Some(default)` and `None` are
	/// different documents -- the policy's presence is what makes the radio
	/// netcfgd's to drive -- so a renderer that wrote nothing where there was
	/// nothing to say would turn every managed radio into an unmanaged one, on
	/// the machine of everybody who has ever activated a radio. 10.21 is the
	/// same fault in `dns { }`.
	#[test]
	fn the_block_netcfgd_writes_itself_survives_a_save() {
		round_trips(
			"device wlan0 {\n\
			 \twifi {\n\
			 \t\tautoconnect = true\n\
			 \t}\n\
			 }\n\
			 interface wlan0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n",
		);
	}

	/// And a device with no radio does not acquire one.
	///
	/// The other direction of the same `Option`, and the half most likely to
	/// be wrong in a fix written for the first: rendering `wifi { }`
	/// unconditionally would hand a policy to every bridge and vlan in the
	/// document. `round_trips` catches it because `None` and `Some(default)`
	/// compile to different documents.
	#[test]
	fn a_device_with_no_radio_gains_no_wifi_block() {
		round_trips(
			"device eth0 {\n\
			 \tmtu = 1400\n\
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

	/// A linkset, whose one interesting property is that the order survives.
	///
	/// A snapshot is what `ncfg profile save` writes, so a set rendered with
	/// its members in some other order would describe a machine that fails
	/// over the other way round -- and nothing downstream could tell.
	#[test]
	fn a_linkset_round_trips_in_its_own_order() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n\
			 interface wwan0 {\n\
			 \tconfig = \"dhcp\"\n\
			 }\n\
			 linkset \"uplink\" {\n\
			 \tmembers = [\"wwan0\", \"eth0\"]\n\
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

	/// A `PPPoE` session, with and without the optional provider names.
	///
	/// Refused wholesale until 2026-09-04, so `ncfg profile save` failed
	/// outright on any machine whose WAN is DSL or fibre. The password is
	/// asserted as a reference in both provider spellings, because the one
	/// thing a snapshot must never do is carry the value -- and `@secret:` and
	/// `@secret:keyring:` are different references to different stores.
	#[test]
	fn a_pppoe_session_round_trips() {
		round_trips(
			"device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n\t\tusername = \"u\"\n\t\tpassword = \"@secret:p\"\n\t}\n}\n",
		);
		round_trips(
			"device ppp0 {\n\tpppoe {\n\t\tparent = \"e0\"\n\t\tusername = \"u\"\n\t\tpassword = \"@secret:keyring:p\"\n\t\tservice = \"svc\"\n\t\tac = \"conc\"\n\t}\n}\n",
		);
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
	/// A document carrying something unrenderable is refused, by name.
	///
	/// **The subject had to change, and that is the test working.** It used
	/// `wireguard` until that kind was rendered, so the case now uses a hook
	/// -- the one entry on the refusal list that is both reachable from the
	/// configuration language and deliberately refused rather than pending. A
	/// `HookRef` holds a path and a sha256 and not the shell, so there is
	/// nothing in the document to write back.
	///
	/// Picking a refusal that is merely *not done yet* would make this test
	/// fail every time somebody closed one, which is a test that punishes the
	/// work it is meant to accompany.
	#[test]
	fn what_cannot_be_rendered_is_named() {
		// The hook is attached rather than written in the configuration,
		// because this module's `compile` helper uses `NoHooks` -- which
		// refuses a hook with "this caller cannot accept hooks" rather than
		// materialising one. That refusal is the compiler's and is a different
		// subject from this one.
		let mut document = compile("interface eth0 { config = \"dhcp\" }\n");
		document.interfaces[0]
			.hooks
			.push(netcfgd_model::hook::HookRef {
				phase: netcfgd_model::hook::HookPhase::PostUp,
				path: "/etc/netcfgd/hook/eth0-post_up".to_owned(),
				sha256: "0".repeat(64),
				run_as: None,
				timeout: None,
			});
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing.iter().any(|what| what.contains("hooks")),
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

	/// The smallest access point a document can hold, which is the one the
	/// compiler's two refusals leave: a radio and a `wifi` block.
	#[test]
	fn an_access_point_round_trips() {
		round_trips(
			"access_point \"Home\" {\n\
			 \tdevice = \"wlan0\"\n\
			 \twifi { psk = \"@secret:ap\" }\n\
			 }\n",
		);
	}

	/// **The options on `dhcp6` and `slaac`, which were dropped in silence.**
	///
	/// Every one of these was found by rendering `netcfgd.conf.example` and
	/// recompiling it, and **none of them was caught by any of this module's
	/// other cases** -- the arms wrote the bare word and returned `Ok`, so
	/// nothing short of comparing the documents could see it. They have their
	/// own cases here as well as in that gate, because the gate's coverage is
	/// whatever the documentation happens to contain: an example deleted for
	/// being repetitive would take the only test of `pd_length` with it.
	#[test]
	fn the_addressing_options_round_trip() {
		round_trips("interface eth0 { config = [\"dhcp\", \"dhcp6 pd\"] }\n");
		round_trips("interface eth0 { config = \"dhcp6 pd_length 56\" }\n");
		round_trips("interface eth0 { config = \"dhcp6 pd_hint 2001:db8::\" }\n");
		round_trips("interface eth0 { config = \"dhcp6 pd_hint 2001:db8:: pd_length 56\" }\n");
		round_trips("interface eth0 { config = \"slaac privacy prefer_temporary\" }\n");
		round_trips("interface eth0 { config = \"slaac privacy none\" }\n");
	}

	/// And the bare words stay bare, which the round trip cannot show.
	///
	/// `dhcp6` with no delegation and `slaac` with privacy off are the
	/// defaults, so a renderer writing ` pd` or ` privacy none` unconditionally
	/// still round-trips -- and makes every profile claim a delegation request
	/// the operator never made. For `pd` that is not cosmetic: it asks the ISP
	/// for a prefix.
	#[test]
	fn plain_dhcp6_and_slaac_stay_plain() {
		let document = compile("interface eth0 { config = [\"dhcp6\", \"slaac\"] }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("\"dhcp6\""), "{rendered}");
		assert!(rendered.contains("\"slaac\""), "{rendered}");
		for absent in ["pd", "privacy"] {
			assert!(
				!rendered.contains(absent),
				"{absent} is not set and must not be written: {rendered}"
			);
		}

		// **And a redundant `pd` beside a `pd_length` is not written.** This
		// is the one assertion here the round trip cannot make: `pd` only sets
		// "a delegation was asked for", which `pd_length` sets too, so
		// `dhcp6 pd pd_length 56` compiles to exactly the same document.
		// Nothing behavioural turns on it -- it is pinned because the arm's
		// comment claims the minimal spelling, and a claim in a comment that
		// no test makes is how this file keeps finding comments that stopped
		// being true. The whole value is compared rather than searched for
		// `pd`, which is a substring of `pd_length`.
		let document = compile("interface eth0 { config = \"dhcp6 pd_length 56\" }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(
			rendered.contains("config = \"dhcp6 pd_length 56\""),
			"{rendered}"
		);
	}

	/// A `dhcp4` lease carrying anything is refused rather than flattened.
	///
	/// `address_source` runs `dhcp` through `no_modifiers`, so every field of
	/// `Dhcp4` is unreachable from the language and a non-default one did not
	/// come from a configuration file. The arm compares against the default
	/// rather than listing fields, so a field added later is refused by name
	/// instead of being dropped by a renderer nobody updated -- which is the
	/// failure the whole unrenderable list exists to prevent, and the one it
	/// kept having.
	#[test]
	fn a_dhcp4_lease_with_options_is_refused() {
		let mut document = compile("interface eth0 { config = \"dhcp\" }\n");
		for source in &mut document.interfaces[0].addressing {
			if let netcfgd_model::AddressSource::Dhcp4(dhcp4) = source {
				dhcp4.metric = Some(250);
			}
		}
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing.iter().any(|what| what.contains("dhcp4 lease")),
			"{missing:?}"
		);
	}

	/// The probe's `require_lease`, whose default is on.
	///
	/// So the key appears only to say "probe with no lease", which is what a
	/// modem needs -- and it was written nowhere, so a profile turned a
	/// working cellular probe into one waiting for a lease it may never get.
	#[test]
	fn a_probes_require_lease_round_trips() {
		round_trips(
			"interface wwan0 {\n\
			 \tconfig = \"dhcp\"\n\
			 \tprobe {\n\
			 \t\tcommand = \"/usr/share/netcfgd/probe/default\"\n\
			 \t\targs = \"wwan0\"\n\
			 \t\trequire_lease = false\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **`domain_suffix_match`, the field whose loss weakens a network.**
	///
	/// Without it the supplicant checks the certificate chain and not the
	/// name, so any certificate from any CA in the store is accepted -- which
	/// is what a rogue RADIUS server needs. It was the one field of nine
	/// `render_eap` did not write, so an enterprise profile came back weaker
	/// than the configuration it was saved from and said nothing.
	#[test]
	fn an_eap_domain_suffix_match_round_trips() {
		round_trips(
			"network \"corp\" {\n\
			 \twifi {\n\
			 \t\teap = \"tls\"\n\
			 \t\tidentity = \"you@corp.example\"\n\
			 \t\tca_cert = \"/etc/netcfgd/certs/corp-ca.pem\"\n\
			 \t\tdomain_suffix_match = \"radius.corp.example\"\n\
			 \t\tprivate_key = \"@secret:corp-key\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// The hostname taken from a lease, in the word the language has.
	///
	/// It wrote `from_dhcp`, the variant's own name, and `lower_globals` reads
	/// anything that is not `dhcp` as a literal hostname -- so the profile did
	/// not lose the setting, it **failed to parse**, with "`from_dhcp` is not
	/// a hostname" pointing at a line netcfgd wrote itself.
	#[test]
	fn a_hostname_from_dhcp_round_trips() {
		round_trips("global { hostname = \"dhcp\" }\n");
		round_trips("global { hostname = \"host.example\" }\n");
	}

	/// A delegated prefix in every spelling the parser accepts.
	///
	/// `@pd:` is an indirection for the same reason `@secret:` is -- no config
	/// file can know what an ISP will delegate -- so what a profile has to
	/// write back is the reference and not the address it resolved to. A
	/// renderer resolving it would pin a profile to one ISP lease.
	#[test]
	fn a_delegated_prefix_round_trips() {
		round_trips("interface lan0 { config = \"@pd:wan0\" }\n");
		round_trips("interface lan0 { config = \"@pd:wan0/2\" }\n");
		round_trips("interface lan0 { config = \"@pd:wan0=::2/64\" }\n");
		round_trips("interface lan0 { config = \"@pd:wan0/3=::1/64\" }\n");
		round_trips("interface lan0 { config = [\"192.0.2.1/24\", \"@pd:wan0\"] }\n");
	}

	/// **The default suffix is not written**, which is the one thing the round
	/// trip above cannot show on its own: `delegated_source` supplies
	/// `::1/64` when no `=` is given, so a renderer writing the suffix
	/// unconditionally still round-trips while making every profile noisier
	/// than the file it came from.
	#[test]
	fn a_delegated_prefix_at_its_default_suffix_says_nothing_extra() {
		let document = compile("interface lan0 { config = \"@pd:wan0\" }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("config = \"@pd:wan0\""), "{rendered}");
		assert!(!rendered.contains("::1/64"), "{rendered}");
	}

	/// And a delegated prefix picked by index is refused, as the advertised
	/// one is.
	///
	/// `PrefixRef::index` selects between several delegations in one lease and
	/// `delegated_source` pins it to 0, so no document can set it and there is
	/// no spelling to write. Reached by putting it in after compiling -- and
	/// the case exists because the sabotage that removes the refusal was
	/// caught by nothing, exactly as the advertise one was.
	#[test]
	fn a_delegated_prefix_by_index_is_refused() {
		let mut document = compile("interface lan0 { config = \"@pd:wan0\" }\n");
		for source in &mut document.interfaces[0].addressing {
			if let netcfgd_model::AddressSource::Delegated(delegated) = source {
				delegated.prefix.index = 1;
			}
		}
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing
				.iter()
				.any(|what| what.contains("selected by index")),
			"{missing:?}"
		);
	}

	/// An address something outside netcfgd reported, where the word is all
	/// there is -- a modem's own report is the value (0047).
	#[test]
	fn a_reported_address_round_trips() {
		round_trips("interface wwan0 { config = \"reported\" }\n");
	}

	/// **A `WireGuard` tunnel and its peers, which was the broadest kind left
	/// refusing a save.** A VPN is the thing a profile is most likely to be
	/// about -- the office tunnel is up at the office and not at home -- so a
	/// renderer that could not write one left profiles unavailable to exactly
	/// the machines that move.
	#[test]
	fn a_wireguard_tunnel_round_trips() {
		round_trips(
			"device wg0 {\n\
			 \twireguard {\n\
			 \t\tprivate_key = \"@secret:wg\"\n\
			 \t\tlisten_port = 51820\n\
			 \t\tfwmark = 51820\n\
			 \t\tpeer \"office\" {\n\
			 \t\t\tpublic_key = \"5mQ3HVK9lJ7Tr0ePjWcQnL8sKdFhGyBvAzXuM2NiRkc=\"\n\
			 \t\t\tpreshared_key = \"@secret:wg-office\"\n\
			 \t\t\tendpoint = \"vpn.example.com:51820\"\n\
			 \t\t\tallowed_ips = [\"10.0.0.0/8\", \"192.168.0.0/16\"]\n\
			 \t\t\tkeepalive = 25\n\
			 \t\t}\n\
			 \t}\n\
			 }\n",
		);
	}

	/// A tunnel with one peer and nothing optional, which is the ordinary one.
	///
	/// Separate from the case above because a renderer writing an optional key
	/// unconditionally round-trips whenever every optional key is set, and the
	/// maximal case is exactly the one that cannot see it.
	#[test]
	fn a_minimal_wireguard_tunnel_round_trips() {
		round_trips(
			"device wg0 {\n\
			 \twireguard {\n\
			 \t\tprivate_key = \"@secret:wg\"\n\
			 \t\tpeer \"home\" {\n\
			 \t\t\tpublic_key = \"5mQ3HVK9lJ7Tr0ePjWcQnL8sKdFhGyBvAzXuM2NiRkc=\"\n\
			 \t\t\tallowed_ips = \"0.0.0.0/0\"\n\
			 \t\t}\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **Two peers, because a peer list is the thing a loop gets wrong.** One
	/// peer passes a renderer that writes only the first, and the compiler
	/// refuses two peers sharing a public key -- so a renderer reusing one
	/// key across the list would be refused on reload rather than silently
	/// merging the two.
	#[test]
	fn two_wireguard_peers_round_trip() {
		round_trips(
			"device wg0 {\n\
			 \twireguard {\n\
			 \t\tprivate_key = \"@secret:wg\"\n\
			 \t\tpeer \"a\" {\n\
			 \t\t\tpublic_key = \"5mQ3HVK9lJ7Tr0ePjWcQnL8sKdFhGyBvAzXuM2NiRkc=\"\n\
			 \t\t\tallowed_ips = \"10.1.0.0/16\"\n\
			 \t\t}\n\
			 \t\tpeer \"b\" {\n\
			 \t\t\tpublic_key = \"Qd8vT2pXsKmN4LcRfWyHbJgZaE3uBnV6oP1iYrAxM0s=\"\n\
			 \t\t\tallowed_ips = \"10.2.0.0/16\"\n\
			 \t\t}\n\
			 \t}\n\
			 }\n",
		);
	}

	/// An `OpenVPN` tunnel with a credential, and one without.
	///
	/// Both, because the username and password are optional here and not on a
	/// `PPPoE` session: a `.ovpn` with inline certificates authenticates
	/// without either, and that is the ordinary provider-supplied case.
	#[test]
	fn an_openvpn_tunnel_round_trips() {
		round_trips(
			"device tun0 {\n\
			 \topenvpn {\n\
			 \t\tconfig = \"/etc/openvpn/work.ovpn\"\n\
			 \t\tusername = \"someone\"\n\
			 \t\tpassword = \"@secret:ovpn\"\n\
			 \t}\n\
			 }\n",
		);
		round_trips("device tun1 { openvpn { config = \"/etc/openvpn/a.ovpn\" } }\n");
	}

	/// Every tunnel mode, and the keys one carries.
	#[test]
	fn every_tunnel_mode_round_trips() {
		for mode in ["gre", "gretap", "ip6gre", "ipip", "sit", "ip6tnl", "geneve"] {
			round_trips(&format!(
				"device tnl0 {{ tunnel {{ mode = \"{mode}\" }} }}\n"
			));
		}
		round_trips(
			"device gre0 {\n\
			 \ttunnel {\n\
			 \t\tmode = \"gre\"\n\
			 \t\tlocal = \"192.0.2.1\"\n\
			 \t\tremote = \"198.51.100.1\"\n\
			 \t\tparent = \"eth0\"\n\
			 \t\tttl = 64\n\
			 \t\tkey = 42\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **`tun` and `tap` are two block heads rather than a `mode` key**, so a
	/// renderer writing one head for both loses layer 2 in silence -- and
	/// writing a `mode` key inside the block would be refused as unknown.
	#[test]
	fn tun_and_tap_round_trip_as_their_own_heads() {
		round_trips("device tun0 { tun { owner = \"someone\"; group = \"netdev\" } }\n");
		round_trips("device tap0 { tap { } }\n");
		let document = compile("device tap0 { tap { } }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("tap {"), "{rendered}");
		assert!(!rendered.contains("tun {"), "{rendered}");
	}

	/// **An `l3mdev` rule, which has no `lookup` and must not grow one.**
	///
	/// The round trip is the whole test: such a rule carries no table, so a
	/// renderer that drops the flag emits `rule "x" { priority = N }` -- and
	/// that does not compile, a rule with no lookup, no action and no
	/// `l3mdev` being exactly what the compiler refuses. So the failure is a
	/// profile that cannot be loaded rather than one that loads wrong, which
	/// is the better of the two and still a profile nobody can use.
	#[test]
	fn an_l3mdev_rule_round_trips() {
		round_trips("rule \"vrf\" {\n\tpriority = 1500\n\tl3mdev = true\n}\n");
		let document = compile("rule \"vrf\" {\n\tpriority = 1500\n\tl3mdev = true\n}\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("l3mdev = true"), "{rendered}");
		// And no table is invented on the way, which the kernel refuses
		// outright: "table can not be specified for l3mdev rules".
		assert!(!rendered.contains("lookup"), "{rendered}");
	}

	/// An interface's guard, which is a sentence rather than a setting.
	///
	/// Losing it in a profile turns a deliberate refusal -- `ncfg` quoting the
	/// operator's own words back when something would take the link down --
	/// into a link that goes down without comment.
	#[test]
	fn a_guard_round_trips() {
		round_trips("interface eth0 {\n\tconfig = \"dhcp\"\n\tguard = \"the office VPN\"\n}\n");
	}

	/// Every advertise key at a non-default.
	#[test]
	fn an_advertise_policy_round_trips() {
		round_trips(
			"interface lan0 {\n\
			 \tconfig = \"192.0.2.1/24\"\n\
			 \tadvertise {\n\
			 \t\tbackend = \"radvd\"\n\
			 \t\tprefixes = [\"@pd:wan0\", \"@pd:wan0/3\"]\n\
			 \t\tmanaged = true\n\
			 \t\tother_config = true\n\
			 \t\tdns = false\n\
			 \t\tlifetime = 1800\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **The default-true key, which is the one that can be got backwards.**
	///
	/// `dns` defaults to on, so the omit-at-default rule writes it only when
	/// it is off -- and a renderer writing it only when *on* produces a
	/// profile whose router stops advertising a resolver. That looks like
	/// working DNS until the host has no other source, which is the failure
	/// nobody connects to a profile they saved weeks earlier.
	#[test]
	fn an_advertise_block_at_its_defaults_says_nothing_extra() {
		round_trips("interface lan0 { advertise { prefixes = \"@pd:wan0\" } }\n");
		let document = compile("interface lan0 { advertise { prefixes = \"@pd:wan0\" } }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("prefixes = \"@pd:wan0\""), "{rendered}");
		for absent in ["backend", "managed", "other_config", "dns", "lifetime"] {
			assert!(
				!rendered.contains(absent),
				"{absent} is at its default and should not be written: {rendered}"
			);
		}
	}

	/// **A backend the language cannot spell is refused, not guessed.**
	///
	/// `RaBackend::Exec` is implemented in `netcfgd-ra` and
	/// `lower_advertise` accepts only auto, radvd and odhcpd, so no document
	/// can ask for it -- which means a renderer inventing a spelling would
	/// write a profile that does not reload. Reached here by putting the
	/// variant in after compiling, since the parser will not.
	#[test]
	fn an_advertise_backend_the_parser_lacks_is_refused() {
		let mut document = compile("interface lan0 { advertise { prefixes = \"@pd:wan0\" } }\n");
		let policy = document.interfaces[0].advertise.as_mut().expect("a policy");
		policy.backend = RaBackend::Exec("/usr/local/bin/ra".to_owned());
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing
				.iter()
				.any(|what| what.contains("handed to a script")),
			"{missing:?}"
		);
	}

	/// And the same for a prefix picked by index, which the parser pins to 0.
	#[test]
	fn an_advertised_prefix_by_index_is_refused() {
		let mut document = compile("interface lan0 { advertise { prefixes = \"@pd:wan0\" } }\n");
		document.interfaces[0]
			.advertise
			.as_mut()
			.expect("a policy")
			.prefixes[0]
			.index = 1;
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing
				.iter()
				.any(|what| what.contains("selected by index")),
			"{missing:?}"
		);
	}

	/// Every ethtool key at a non-default, which is the whole block.
	///
	/// It was on the unrenderable list until now, so a wired machine with a
	/// forced speed or a wake-on-LAN flag could save no profile at all -- and
	/// those are settings of a particular socket on a particular switch, which
	/// is to say exactly what differs between one site and the next.
	#[test]
	fn every_ethtool_key_round_trips() {
		round_trips(
			"device eth0 {\n\
			 \tethtool {\n\
			 \t\tautoneg = \"off\"\n\
			 \t\tspeed = 100\n\
			 \t\tduplex = \"full\"\n\
			 \t\twol = \"g\"\n\
			 \t\trx_ring = 4096\n\
			 \t\ttx_ring = 4096\n\
			 \t\tgro = \"off\"\n\
			 \t\tgso = \"off\"\n\
			 \t\ttso = \"on\"\n\
			 \t\trx_checksum = \"on\"\n\
			 \t\ttx_checksum = \"unmanaged\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **One offload set and the rest left alone**, which is the ordinary case
	/// and the one that distinguishes `unmanaged` from `off`. A renderer
	/// writing every toggle would turn a block declining to touch five
	/// offloads into one that says `unmanaged` five times -- and worse, a
	/// renderer treating the default as `off` would turn "leave this alone"
	/// into "switch it off", which is a change to the hardware rather than to
	/// the file.
	#[test]
	fn one_ethtool_key_does_not_write_the_others() {
		let document = compile("device eth0 { ethtool { gro = \"off\" } }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("gro = \"off\""), "{rendered}");
		for absent in [
			"unmanaged",
			"gso",
			"tso",
			"checksum",
			"speed",
			"wol",
			"ring",
		] {
			assert!(
				!rendered.contains(absent),
				"{absent} should not be written: {rendered}"
			);
		}
		round_trips("device eth0 { ethtool { gro = \"off\" } }\n");
	}

	/// A scheduler with nothing to configure, written in the short form.
	///
	/// Both spellings compile to the same `QdiscPolicy`, so the round trip
	/// cannot tell them apart and the choice would otherwise be a claim in a
	/// doc comment that nothing checks.
	#[test]
	fn a_bare_qdisc_is_written_in_the_short_form() {
		round_trips("device eth0 { qdisc = \"fq_codel\" }\n");
		let document = compile("device eth0 { qdisc { kind = \"fq_codel\" } }\n");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(rendered.contains("qdisc = \"fq_codel\""), "{rendered}");
		assert!(!rendered.contains("qdisc {"), "{rendered}");
	}

	/// A shaper, where the rate is the point.
	#[test]
	fn a_shaped_qdisc_round_trips() {
		round_trips(
			"device eth0 {\n\
			 \tqdisc {\n\
			 \t\tkind = \"cake\"\n\
			 \t\tbandwidth = \"100mbit\"\n\
			 \t\tingress_bandwidth = \"40mbit\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// **A rate no unit divides exactly.** `rate_bits` multiplies, so a
	/// renderer picking a unit that does not divide the number loses bits off
	/// a shaped rate on every save -- quietly, and compounding, since the next
	/// save renders the number it read back.
	#[test]
	fn a_rate_that_divides_no_unit_round_trips() {
		for spelling in ["100000001bit", "1001kbit", "7mbit", "2gbit", "999bit"] {
			round_trips(&format!(
				"device eth0 {{ qdisc {{ kind = \"cake\"; bandwidth = \"{spelling}\" }} }}\n"
			));
		}
	}

	/// **Ingress shaping, which is the renderer's only reconstruction.**
	///
	/// The round trip is the whole proof: the first compile derives an `ifb`
	/// device, a redirect and a flagged qdisc from one `ingress_bandwidth`, and
	/// the rendered profile must make the second compile derive exactly the
	/// same three. A renderer describing the document instead would move the
	/// rate onto a device the operator never wrote, and recompiling that would
	/// synthesise a second `ifb` on top of the first.
	///
	/// The shaped-and-unshaped case matters separately: with no outbound rate
	/// the operator's qdisc keeps only a kind, which is the short-form test's
	/// condition, so the recovered inbound rate is the only thing forcing the
	/// block form.
	#[test]
	fn an_ingress_shaper_round_trips() {
		round_trips(
			"device eth0 {\n\
			 \tqdisc {\n\
			 \t\tkind = \"cake\"\n\
			 \t\tingress_bandwidth = \"40mbit\"\n\
			 \t}\n\
			 }\n",
		);
	}

	/// And the derived device itself is not written.
	///
	/// Asserted on the text as well as by the round trip, because an `ifb`
	/// block in the profile is not merely redundant: `expand_ingress_shapers`
	/// refuses outright when a document already declares the name it needs, so
	/// a profile naming `ifb-eth0` would be one that cannot be loaded at all.
	#[test]
	fn the_derived_ifb_is_not_in_the_profile() {
		let document =
			compile("device eth0 { qdisc { kind = \"cake\"; ingress_bandwidth = \"40mbit\" } }\n");
		assert_eq!(document.devices.len(), 2, "the compiler derives one");
		let rendered = render(&document, &Overrides::new()).expect("renders");
		assert!(!rendered.contains("ifb-eth0"), "{rendered}");
		assert!(!rendered.contains("ingress_redirect"), "{rendered}");
		assert!(
			rendered.contains("ingress_bandwidth = \"40mbit\""),
			"{rendered}"
		);
	}

	/// **An `ifb` carrying something of its own is refused, not inverted.**
	///
	/// The inversion is only valid for a device that really is the compiler's
	/// output, and nothing in the type says a document came from the compiler.
	/// Here an MTU is put on the derived device after the fact: that is
	/// operator intent the inversion would discard, so the renderer declines
	/// instead -- which is the same reason every other entry on the
	/// unrenderable list exists.
	#[test]
	fn an_ifb_that_is_not_this_compilers_is_refused() {
		let mut document =
			compile("device eth0 { qdisc { kind = \"cake\"; ingress_bandwidth = \"40mbit\" } }\n");
		let ifb = document
			.devices
			.iter_mut()
			.find(|device| device.name == "ifb-eth0")
			.expect("derived");
		ifb.mtu = Some(1500);
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing.iter().any(|what| what.contains("ingress redirect")),
			"{missing:?}"
		);
	}

	/// **The pairing is by name, and that is correctness rather than
	/// paranoia.**
	///
	/// `expand_ingress_shapers` always names the device it makes
	/// `ifb-<shaped>`, so a redirect pointing at a bare `ifb` under any other
	/// name did not come from here -- and inverting it would not round-trip:
	/// the rendered `ingress_bandwidth` recompiles into `ifb-eth0`, which is a
	/// different document from one naming `shaper0`. Without this case,
	/// deleting the name check broke no test at all, which is what put the
	/// case here.
	#[test]
	fn an_ifb_under_another_name_is_refused() {
		let mut document =
			compile("device eth0 { qdisc { kind = \"cake\"; ingress_bandwidth = \"40mbit\" } }\n");
		for device in &mut document.devices {
			if device.name == "ifb-eth0" {
				device.name = "shaper0".to_owned();
			} else if device.ingress_redirect.is_some() {
				device.ingress_redirect = Some("shaper0".to_owned());
			}
		}
		let missing = render(&document, &Overrides::new()).expect_err("refused");
		assert!(
			missing.iter().any(|what| what.contains("shaper0")),
			"{missing:?}"
		);
	}

	/// An address's trailing modifier words, all three and then each alone.
	///
	/// `preferred_lft 0` is the one worth naming: it is how an address is kept
	/// reachable while no longer being chosen as a source, and until now it put
	/// `an address with lifetimes or a peer` on the unrenderable list and
	/// refused the whole save.
	#[test]
	fn an_addresss_modifiers_round_trip() {
		round_trips(
			"interface eth0 {\n\
			 \tconfig = \"192.0.2.1/32 peer 192.0.2.2 preferred_lft 0 valid_lft 3600\"\n\
			 }\n",
		);
		round_trips("interface eth0 { config = \"192.0.2.1/32 peer 192.0.2.2\" }\n");
		round_trips("interface eth0 { config = \"192.0.2.1/24 preferred_lft 0\" }\n");
		round_trips("interface eth0 { config = \"192.0.2.1/24 valid_lft 3600\" }\n");
	}

	/// **An access point that is deliberately open, which is why the `wifi`
	/// block is written unconditionally.** Its security is `Open`, so a
	/// renderer writing the block only for a credential would emit an access
	/// point with no `wifi` block at all -- and the compiler refuses that one,
	/// saying it *"would be open"*. The save would be refused for a document
	/// that was open on purpose and said so.
	#[test]
	fn an_open_access_point_round_trips() {
		round_trips(
			"access_point \"Guests\" {\n\
			 \tdevice = \"wlan0\"\n\
			 \twifi { open = true }\n\
			 }\n",
		);
	}

	/// Every key at once, for the reason the network equivalent gives: these
	/// arrived over several passes and a renderer written per key drops the
	/// ones nobody came back for.
	#[test]
	fn a_fully_populated_access_point_round_trips() {
		round_trips(
			"access_point \"Guest\" {\n\
			 \tdevice = \"wlan1\"\n\
			 \tssid = \"47756573742057692d4669\"\n\
			 \tchannel = 36\n\
			 \tband = \"5\"\n\
			 \tregdom = \"SE\"\n\
			 \thidden = true\n\
			 \twifi { psk = \"@secret:guest\"; proto = \"wpa3\" }\n\
			 \taccess_control { deny = [\"aa:bb:cc:dd:ee:ff\"] }\n\
			 }\n",
		);
	}

	/// **Both station-list policies, because they are one list under two
	/// keys.** The policy is not written as a value anywhere -- it *is* which
	/// key the list is under -- so a renderer that wrote the wrong one would
	/// produce a document that compiles, loads, and inverts the operator's
	/// intent: a deny list of one station read back as an allow list is a
	/// hotspot that admits exactly the station that was banned.
	#[test]
	fn both_station_list_policies_round_trip() {
		for key in ["deny", "allow"] {
			round_trips(&format!(
				"access_point \"H\" {{\n\
				 \tdevice = \"wlan0\"\n\
				 \twifi {{ psk = \"@secret:h\" }}\n\
				 \taccess_control {{ {key} = [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"] }}\n\
				 }}\n"
			));
		}
	}

	/// An access point's PSK is written as the reference it came in as.
	///
	/// **Not against a leak, which the model forecloses**: a [`SecretRef`] is
	/// a provider and a name and holds no value, so no renderer can write a
	/// passphrase it does not have. What this guards is the `@secret:` prefix
	/// itself -- written bare, the name reads back as a *literal* passphrase,
	/// and the access point comes up with the string `ap-psk` as its key. The
	/// round trip cannot see it either way, because both spellings compile to
	/// a credential; only the text distinguishes them.
	#[test]
	fn an_access_points_credential_stays_a_reference() {
		let document = compile(
			"access_point \"Home\" {\n\
			 \tdevice = \"wlan0\"\n\
			 \twifi { psk = \"@secret:ap-psk\" }\n\
			 }\n",
		);
		let rendered = render(&document, &Overrides::new()).expect("rendered");
		assert!(rendered.contains("psk = \"@secret:ap-psk\""), "{rendered}");
	}

	/// **Every secret provider, because three of the four spellings were
	/// written nowhere any test could read them.** `secret_ref` is the one
	/// function every credential in the tree passes through, and it renders
	/// the provider as a prefix: `@secret:keyring:home` and `@secret:home`
	/// name different stores. Only the keyring arm had a case -- the `PPPoE`
	/// password, whose own comment says why -- so a wrong prefix on `pass` or
	/// `exec` would have produced a profile that loads, finds no credential
	/// where it looked, and reports a wifi failure rather than a parse one.
	///
	/// The relationship asserted is distinctness as well as the round trip: a
	/// renderer collapsing two providers to one spelling round-trips happily
	/// if the parser then maps that spelling back to whichever it collapsed
	/// to, and four equal strings would satisfy every individual case.
	#[test]
	fn every_secret_provider_round_trips_distinctly() {
		let mut seen = Vec::new();
		for provider in ["", "keyring:", "pass:", "exec:"] {
			let text = format!(
				"access_point \"H\" {{\n\
				 \tdevice = \"wlan0\"\n\
				 \twifi {{ psk = \"@secret:{provider}h\" }}\n\
				 }}\n"
			);
			round_trips(&text);
			let rendered = render(&compile(&text), &Overrides::new()).expect("rendered");
			let line = rendered
				.lines()
				.find(|line| line.contains("psk ="))
				.expect("a psk line")
				.trim()
				.to_owned();
			assert!(
				!seen.contains(&line),
				"two providers rendered alike: {line} already in {seen:?}"
			);
			seen.push(line);
		}
		assert_eq!(seen.len(), 4, "{seen:?}");
	}

	/// An access point the base defines is restated with `override`, which is
	/// the half that lives in `netcfgd-host` and is asserted here because the
	/// renderer is where it is spelled.
	#[test]
	fn an_access_point_is_overridden_where_the_caller_says() {
		let document = compile(
			"access_point \"Home\" {\n\
			 \tdevice = \"wlan0\"\n\
			 \twifi { psk = \"@secret:ap\" }\n\
			 }\n",
		);
		let mut overrides = Overrides::new();
		overrides.insert("access_point Home".to_owned());
		let rendered = render(&document, &overrides).expect("renders");
		assert!(
			rendered.contains("\noverride access_point \"Home\" {"),
			"{rendered}"
		);
	}

	/// A name the kernel allows and the lexer will not read bare.
	///
	/// **Found by the mutation sweep over the example corpus**, which hit a
	/// bond whose `members` named `.th0` -- accepted, because a member is a
	/// string -- and then rendered `device .th0 {`, which does not parse. The
	/// round-trip proof refused the snapshot, which is what it is for; the
	/// operator got no profile.
	///
	/// Deterministic here as well as probabilistic there. The mutation test
	/// reaches this by chance, and only after its digit-aware arm was added --
	/// before that the whole sweep found it once in a run or not at all.
	///
	/// Both names are real: `ip link add .th0 type dummy` succeeds, and so does
	/// `2eth`. A leading digit is an ordinary way to name a mobile interface,
	/// which is the case worth caring about rather than the leading dot.
	#[test]
	fn a_name_the_lexer_cannot_read_bare_is_quoted() {
		for name in [".th0", "2eth", "4g0"] {
			round_trips(&format!(
				"device \"{name}\" {{\n\tmtu = 1400\n}}\n\
				 interface \"{name}\" {{\n\tconfig = \"dhcp\"\n}}\n"
			));
		}
		// The control: a name that IS a bare identifier must stay bare, so a
		// `label` that quoted everything would be caught here rather than
		// quietly rewriting every profile this tree renders. `eth0.42` is the
		// case the lexer's own comment is about.
		for name in ["eth0", "eth0.42", "br-lan", "_x"] {
			let text = format!(
				"device {name} {{\n\tmtu = 1400\n}}\n\
				 interface {name} {{\n\tconfig = \"dhcp\"\n}}\n"
			);
			round_trips(&text);
			let mut sources = crate::SourceMap::new();
			sources.add("bare.conf", &text);
			let document = crate::compile(&sources, &mut crate::NoHooks).expect("it compiles");
			let rendered = render(&document, &Overrides::new()).expect("it renders");
			assert!(
				rendered.contains(&format!("device {name} {{")),
				"`{name}` is a bare identifier and must not be quoted:\n{rendered}"
			);
		}
	}

	/// A network named by its access points says so.
	///
	/// **`None` is a statement, not an absence.** The model is explicit: `None`
	/// means "whatever the access points in `bssid` call themselves" (0090),
	/// while omitting the key makes the SSID the block's label. The renderer
	/// read `None` as nothing to write, so `ssid = "@bssid"` vanished and the
	/// document came back as a network named after its own label --
	/// `ncfg profile save` refused on any machine with a network pinned by
	/// access point, naming the renderer as the fault, which it was.
	///
	/// Found by round-tripping the documents this suite's own tests compile,
	/// which cost nothing to collect: 88 of 90 came back identical and the two
	/// that did not were both this, in
	/// `a_network_can_be_named_by_its_access_points` and
	/// `a_network_can_list_several_access_points`. Neither was wrong; neither
	/// had any reason to ask about the renderer.
	///
	/// The control is the three states kept apart. A label-equal SSID must stay
	/// omitted, because that is what omitting it means and the shorter form is
	/// the faithful one; a different SSID must be stated as hex; and `None`
	/// must be stated as the marker. A renderer that wrote `@bssid` for all
	/// three, or omitted all three, satisfies no two of these at once.
	#[test]
	fn a_network_named_by_its_access_points_says_so() {
		// `None`: the marker has to come back.
		let text = "network \"Lobby\" {\n\
			 \tssid = \"@bssid\"\n\
			 \tbssid = \"aa:bb:cc:dd:ee:ff\"\n\
			 \twifi { psk = \"@secret:l\" }\n\
			 }\n";
		round_trips(text);
		let mut sources = crate::SourceMap::new();
		sources.add("bssid.conf", text);
		let document = crate::compile(&sources, &mut crate::NoHooks).expect("it compiles");
		assert!(
			document.networks[0].ssid.is_none(),
			"the fixture must reach the `None` state, or this tests nothing"
		);
		let rendered = render(&document, &Overrides::new()).expect("it renders");
		assert!(
			rendered.contains("ssid = \"@bssid\""),
			"a network with no stated SSID must say which state that is:\n{rendered}"
		);

		// Label-equal: omitted, because that is what omitting it means.
		let plain = "network \"Cafe\" {\n\twifi { psk = \"@secret:c\" }\n}\n";
		round_trips(plain);
		let mut sources = crate::SourceMap::new();
		sources.add("plain.conf", plain);
		let document = crate::compile(&sources, &mut crate::NoHooks).expect("it compiles");
		let rendered = render(&document, &Overrides::new()).expect("it renders");
		assert!(
			!rendered.contains("ssid ="),
			"an SSID equal to the label is what omitting the key means, so stating \
			 it is noise:\n{rendered}"
		);

		// Stated and different: hex, which is how a name that is not text is
		// written down at all.
		let hex = "network \"Odd\" {\n\
			 \tssid = \"4f6464\"\n\
			 \twifi { psk = \"@secret:o\" }\n\
			 }\n";
		round_trips(hex);
	}

	/// A `device` block with nothing in it is NOT written, and this pins why.
	///
	/// **This case asserted the opposite and the assertion was the defect.** It
	/// read 10.21's "present and empty is not absent" as covering a `device`
	/// block the way it covers `dns { }`, removed `render_device`'s early
	/// return, and broke `ncfg profile save` for any configuration that
	/// declares an interface and no device -- which is the ordinary one. The
	/// document carries a synthesised all-default device per interface and
	/// `overrides` claims it is declared in the base, so the renderer wrote
	/// `override device eth0 { }` for a block the base config never had:
	///
	///     `override device eth0` has nothing to override
	///
	/// Measured on `tests/footprint/etc`, and the agree gate caught it when
	/// this branch was rebased, which is the first time the two programs were
	/// compared with it present.
	///
	/// 10.21's criterion is whether the block carries meaning of its own, and a
	/// `device` block measures as the `global` case rather than the interface
	/// one: it changes no plan, and netcfgd says so itself.
	///
	/// **The written one is now kept, which this used to pin as lost.**
	/// Closing it needed the model to record which devices were DECLARED
	/// rather than synthesised, and 10.438 put `declared` in the wire form on
	/// both sides, so the renderer can tell an invented all-default device
	/// from a written empty one. This is the assertion the pin said it would
	/// become: the block is written, the document round trips whole, and
	/// `round_trip`'s waiver is gone rather than left with nothing to waive.
	#[test]
	fn an_empty_device_block_is_written_when_somebody_wrote_it() {
		let text = "device wlan0 { }\naccess_point \"home\" {\n\
			 \tdevice = \"wlan0\"\n\
			 \twifi { psk = \"@secret:ap\"; proto = \"wpa2\" }\n\
			 }\n";
		let mut sources = crate::SourceMap::new();
		sources.add("empty.conf", text);
		let document = crate::compile(&sources, &mut crate::NoHooks).expect("it compiles");
		assert_eq!(
			document.devices.len(),
			1,
			"the fixture must produce a device, or this tests nothing"
		);

		let rendered = render(&document, &Overrides::new()).expect("it renders");
		assert!(
			rendered.contains("device wlan0"),
			"a device somebody wrote is kept even with nothing in it, since \
			 nothing else here recreates its entry:\n{rendered}"
		);

		// And the whole document round trips, with no waiver: there is
		// nothing left for one to be about.
		round_trip(&document).expect("it round trips");
		let mut back = crate::SourceMap::new();
		back.add("rendered.conf", &rendered);
		let again = crate::compile(&back, &mut crate::NoHooks).expect("it recompiles");
		assert_eq!(again.devices.len(), 1, "the device comes back");
		assert!(again.devices[0].declared.0, "and as one somebody wrote");
		assert_eq!(
			again.access_points.len(),
			1,
			"and the access point that named it is not"
		);
	}
}
