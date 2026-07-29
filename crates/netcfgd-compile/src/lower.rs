//! Turning what was written into what it means.
//!
//! Every diagnostic here can point at the text that caused it, which is why
//! the AST carries spans rather than being lowered as it is parsed.

use crate::ast::{Assignment, Block, Item, Spanned, Value};
use crate::diag::SourceMap;
use crate::diag::{Diagnostic, Diagnostics, Span};
use crate::hook::HookSink;
use crate::merge::Merged;
use crate::provenance::{field_path, interface_path, Provenance};
use netcfgd_model::address::{Delegated, PrefixRef, Static};
use netcfgd_model::device::{Powersave, WifiBackend, WifiDevicePolicy};
use netcfgd_model::dns::{DnsMode, RoutingDomain};
use netcfgd_model::interface::{BondConfig, BridgeConfig, VlanConfig, VlanProtocol};
use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{
	AddressSource, Device, Dhcp4, Dhcp6, DnsPolicy, DnsServer, Document, DriftPolicy, HookPhase,
	HostnamePolicy, Interface, InterfaceKind, Route, Slaac,
};
use netcfgd_model::{EapConfig, EapMethod, SecretProvider, SecretRef, Security, Ssid, WifiNetwork};
use std::net::IpAddr;

/// Lower merged blocks into a document.
///
/// # Errors
///
/// Returns every diagnostic found.
pub fn lower(
	merged: &Merged,
	hooks: &mut dyn HookSink,
	sources: &SourceMap,
	provenance: &mut Provenance,
) -> Result<Document, Diagnostics> {
	let mut diagnostics = Diagnostics::new();
	let mut document = Document::default();

	for assignment in &merged.assignments {
		lower_global_key(&mut document, assignment, &mut diagnostics);
	}

	for block in &merged.blocks {
		match block.head.as_str() {
			"global" => lower_global_block(&mut document, block, &mut diagnostics),
			"device" => {
				if let Some(device) = lower_device(block, &mut diagnostics) {
					document.devices.push(device);
				}
			}
			"interface" => {
				if let Some(interface) =
					lower_interface(block, hooks, &mut diagnostics, sources, provenance)
				{
					provenance.record(sources, interface_path(&interface.name), block.span);
					document.interfaces.push(interface);
				}
			}
			"network" => {
				if let Some(network) = lower_network(block, hooks, &mut diagnostics) {
					provenance.record(sources, format!("network.{}", network.id), block.span);
					document.networks.push(network);
				}
			}
			other => diagnostics.push(
				Diagnostic::new(block.span, format!("unknown top-level block `{other}`"))
					.with_help("the top-level blocks are interface, network, device and global"),
			),
		}
	}

	if diagnostics.is_empty() {
		Ok(document)
	} else {
		Err(diagnostics)
	}
}

fn lower_global_key(document: &mut Document, assignment: &Assignment, diags: &mut Diagnostics) {
	match assignment.key.as_str() {
		"hostname" => {
			if let Some(name) = as_string(&assignment.value, diags) {
				document.globals.hostname_policy = if name == "dhcp" {
					HostnamePolicy::FromDhcp
				} else {
					HostnamePolicy::Static(name)
				};
			}
		}
		"confirm" => {
			if let Some(seconds) = as_u32(&assignment.value, diags) {
				document.globals.confirm_default = Some(seconds);
			}
		}
		"on_drift" => {
			if let Some(policy) = as_drift(&assignment.value, diags) {
				document.globals.on_drift_default = policy;
			}
		}
		"dns" | "dns_search" | "dns_mode" | "dns_domains" => {
			lower_dns_key(&mut document.globals.dns, assignment, diags);
		}
		other => diags.push(Diagnostic::new(
			assignment.span,
			format!("unknown top-level key `{other}`"),
		)),
	}
}

fn lower_global_block(document: &mut Document, block: &Block, diags: &mut Diagnostics) {
	for item in &block.items {
		match item {
			Item::Assignment(assignment) => lower_global_key(document, assignment, diags),
			Item::Block(inner) if inner.head == "dns" => {
				for item in &inner.items {
					if let Item::Assignment(assignment) = item {
						lower_dns_key(&mut document.globals.dns, assignment, diags);
					}
				}
			}
			Item::Block(inner) if inner.head == "control" => {
				for item in &inner.items {
					if let Item::Assignment(assignment) = item {
						lower_control_key(&mut document.globals.control, assignment, diags);
					}
				}
			}
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside `global`", inner.head),
			)),
			Item::Hook(hook) => diags.push(Diagnostic::new(
				hook.span,
				"hooks belong to an interface, not to `global`",
			)),
			Item::Include(include) => diags.push(Diagnostic::new(
				include.span,
				"include was not resolved before compiling",
			)),
		}
	}
}

fn lower_dns_key(policy: &mut DnsPolicy, assignment: &Assignment, diags: &mut Diagnostics) {
	match assignment.key.as_str() {
		// netifrc spells this as a space-separated string, so accept that as
		// well as a list. The two spellings mean exactly the same thing.
		"dns" | "servers" => {
			for word in as_words(&assignment.value, diags) {
				match word.node.parse::<IpAddr>() {
					Ok(addr) => policy.servers.push(DnsServer {
						addr,
						port: None,
						sni: None,
					}),
					Err(_) => diags.push(Diagnostic::new(
						word.span,
						format!("`{}` is not an IP address", word.node),
					)),
				}
			}
		}
		"dns_search" | "search" => {
			for word in as_words(&assignment.value, diags) {
				policy.search.push(word.node);
			}
		}
		"dns_domains" | "domains" => {
			for word in as_words(&assignment.value, diags) {
				// A leading `~` is resolved's spelling for a routing-only
				// domain. Accept it so a config copied from resolved does the
				// same thing, but store the flag rather than the sigil.
				let (suffix, exclusive) = match word.node.strip_prefix('~') {
					Some(rest) => (rest.to_owned(), true),
					None => (word.node.clone(), false),
				};
				policy.domains.push(RoutingDomain { suffix, exclusive });
			}
		}
		"dns_mode" | "mode" => {
			if let Some(name) = as_string(&assignment.value, diags) {
				match dns_mode(&name) {
					Some(mode) => policy.mode = mode,
					None => diags.push(
						Diagnostic::new(
							assignment.value.span,
							format!("unknown dns mode `{name}`"),
						)
						.with_help(
							"one of: none, write_resolv_conf, resolvconf, openresolv, \
							 resolved, dnsmasq, unbound",
						),
					),
				}
			}
		}
		other => diags.push(Diagnostic::new(
			assignment.span,
			format!("unknown dns key `{other}`"),
		)),
	}
}

/// One key of the `control` block.
fn lower_control_key(
	control: &mut netcfgd_model::Control,
	assignment: &Assignment,
	diags: &mut Diagnostics,
) {
	let Some(text) = as_string(&assignment.value, diags) else {
		return;
	};
	let principal = match netcfgd_model::Principal::parse(&text) {
		Ok(principal) => principal,
		Err(message) => {
			diags.push(
				Diagnostic::new(assignment.value.span, message)
					.with_help("for example: group:netdev, user:alice, any, root"),
			);
			return;
		}
	};
	match assignment.key.as_str() {
		"observe" => control.observe = principal,
		"wifi" => control.wifi = principal,
		"admin" => control.admin = principal,
		other => diags.push(
			Diagnostic::new(assignment.span, format!("unknown control key `{other}`"))
				.with_help("the tiers are observe, wifi and admin"),
		),
	}
}

fn dns_mode(name: &str) -> Option<DnsMode> {
	Some(match name {
		"none" => DnsMode::None,
		"write_resolv_conf" | "resolv.conf" => DnsMode::WriteResolvConf,
		"resolvconf" => DnsMode::Resolvconf,
		"openresolv" => DnsMode::Openresolv,
		"resolved" => DnsMode::Resolved,
		"dnsmasq" => DnsMode::Dnsmasq,
		"unbound" => DnsMode::Unbound,
		_ => return None,
	})
}

fn lower_device(block: &Block, diags: &mut Diagnostics) -> Option<Device> {
	let name = require_label(block, diags)?;
	let mut device = Device {
		name,
		r#match: None,
		managed: true,
		wifi: None,
	};

	for item in &block.items {
		match item {
			Item::Assignment(assignment) if assignment.key == "managed" => {
				if let Some(flag) = as_bool(&assignment.value, diags) {
					device.managed = flag;
				}
			}
			Item::Assignment(assignment) => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown device key `{}`", assignment.key),
			)),
			Item::Block(inner) if inner.head == "wifi" => {
				device.wifi = Some(lower_wifi_device(inner, diags));
			}
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside `device`", inner.head),
			)),
			Item::Hook(hook) => diags.push(Diagnostic::new(
				hook.span,
				"hooks belong to an interface, not to a device",
			)),
			Item::Include(include) => diags.push(Diagnostic::new(
				include.span,
				"include was not resolved before compiling",
			)),
		}
	}

	Some(device)
}

/// A `wifi` block inside `device`: how the radio behaves, not what it joins.
fn lower_wifi_device(block: &Block, diags: &mut Diagnostics) -> WifiDevicePolicy {
	let mut policy = WifiDevicePolicy::default();

	for item in &block.items {
		match item {
			Item::Assignment(assignment) => match assignment.key.as_str() {
				"backend" => {
					if let Some(name) = as_string(&assignment.value, diags) {
						match name.as_str() {
							"auto" => policy.backend = WifiBackend::Auto,
							"wpa_supplicant" => policy.backend = WifiBackend::WpaSupplicant,
							// Accepted by the compiler and refused at use, so
							// the diagnostic can explain the reason rather
							// than reading as a typo. Decision 0014: iwd keeps
							// its own network database, which cannot be
							// reconciled against.
							"iwd" => policy.backend = WifiBackend::Iwd,
							other => diags.push(
								Diagnostic::new(
									assignment.span,
									format!("`{other}` is not a wifi backend"),
								)
								.with_help("one of auto, wpa_supplicant, iwd"),
							),
						}
					}
				}
				"autoconnect" => {
					if let Some(flag) = as_bool(&assignment.value, diags) {
						policy.autoconnect = flag;
					}
				}
				"portal_check" => {
					if let Some(flag) = as_bool(&assignment.value, diags) {
						policy.portal_check = flag;
					}
				}
				"regdom" => {
					if let Some(code) = as_string(&assignment.value, diags) {
						// Two letters, because a regulatory domain that is not
						// one is silently ignored by the kernel -- and a radio
						// quietly using the world-roaming defaults is a
						// difficult thing to notice.
						if code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase()) {
							policy.regdom = Some(code);
						} else {
							diags.push(
								Diagnostic::new(
									assignment.span,
									format!("`{code}` is not a regulatory domain"),
								)
								.with_help("an ISO 3166-1 alpha-2 code in capitals, such as SE"),
							);
						}
					}
				}
				"powersave" => {
					if let Some(name) = as_string(&assignment.value, diags) {
						match name.as_str() {
							"default" => policy.powersave = Powersave::Default,
							"on" => policy.powersave = Powersave::On,
							"off" => policy.powersave = Powersave::Off,
							other => diags.push(
								Diagnostic::new(
									assignment.span,
									format!("`{other}` is not a powersave setting"),
								)
								.with_help("one of default, on, off"),
							),
						}
					}
				}
				other => diags.push(Diagnostic::new(
					assignment.span,
					format!("unknown wifi device key `{other}`"),
				)),
			},
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside a device `wifi` block", inner.head),
			)),
			Item::Hook(hook) => diags.push(Diagnostic::new(
				hook.span,
				"hooks belong to an interface or a network, not to a radio",
			)),
			Item::Include(include) => diags.push(Diagnostic::new(
				include.span,
				"include was not resolved before compiling",
			)),
		}
	}

	policy
}

/// One `key = value` directly inside a `network` block.
fn lower_network_key(network: &mut WifiNetwork, assignment: &Assignment, diags: &mut Diagnostics) {
	match assignment.key.as_str() {
		"config" => {
			for entry in address_entries(&assignment.value, diags) {
				if let Some(source) = address_source(&entry, diags) {
					network.addressing.push(source);
				}
			}
		}
		"routes" => {
			for line in as_lines(&assignment.value, diags) {
				if let Some(route) = parse_route(&line, diags) {
					network.routes.push(route);
				}
			}
		}
		"hidden" => {
			if let Some(flag) = as_bool(&assignment.value, diags) {
				network.hidden = flag;
			}
		}
		"metered" => {
			if let Some(flag) = as_bool(&assignment.value, diags) {
				network.metered = flag;
			}
		}
		"ssid" => {
			// The escape hatch for a name that is not text, given as hex. The
			// label stays the id, so the network still has one readable
			// handle.
			if let Some(text) = as_string(&assignment.value, diags) {
				match Ssid::from_hex(&text) {
					Ok(ssid) => network.ssid = ssid,
					Err(error) => diags.push(Diagnostic::new(
						assignment.span,
						format!("`{text}` is not a usable ssid: {error}"),
					)),
				}
			}
		}
		"bssid" => {
			if let Some(text) = as_string(&assignment.value, diags) {
				network.bssid_pin = Some(text);
			}
		}
		other => diags.push(Diagnostic::new(
			assignment.span,
			format!("unknown network key `{other}`"),
		)),
	}
}

/// A `network` block: an SSID profile, not bound to a device.
fn lower_network(
	block: &Block,
	hooks: &mut dyn HookSink,
	diags: &mut Diagnostics,
) -> Option<WifiNetwork> {
	let label = require_label(block, diags)?;

	// The label is the SSID as written, and it is also the id. That is not a
	// shortcut: an SSID is what the operator recognises, and giving a network
	// a separate handle would mean two names for one thing in every
	// diagnostic. A profile for a name that is not text uses `ssid` below.
	let ssid = match Ssid::new(label.as_bytes().to_vec()) {
		Ok(ssid) => ssid,
		Err(error) => {
			diags.push(Diagnostic::new(
				block.span,
				format!("`{label}` cannot be a network name: {error}"),
			));
			return None;
		}
	};

	let mut network = WifiNetwork {
		id: label.clone(),
		ssid,
		hidden: false,
		security: Security::Open,
		priority: 0,
		autoconnect: true,
		metered: false,
		bssid_pin: None,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
	};
	let mut security_seen = false;

	for item in &block.items {
		match item {
			Item::Assignment(assignment) => {
				lower_network_key(&mut network, assignment, diags);
			}
			Item::Block(inner) if inner.head == "wifi" => {
				security_seen = true;
				lower_network_wifi(inner, &mut network, diags);
			}
			Item::Block(inner) if inner.head == "dns" => {
				let mut policy = DnsPolicy::default();
				for item in &inner.items {
					if let Item::Assignment(assignment) = item {
						lower_dns_key(&mut policy, assignment, diags);
					}
				}
				network.dns = Some(policy);
			}
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside `network`", inner.head),
			)),
			Item::Hook(hook) => match hook_phase(&hook.phase) {
				Some(phase) => match hooks.materialise(phase, &label, &hook.body) {
					Ok(reference) => network.hooks.push(reference),
					Err(message) => diags.push(Diagnostic::new(hook.span, message)),
				},
				None => diags.push(
					Diagnostic::new(hook.span, format!("unknown hook phase `{}`", hook.phase))
						.with_help(
							"phases: pre_up, up, post_up, pre_down, down, post_down, \
							 and `on` with carrier, lease, roam, portal or drift",
						),
				),
			},
			Item::Include(include) => diags.push(Diagnostic::new(
				include.span,
				"include was not resolved before compiling",
			)),
		}
	}

	// An open network is a real thing, but it is almost never what somebody
	// meant to write, and joining one silently is how a laptop ends up
	// associating with anything calling itself the same name. Saying so costs
	// one line in the config for the cases that are deliberate.
	if !security_seen {
		diags.push(
			Diagnostic::new(
				block.span,
				format!("`{label}` has no `wifi` block, so it is an open network"),
			)
			.with_help(
				"add `wifi { psk = \"@secret:NAME\" }`, or `wifi { open = true }` if that is meant",
			),
		);
		return None;
	}

	Some(network)
}

/// The keys a network's `wifi` block can carry, before they become a
/// [`Security`].
///
/// Collected first and interpreted second, because which fields matter depends
/// on which kind of security was named -- and that may be named after them.
#[derive(Default)]
struct WifiKeys {
	psk: Option<SecretRef>,
	proto: PskProto,
	open: bool,
	owe: bool,
	eap: Option<EapMethod>,
	identity: Option<String>,
	anonymous_identity: Option<String>,
	password: Option<SecretRef>,
	ca_cert: Option<String>,
	client_cert: Option<String>,
	private_key: Option<SecretRef>,
	phase2: Option<String>,
}

/// The `wifi` block inside a `network`: how to authenticate to it.
fn lower_network_wifi(block: &Block, network: &mut WifiNetwork, diags: &mut Diagnostics) {
	let mut keys = WifiKeys::default();

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			if let Item::Block(inner) = item {
				diags.push(Diagnostic::new(
					inner.span,
					format!(
						"`{}` is not valid inside a network `wifi` block",
						inner.head
					),
				));
			}
			continue;
		};
		lower_wifi_key(&mut keys, network, assignment, diags);
	}

	// Exactly one kind of security. Two would mean guessing which the operator
	// meant, and the wrong guess is a network that either will not join or
	// joins with less protection than was asked for.
	let chosen = usize::from(keys.psk.is_some())
		+ usize::from(keys.eap.is_some())
		+ usize::from(keys.open)
		+ usize::from(keys.owe);
	if chosen > 1 {
		diags.push(
			Diagnostic::new(block.span, "a network has one kind of security")
				.with_help("exactly one of psk, eap, open or owe"),
		);
		return;
	}

	if let Some(security) = build_security(keys, block, diags) {
		network.security = security;
	}
}

/// One `key = value` inside a network's `wifi` block.
fn lower_wifi_key(
	keys: &mut WifiKeys,
	network: &mut WifiNetwork,
	assignment: &Assignment,
	diags: &mut Diagnostics,
) {
	match assignment.key.as_str() {
		"psk" => keys.psk = as_secret(&assignment.value, diags),
		"password" => keys.password = as_secret(&assignment.value, diags),
		"private_key" => keys.private_key = as_secret(&assignment.value, diags),
		"open" => keys.open = as_bool(&assignment.value, diags).unwrap_or(false),
		"owe" => keys.owe = as_bool(&assignment.value, diags).unwrap_or(false),
		"identity" => keys.identity = as_string(&assignment.value, diags),
		"anonymous_identity" => keys.anonymous_identity = as_string(&assignment.value, diags),
		"ca_cert" => keys.ca_cert = as_string(&assignment.value, diags),
		"client_cert" => keys.client_cert = as_string(&assignment.value, diags),
		"phase2" => keys.phase2 = as_string(&assignment.value, diags),
		"priority" => {
			if let Some(value) = as_u32(&assignment.value, diags) {
				network.priority = i32::try_from(value).unwrap_or(i32::MAX);
			}
		}
		"autoconnect" => {
			if let Some(flag) = as_bool(&assignment.value, diags) {
				network.autoconnect = flag;
			}
		}
		"proto" => {
			if let Some(name) = as_string(&assignment.value, diags) {
				match name.as_str() {
					"wpa2" => keys.proto = PskProto::Wpa2,
					"wpa3" => keys.proto = PskProto::Wpa3,
					"wpa2+wpa3" | "wpa2wpa3" => keys.proto = PskProto::Wpa2Wpa3,
					other => diags.push(
						Diagnostic::new(
							assignment.span,
							format!("`{other}` is not a WPA generation"),
						)
						.with_help("one of wpa2, wpa3, wpa2+wpa3"),
					),
				}
			}
		}
		"eap" => {
			if let Some(name) = as_string(&assignment.value, diags) {
				match name.as_str() {
					"peap" => keys.eap = Some(EapMethod::Peap),
					"ttls" => keys.eap = Some(EapMethod::Ttls),
					"tls" => keys.eap = Some(EapMethod::Tls),
					"pwd" => keys.eap = Some(EapMethod::Pwd),
					other => diags.push(
						Diagnostic::new(assignment.span, format!("`{other}` is not an EAP method"))
							.with_help("one of peap, ttls, tls, pwd"),
					),
				}
			}
		}
		other => diags.push(Diagnostic::new(
			assignment.span,
			format!("unknown wifi key `{other}`"),
		)),
	}
}

/// Turn the collected keys into the one security mode they describe.
fn build_security(keys: WifiKeys, block: &Block, diags: &mut Diagnostics) -> Option<Security> {
	if let Some(passphrase) = keys.psk {
		return Some(Security::Psk(PskConfig {
			passphrase,
			proto: keys.proto,
		}));
	}
	if let Some(method) = keys.eap {
		let Some(identity) = keys.identity else {
			diags.push(Diagnostic::new(
				block.span,
				"an EAP network needs an `identity`",
			));
			return None;
		};
		if keys.ca_cert.is_none() {
			// Not an error, because plenty of real deployments pin nothing and
			// refusing would make netcfgd unusable on them. But an EAP network
			// with no CA certificate will authenticate to any server that
			// answers, which is the whole attack -- so it is said out loud
			// rather than left for somebody to notice.
			diags.push(
				Diagnostic::new(
					block.span,
					"this EAP network has no `ca_cert`, so it will trust any server that answers",
				)
				.with_help("set `ca_cert` to the issuer's certificate; see docs/decisions/0008"),
			);
		}
		return Some(Security::Eap(EapConfig {
			method,
			identity,
			anonymous_identity: keys.anonymous_identity,
			password: keys.password,
			ca_cert: keys.ca_cert,
			client_cert: keys.client_cert,
			private_key: keys.private_key,
			phase2: keys.phase2,
		}));
	}
	if keys.owe {
		return Some(Security::Owe);
	}
	Some(Security::Open)
}

/// `"@secret:NAME"` or `"@secret:provider:NAME"`.
fn as_secret(value: &Spanned<Value>, diags: &mut Diagnostics) -> Option<SecretRef> {
	let text = as_string(value, diags)?;
	let Some(rest) = text.strip_prefix("@secret:") else {
		// The whole point of the indirection is that a config file stays safe
		// to commit. Accepting a bare string here would make that a convention
		// rather than a property, and the first person to paste a passphrase
		// in would find it works.
		diags.push(
			Diagnostic::new(value.span, "a credential must be a secret reference").with_help(
				"write `@secret:NAME`; `ncfg secret set NAME` stores the value outside \
					 the config, which is what keeps the config safe to commit",
			),
		);
		return None;
	};
	let (provider, name) = match rest.split_once(':') {
		Some((provider, name)) => (provider, name),
		None => ("file", rest),
	};
	let provider = match provider {
		"file" => SecretProvider::File,
		"exec" => SecretProvider::Exec,
		"keyring" => SecretProvider::Keyring,
		"pass" => SecretProvider::Pass,
		other => {
			diags.push(
				Diagnostic::new(value.span, format!("`{other}` is not a secret provider"))
					.with_help("one of file, exec, keyring, pass"),
			);
			return None;
		}
	};
	if name.is_empty() {
		diags.push(Diagnostic::new(
			value.span,
			"a secret reference needs a name",
		));
		return None;
	}
	Some(SecretRef {
		provider,
		name: name.to_owned(),
	})
}

#[allow(clippy::too_many_lines)]
fn lower_interface(
	block: &Block,
	hooks: &mut dyn HookSink,
	diags: &mut Diagnostics,
	sources: &SourceMap,
	provenance: &mut Provenance,
) -> Option<Interface> {
	let name = require_label(block, diags)?;
	let mut interface = Interface {
		name: name.clone(),
		kind: InterfaceKind::Physical,
		enabled: true,
		mtu: None,
		mac: None,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
		on_drift: None,
		master: None,
		dot1x: None,
		advertise: None,
		forwarding: None,
		guard: None,
	};
	let mut dns = DnsPolicy::default();
	let mut dns_touched = false;

	for item in &block.items {
		match item {
			Item::Assignment(assignment) => match assignment.key.as_str() {
				"config" => {
					for entry in address_entries(&assignment.value, diags) {
						if let Some(source) = address_source(&entry, diags) {
							provenance.record(
								sources,
								field_path(
									&name,
									&format!("addressing[{}]", interface.addressing.len()),
								),
								entry.span,
							);
							interface.addressing.push(source);
						}
					}
				}
				"routes" => {
					for line in as_lines(&assignment.value, diags) {
						if let Some(route) = parse_route(&line, diags) {
							provenance.record(
								sources,
								field_path(&name, &format!("routes[{}]", route.destination)),
								line.span,
							);
							interface.routes.push(route);
						}
					}
				}
				"mtu" => {
					provenance.record(sources, field_path(&name, "mtu"), assignment.span);
					interface.mtu = as_u32(&assignment.value, diags);
				}
				"mac" => interface.mac = as_string(&assignment.value, diags),
				"enabled" => {
					if let Some(flag) = as_bool(&assignment.value, diags) {
						interface.enabled = flag;
					}
				}
				"master" => interface.master = as_string(&assignment.value, diags),
				"forwarding" => interface.forwarding = as_bool(&assignment.value, diags),
				"on_drift" => interface.on_drift = as_drift(&assignment.value, diags),
				"guard" => {
					provenance.record(sources, field_path(&name, "guard"), assignment.span);
					interface.guard = as_string(&assignment.value, diags)
						.map(|reason| netcfgd_model::Guard { reason });
				}
				"dns" | "dns_search" | "dns_mode" | "dns_domains" => {
					dns_touched = true;
					provenance.record(sources, field_path(&name, "dns"), assignment.span);
					lower_dns_key(&mut dns, assignment, diags);
				}
				other => diags.push(Diagnostic::new(
					assignment.span,
					format!("unknown interface key `{other}`"),
				)),
			},
			Item::Block(inner) => match inner.head.as_str() {
				"vlan" => {
					if let Some(kind) = lower_vlan(inner, diags) {
						interface.kind = kind;
					}
				}
				"bridge" => interface.kind = lower_bridge(inner, diags),
				"bond" => {
					if let Some(kind) = lower_bond(inner, diags) {
						interface.kind = kind;
					}
				}
				"dns" => {
					dns_touched = true;
					for item in &inner.items {
						if let Item::Assignment(assignment) = item {
							lower_dns_key(&mut dns, assignment, diags);
						}
					}
				}
				"wireguard" => diags.push(
					Diagnostic::new(inner.span, "wireguard is not supported by this build")
						.with_help("`wireguard` blocks land in M4; see project.md section 7"),
				),
				other => diags.push(Diagnostic::new(
					inner.span,
					format!("`{other}` is not valid inside `interface`"),
				)),
			},
			Item::Hook(hook) => match hook_phase(&hook.phase) {
				Some(phase) => match hooks.materialise(phase, &name, &hook.body) {
					Ok(reference) => interface.hooks.push(reference),
					Err(message) => diags.push(Diagnostic::new(hook.span, message)),
				},
				None => diags.push(
					Diagnostic::new(hook.span, format!("unknown hook phase `{}`", hook.phase))
						.with_help(
							"phases: pre_up, up, post_up, pre_down, down, post_down, \
							 and `on` with carrier, lease, roam, portal or drift",
						),
				),
			},
			Item::Include(include) => diags.push(Diagnostic::new(
				include.span,
				"include was not resolved before compiling",
			)),
		}
	}

	if dns_touched {
		interface.dns = Some(dns);
	}
	Some(interface)
}

fn lower_vlan(block: &Block, diags: &mut Diagnostics) -> Option<InterfaceKind> {
	let mut parent = None;
	let mut id = None;
	let mut protocol = VlanProtocol::Dot1q;

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		match assignment.key.as_str() {
			"parent" => parent = as_string(&assignment.value, diags),
			"id" => {
				id = as_u32(&assignment.value, diags).and_then(|n| u16::try_from(n).ok());
				if id.is_none() {
					diags.push(Diagnostic::new(
						assignment.value.span,
						"vlan id must be between 0 and 4095",
					));
				}
			}
			"protocol" => {
				if let Some(name) = as_string(&assignment.value, diags) {
					match name.as_str() {
						"dot1q" | "802.1q" => protocol = VlanProtocol::Dot1q,
						"dot1ad" | "802.1ad" => protocol = VlanProtocol::Dot1ad,
						other => diags.push(Diagnostic::new(
							assignment.value.span,
							format!("unknown vlan protocol `{other}`"),
						)),
					}
				}
			}
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown vlan key `{other}`"),
			)),
		}
	}

	let (Some(parent), Some(id)) = (parent, id) else {
		diags.push(
			Diagnostic::new(block.span, "a vlan needs both `parent` and `id`")
				.with_help("for example: vlan { parent = \"eth0\"; id = 10 }"),
		);
		return None;
	};
	Some(InterfaceKind::Vlan(VlanConfig {
		parent,
		id,
		protocol,
	}))
}

fn lower_bridge(block: &Block, diags: &mut Diagnostics) -> InterfaceKind {
	let mut config = BridgeConfig::default();
	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		match assignment.key.as_str() {
			"members" => {
				config.members = as_words(&assignment.value, diags)
					.into_iter()
					.map(|w| w.node)
					.collect();
			}
			"stp" => {
				if let Some(flag) = as_bool(&assignment.value, diags) {
					config.stp = flag;
				}
			}
			"forward_delay" => config.forward_delay = as_u32(&assignment.value, diags),
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown bridge key `{other}`"),
			)),
		}
	}
	InterfaceKind::Bridge(config)
}

fn lower_bond(block: &Block, diags: &mut Diagnostics) -> Option<InterfaceKind> {
	let mut members = Vec::new();
	let mut mode = None;
	let mut miimon = None;

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		match assignment.key.as_str() {
			"members" => {
				members = as_words(&assignment.value, diags)
					.into_iter()
					.map(|w| w.node)
					.collect();
			}
			"mode" => mode = as_string(&assignment.value, diags),
			"miimon" => miimon = as_u32(&assignment.value, diags),
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown bond key `{other}`"),
			)),
		}
	}

	let Some(mode) = mode else {
		diags.push(Diagnostic::new(block.span, "a bond needs a `mode`"));
		return None;
	};
	Some(InterfaceKind::Bond(BondConfig {
		members,
		mode,
		miimon,
	}))
}

fn hook_phase(name: &str) -> Option<HookPhase> {
	Some(match name {
		"pre_up" => HookPhase::PreUp,
		"up" => HookPhase::Up,
		"post_up" => HookPhase::PostUp,
		"pre_down" => HookPhase::PreDown,
		"down" => HookPhase::Down,
		"post_down" => HookPhase::PostDown,
		"carrier" => HookPhase::Carrier,
		"lease" => HookPhase::Lease,
		"roam" => HookPhase::Roam,
		"portal" => HookPhase::Portal,
		"drift" => HookPhase::Drift,
		_ => return None,
	})
}

/// One addressing entry: a head, plus the modifier words that follow it.
#[derive(Debug, Clone)]
pub struct AddressEntry {
	/// The address or keyword.
	head: String,
	/// `(keyword, argument)` pairs following it.
	modifiers: Vec<(String, Option<String>)>,
}

/// Modifier keywords and how many words each consumes after itself.
///
/// This table is what makes splitting unambiguous. Without it,
/// `192.168.0.2 netmask 255.255.255.0` splits into two addresses, because the
/// netmask is itself address-shaped. Taken from net.example's documented
/// forms.
const MODIFIERS: &[(&str, usize)] = &[
	("netmask", 1),
	("peer", 1),
	("pointopoint", 1),
	("scope", 1),
	("brd", 1),
	("broadcast", 1),
	("label", 1),
	("metric", 1),
	("preferred_lft", 1),
	("valid_lft", 1),
	("nodad", 0),
	("home", 0),
	("mngtmpaddr", 0),
	("noprefixroute", 0),
];

fn modifier_arity(word: &str) -> Option<usize> {
	MODIFIERS
		.iter()
		.find(|(name, _)| *name == word)
		.map(|(_, arity)| *arity)
}

/// Whether a word begins a new addressing entry.
fn starts_entry(word: &str) -> bool {
	matches!(
		word,
		"dhcp"
			| "dhcp4" | "dhcpv6"
			| "dhcp6" | "slaac"
			| "link-local"
			| "link_local"
			| "null" | "noop"
	) || word.starts_with("@pd:")
		|| word
			.split('/')
			.next()
			.is_some_and(|head| head.parse::<IpAddr>().is_ok())
}

/// Split a `config` value into entries.
///
/// netifrc separates addresses with **spaces**, and uses newlines only when an
/// entry carries modifiers that themselves contain spaces:
///
/// ```text
/// config_eth0="192.168.0.2/24 192.168.0.3/24 192.168.0.4/24"
/// config_eth0="192.168.0.2/24 scope host
/// 4321:0:1:2:3:4:567:89ab/64 nodad home preferred_lft 0"
/// ```
///
/// Splitting on newlines alone -- which this did until a real config failed to
/// compile -- treats the first line as one malformed address. Both separators
/// are honoured here, with [`MODIFIERS`] deciding where an entry really ends.
fn address_entries(value: &Spanned<Value>, diags: &mut Diagnostics) -> Vec<Spanned<AddressEntry>> {
	let mut out = Vec::new();
	for line in as_lines(value, diags) {
		let words: Vec<&str> = line.node.split_whitespace().collect();
		let mut index = 0;
		let mut current: Option<AddressEntry> = None;

		while index < words.len() {
			let word = words[index];
			if let Some(arity) = modifier_arity(word) {
				let argument = if arity == 0 {
					None
				} else {
					index += 1;
					if let Some(argument) = words.get(index) {
						Some((*argument).to_owned())
					} else {
						diags.push(Diagnostic::new(
							line.span,
							format!("`{word}` needs a value"),
						));
						break;
					}
				};
				if let Some(entry) = &mut current {
					entry.modifiers.push((word.to_owned(), argument));
				} else {
					diags.push(Diagnostic::new(
						line.span,
						format!("`{word}` has no address to apply to"),
					));
				}
			} else if starts_entry(word) {
				if let Some(entry) = current.take() {
					out.push(Spanned::new(entry, line.span));
				}
				current = Some(AddressEntry {
					head: word.to_owned(),
					modifiers: Vec::new(),
				});
			} else {
				diags.push(
					Diagnostic::new(line.span, format!("`{word}` is not an address or keyword"))
						.with_help(
							"an entry is an address, or one of dhcp, dhcp6, slaac, link-local",
						),
				);
			}
			index += 1;
		}
		if let Some(entry) = current {
			out.push(Spanned::new(entry, line.span));
		}
	}
	out
}

/// An IPv4 netmask as a prefix length, rejecting a non-contiguous one.
fn netmask_to_prefix(text: &str) -> Option<u8> {
	let mask: std::net::Ipv4Addr = text.parse().ok()?;
	let bits = u32::from_be_bytes(mask.octets());
	let ones = bits.leading_ones();
	// 255.0.255.0 has four leading ones and is not a mask. Rebuilding from the
	// count and comparing is the cheapest way to insist it is contiguous.
	let rebuilt = if ones == 0 {
		0
	} else {
		u32::MAX << (32 - ones)
	};
	if rebuilt != bits {
		return None;
	}
	u8::try_from(ones).ok()
}

/// One entry of a `config` value.
fn address_source(entry: &Spanned<AddressEntry>, diags: &mut Diagnostics) -> Option<AddressSource> {
	let text = entry.node.head.trim();
	match text {
		"dhcp" | "dhcp4" => return Some(AddressSource::Dhcp4(Dhcp4::default())),
		"dhcp6" | "dhcpv6" => return Some(AddressSource::Dhcp6(Dhcp6::default())),
		"slaac" => return Some(AddressSource::Slaac(Slaac::default())),
		"link-local" | "link_local" => return Some(AddressSource::LinkLocal),
		// netifrc's "no address at all", used on bridge members. An empty
		// addressing list is already legal (decision 0006 rule 6), so this
		// contributes nothing rather than being an error.
		"null" => return None,
		// "keep whatever is already there" cannot be expressed by a
		// reconciler: there is no state to converge on, so every run would
		// have to decide afresh what it meant.
		"noop" => {
			diags.push(
				Diagnostic::new(entry.span, "`noop` has no meaning in a reconciled model")
					.with_help(
						"state what the interface should have; an empty config keeps nothing",
					),
			);
			return None;
		}
		_ => {}
	}

	// `@pd:wan0` and `@pd:wan0/2` are the DSL spelling of a delegated prefix,
	// matching `@secret:` in shape because both are indirections the document
	// carries instead of a value.
	if let Some(rest) = text.strip_prefix("@pd:") {
		let (source, suffix) = rest.split_once('=').unwrap_or((rest, "::1/64"));
		let (source, subnet) = match source.split_once('/') {
			Some((name, index)) => {
				if let Ok(subnet) = index.parse::<u16>() {
					(name, subnet)
				} else {
					diags.push(Diagnostic::new(
						entry.span,
						format!("`{index}` is not a subnet number"),
					));
					return None;
				}
			}
			None => (source, 0),
		};
		return Some(AddressSource::Delegated(Delegated {
			prefix: PrefixRef {
				source: source.to_owned(),
				index: 0,
				subnet,
			},
			suffix: suffix.to_owned(),
		}));
	}

	let mut address = text.to_owned();
	let mut peer = None;
	let mut preferred_lifetime = None;
	let mut valid_lifetime = None;

	for (keyword, argument) in &entry.node.modifiers {
		match (keyword.as_str(), argument.as_deref()) {
			("netmask", Some(mask)) => {
				// netifrc's pre-CIDR spelling. Converting rather than refusing
				// costs fifteen lines and is the second form net.example
				// documents, so a converted config is likelier to work.
				let Some(prefix) = netmask_to_prefix(mask) else {
					diags.push(Diagnostic::new(
						entry.span,
						format!("`{mask}` is not a contiguous netmask"),
					));
					return None;
				};
				if address.contains('/') {
					diags.push(Diagnostic::new(
						entry.span,
						"an address may carry a prefix length or a netmask, not both",
					));
					return None;
				}
				address = format!("{address}/{prefix}");
			}
			("peer" | "pointopoint", Some(value)) => peer = Some(value.to_owned()),
			("preferred_lft", Some(value)) => {
				if !set_lifetime(&mut preferred_lifetime, value, entry.span, diags) {
					return None;
				}
			}
			("valid_lft", Some(value)) => {
				if !set_lifetime(&mut valid_lifetime, value, entry.span, diags) {
					return None;
				}
			}
			(other, _) => {
				// Recognised, and not silently dropped. Section 2's rule about
				// unknown fields applies to the language too: acting on a
				// subset of what the author wrote is the failure mode.
				diags.push(
					Diagnostic::new(
						entry.span,
						format!("`{other}` is not supported by this build"),
					)
					.with_help("supported modifiers: netmask, peer, preferred_lft, valid_lft"),
				);
				return None;
			}
		}
	}

	// A bare address with no prefix and no netmask is still an error, and the
	// message says which of the two spellings to reach for.
	check_cidr(&address, entry.span, diags)?;
	Some(AddressSource::Static(Static {
		address,
		peer,
		preferred_lifetime,
		valid_lifetime,
	}))
}

/// Set a lifetime, where netifrc's `forever` means "no limit" and so leaves
/// the slot empty. Returns false if the value was not a lifetime at all.
///
/// A slot rather than a return value because "forever" and "failed" are both
/// absences, and `Option<Option<u32>>` makes the caller decide which is which
/// on every line.
fn set_lifetime(slot: &mut Option<u32>, text: &str, span: Span, diags: &mut Diagnostics) -> bool {
	if text == "forever" {
		*slot = None;
		return true;
	}
	if let Ok(seconds) = text.parse::<u32>() {
		*slot = Some(seconds);
		true
	} else {
		diags.push(Diagnostic::new(
			span,
			format!("`{text}` is not a number of seconds"),
		));
		false
	}
}

/// Reject an address that is not `IP/prefixlen` here rather than at apply
/// time, when the interface is half configured.
fn check_cidr(text: &str, span: Span, diags: &mut Diagnostics) -> Option<()> {
	let Some((addr, prefix)) = text.split_once('/') else {
		diags.push(
			Diagnostic::new(span, format!("`{text}` is not an address"))
				.with_help("write an address with a prefix length, or one of dhcp, dhcp6, slaac"),
		);
		return None;
	};
	let Ok(parsed) = addr.parse::<IpAddr>() else {
		diags.push(Diagnostic::new(
			span,
			format!("`{addr}` is not an IP address"),
		));
		return None;
	};
	let max = if parsed.is_ipv4() { 32 } else { 128 };
	match prefix.parse::<u8>() {
		Ok(length) if u32::from(length) <= max => Some(()),
		_ => {
			diags.push(Diagnostic::new(
				span,
				format!("prefix length `{prefix}` is not between 0 and {max}"),
			));
			None
		}
	}
}

/// One entry of a `routes` value: `default via 10.0.0.1 metric 100`.
fn parse_route(entry: &Spanned<String>, diags: &mut Diagnostics) -> Option<Route> {
	let mut words = entry.node.split_whitespace();
	let destination = words.next()?.to_owned();
	let mut route = Route {
		destination,
		via: None,
		metric: None,
		table: None,
		src: None,
		scope: None,
		onlink: false,
		proto: None,
	};

	while let Some(word) = words.next() {
		match word {
			"via" => {
				if let Some(Ok(addr)) = words.next().map(str::parse::<IpAddr>) {
					route.via = Some(addr);
				} else {
					diags.push(Diagnostic::new(entry.span, "`via` needs an IP address"));
					return None;
				}
			}
			"metric" => {
				if let Some(Ok(metric)) = words.next().map(str::parse::<u32>) {
					route.metric = Some(metric);
				} else {
					diags.push(Diagnostic::new(entry.span, "`metric` needs a number"));
					return None;
				}
			}
			"table" => {
				if let Some(Ok(table)) = words.next().map(str::parse::<u32>) {
					route.table = Some(table);
				} else {
					diags.push(Diagnostic::new(entry.span, "`table` needs a number"));
					return None;
				}
			}
			"src" => {
				if let Some(Ok(addr)) = words.next().map(str::parse::<IpAddr>) {
					route.src = Some(addr);
				} else {
					diags.push(Diagnostic::new(entry.span, "`src` needs an IP address"));
					return None;
				}
			}
			"onlink" => route.onlink = true,
			other => {
				diags.push(
					Diagnostic::new(entry.span, format!("unknown route keyword `{other}`"))
						.with_help("keywords: via, metric, table, src, onlink"),
				);
				return None;
			}
		}
	}

	Some(route)
}

fn require_label(block: &Block, diags: &mut Diagnostics) -> Option<String> {
	if let Some(label) = &block.label {
		Some(label.clone())
	} else {
		diags.push(Diagnostic::new(
			block.span,
			format!("`{}` needs a name", block.head),
		));
		None
	}
}

fn as_string(value: &Spanned<Value>, diags: &mut Diagnostics) -> Option<String> {
	match &value.node {
		Value::Str(text) => Some(text.clone()),
		other => {
			diags.push(Diagnostic::new(
				value.span,
				format!("expected a string, found {}", other.describe()),
			));
			None
		}
	}
}

fn as_bool(value: &Spanned<Value>, diags: &mut Diagnostics) -> Option<bool> {
	match &value.node {
		Value::Bool(flag) => Some(*flag),
		other => {
			diags.push(Diagnostic::new(
				value.span,
				format!("expected true or false, found {}", other.describe()),
			));
			None
		}
	}
}

fn as_u32(value: &Spanned<Value>, diags: &mut Diagnostics) -> Option<u32> {
	match &value.node {
		Value::Number(number) => {
			if let Ok(value) = u32::try_from(*number) {
				Some(value)
			} else {
				diags.push(Diagnostic::new(
					value.span,
					format!("{number} is out of range here"),
				));
				None
			}
		}
		other => {
			diags.push(Diagnostic::new(
				value.span,
				format!("expected a number, found {}", other.describe()),
			));
			None
		}
	}
}

fn as_drift(value: &Spanned<Value>, diags: &mut Diagnostics) -> Option<DriftPolicy> {
	let name = as_string(value, diags)?;
	match name.as_str() {
		"report" => Some(DriftPolicy::Report),
		"reconcile" => Some(DriftPolicy::Reconcile),
		"ignore" => Some(DriftPolicy::Ignore),
		other => {
			diags.push(Diagnostic::new(
				value.span,
				format!("unknown drift policy `{other}`"),
			));
			None
		}
	}
}

/// A string splits on newlines, a list gives its elements.
///
/// The netifrc spelling puts several addresses or routes in one quoted string,
/// one per line, and that is the shape most existing configs are in.
fn as_lines(value: &Spanned<Value>, diags: &mut Diagnostics) -> Vec<Spanned<String>> {
	split_value(value, diags, |text, span| {
		text.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty())
			.map(|line| Spanned::new(line.to_owned(), span))
			.collect()
	})
}

/// A string splits on whitespace, a list gives its elements.
fn as_words(value: &Spanned<Value>, diags: &mut Diagnostics) -> Vec<Spanned<String>> {
	split_value(value, diags, |text, span| {
		text.split_whitespace()
			.map(|word| Spanned::new(word.to_owned(), span))
			.collect()
	})
}

fn split_value(
	value: &Spanned<Value>,
	diags: &mut Diagnostics,
	split: impl Fn(&str, Span) -> Vec<Spanned<String>>,
) -> Vec<Spanned<String>> {
	match &value.node {
		Value::Str(text) => split(text, value.span),
		Value::List(entries) => {
			let mut out = Vec::new();
			for entry in entries {
				match &entry.node {
					Value::Str(text) => out.push(Spanned::new(text.clone(), entry.span)),
					other => diags.push(Diagnostic::new(
						entry.span,
						format!("expected a string in this list, found {}", other.describe()),
					)),
				}
			}
			out
		}
		other => {
			diags.push(Diagnostic::new(
				value.span,
				format!("expected a string or a list, found {}", other.describe()),
			));
			Vec::new()
		}
	}
}
