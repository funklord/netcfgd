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
use netcfgd_model::device::{AccessPoint, MacPolicy, Powersave, WifiBackend, WifiDevicePolicy};
use netcfgd_model::dns::{DnsMode, RoutingDomain};
use netcfgd_model::interface::{
	BondConfig, BondMode, BridgeConfig, VethConfig, VlanConfig, VlanProtocol, VxlanConfig, WgPeer,
	WireGuardConfig,
};
use netcfgd_model::interface::{LinkSettings, Toggle};
use netcfgd_model::rule::{RoutingRule, RuleAction, RuleFamily};
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
	// `(member, master, where the master's block is)`, so a conflict points at
	// the line that declared the membership rather than at the top of a file.
	let mut memberships: Vec<(String, String, crate::diag::Span)> = Vec::new();

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
					let members = match &interface.kind {
						InterfaceKind::Bridge(bridge) => bridge.members.clone(),
						InterfaceKind::Bond(bond) => bond.members.clone(),
						_ => Vec::new(),
					};
					for member in members {
						memberships.push((member, interface.name.clone(), block.span));
					}
					document.interfaces.push(interface);
				}
			}
			"rule" => {
				if let Some(rule) = lower_rule(block, &mut diagnostics) {
					provenance.record(sources, format!("rule.{}", rule.id), block.span);
					document.rules.push(rule);
				}
			}
			"access_point" => {
				if let Some(access_point) = lower_access_point(block, &mut diagnostics) {
					provenance.record(
						sources,
						format!("access_point.{}", access_point.id),
						block.span,
					);
					document.access_points.push(access_point);
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
					.with_help(
						"the top-level blocks are interface, network, device, rule, \
						 access_point and global",
					),
			),
		}
	}

	expand_members(&mut document, &memberships, &mut diagnostics);

	if diagnostics.is_empty() {
		Ok(document)
	} else {
		Err(diagnostics)
	}
}

/// Turn `bridge { members = ... }` into `master` on each member.
///
/// Membership can be written from either end -- the master listing its members
/// or a member naming its master -- and the model holds only the second, since
/// that is the direction the kernel works in and the direction the planner
/// reads. Before this existed the `members` list was accepted and ignored: a
/// bridge would be created empty and the apply would report success, which is
/// the worst way for a feature to be missing.
///
/// Run after every block is lowered, because a member may be declared before
/// or after the master, or not declared at all.
fn expand_members(
	document: &mut Document,
	memberships: &[(String, String, crate::diag::Span)],
	diags: &mut Diagnostics,
) {
	for (member, master, span) in memberships {
		let (member, master) = (member.clone(), master.clone());
		if member == master {
			diags.push(Diagnostic::new(
				*span,
				format!("`{master}` lists itself as a member"),
			));
			continue;
		}

		if let Some(existing) = document
			.interfaces
			.iter_mut()
			.find(|interface| interface.name == member)
		{
			match &existing.master {
				// Said twice, consistently. Harmless, and common in a config
				// assembled from drop-ins.
				Some(current) if *current == master => {}
				// Said twice, differently. One of them is wrong and guessing
				// which would put an interface in the wrong bridge.
				Some(current) => diags.push(
					Diagnostic::new(
						*span,
						format!(
							"`{member}` is listed as a member of `{master}` but has \
							 `master = \"{current}\"`"
						),
					)
					.with_help("an interface has one master; remove one of the two"),
				),
				None => existing.master = Some(master),
			}
			continue;
		}

		// A member with no `interface` block of its own. Creating one is what
		// makes `bridge { members = "eth0 eth1" }` work on its own, which is
		// the shape design section 3.2 uses and the shape somebody converting
		// from another tool will write.
		document.interfaces.push(Interface {
			name: member,
			kind: InterfaceKind::Physical,
			enabled: true,
			mtu: None,
			mac: None,
			addressing: Vec::new(),
			routes: Vec::new(),
			dns: None,
			hooks: Vec::new(),
			on_drift: None,
			master: Some(master),
			dot1x: None,
			advertise: None,
			forwarding: None,
			guard: None,
			ipv6_token: None,
			link_settings: None,
		});
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

/// A `rule` block: `rule 100 { from = "10.0.0.0/8"; lookup = 100 }`.
///
/// The label is the priority, because the priority is what identifies a rule
/// to the kernel and what determines when it is consulted. Making it the label
/// rather than a key means it cannot be omitted -- see [`RoutingRule`] for why
/// an unnumbered rule makes reconciliation meaningless.
fn lower_rule(block: &Block, diags: &mut Diagnostics) -> Option<RoutingRule> {
	let label = require_label(block, diags)?;

	let mut rule = RoutingRule::lookup(label.clone(), 0, netcfgd_model::route::MAIN_TABLE);
	rule.table = None;
	let mut action_named = false;
	let mut priority = None;

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			if let Item::Block(inner) = item {
				diags.push(Diagnostic::new(
					inner.span,
					format!("`{}` is not valid inside `rule`", inner.head),
				));
			}
			continue;
		};
		match assignment.key.as_str() {
			"family" => {
				if let Some(name) = as_string(&assignment.value, diags) {
					match name.as_str() {
						"inet" | "ipv4" => rule.family = RuleFamily::Inet,
						"inet6" | "ipv6" => rule.family = RuleFamily::Inet6,
						other => diags.push(
							Diagnostic::new(
								assignment.span,
								format!("`{other}` is not an address family"),
							)
							.with_help("one of inet, inet6"),
						),
					}
				}
			}
			"priority" => priority = as_u32(&assignment.value, diags),
			"from" => rule.from = as_string(&assignment.value, diags),
			"to" => rule.to = as_string(&assignment.value, diags),
			"iif" => rule.iif = as_string(&assignment.value, diags),
			"oif" => rule.oif = as_string(&assignment.value, diags),
			"fwmark" => rule.fwmark = as_u32(&assignment.value, diags),
			"fwmask" => rule.fwmask = as_u32(&assignment.value, diags),
			"lookup" | "table" => rule.table = as_u32(&assignment.value, diags),
			"suppress_prefixlength" => {
				rule.suppress_prefixlength = as_u32(&assignment.value, diags);
			}
			"l3mdev" => {
				if let Some(flag) = as_bool(&assignment.value, diags) {
					rule.l3mdev = flag;
				}
			}
			"action" => {
				if let Some(name) = as_string(&assignment.value, diags) {
					action_named = true;
					match name.as_str() {
						"lookup" => rule.action = RuleAction::Lookup,
						"blackhole" => rule.action = RuleAction::Blackhole,
						"unreachable" => rule.action = RuleAction::Unreachable,
						"prohibit" => rule.action = RuleAction::Prohibit,
						other => diags.push(
							Diagnostic::new(
								assignment.span,
								format!("`{other}` is not a rule action"),
							)
							.with_help("one of lookup, blackhole, unreachable, prohibit"),
						),
					}
				}
			}
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown rule key `{other}`"),
			)),
		}
	}

	if !rule_is_complete(&rule, &label, priority, action_named, block, diags) {
		return None;
	}
	rule.priority = priority.unwrap_or_default();
	Some(rule)
}

/// The checks a rule has to pass to mean anything.
///
/// Separate from the key parsing because they are a different question: the
/// loop above asks "is this a key I know?", and this asks "does the result
/// describe something the kernel can be asked for?".
fn rule_is_complete(
	rule: &RoutingRule,
	label: &str,
	priority: Option<u32>,
	action_named: bool,
	block: &Block,
	diags: &mut Diagnostics,
) -> bool {
	// Mandatory. The kernel will assign a priority, but an unnumbered rule
	// lands wherever it puts one, two applies can produce different orders,
	// and the document has stopped describing the system.
	if priority.is_none() {
		diags.push(
			Diagnostic::new(block.span, format!("rule `{label}` has no `priority`")).with_help(
				"add `priority = N`; lower is consulted first, and leaving it to the \
					 kernel means two applies can order the rules differently",
			),
		);
		return false;
	}

	// A rule that looks nothing up and does nothing else is a rule that has no
	// effect, and the most likely cause is a `lookup` somebody meant to write.
	if rule.action == RuleAction::Lookup && rule.table.is_none() {
		diags.push(
			Diagnostic::new(
				block.span,
				format!("rule `{label}` looks up no table and names no action"),
			)
			.with_help(if action_named {
				"`action = \"lookup\"` needs a `lookup = N`"
			} else {
				"add `lookup = N`, or an `action` of blackhole, unreachable or prohibit"
			}),
		);
		return false;
	}
	// A mask without a mark matches nothing in particular, and reads as though
	// it does.
	if rule.fwmask.is_some() && rule.fwmark.is_none() {
		diags.push(Diagnostic::new(
			block.span,
			format!("rule `{label}` has an `fwmask` but no `fwmark`"),
		));
		return false;
	}

	true
}

/// An `access_point` block. Compiled, then refused at use.
fn lower_access_point(block: &Block, diags: &mut Diagnostics) -> Option<AccessPoint> {
	let label = require_label(block, diags)?;
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

	let mut access_point = AccessPoint {
		id: label.clone(),
		ssid,
		device: String::new(),
		security: Security::Open,
		channel: None,
		band: None,
		hidden: false,
		regdom: None,
	};
	let mut security_seen = false;

	for item in &block.items {
		match item {
			Item::Assignment(assignment) => match assignment.key.as_str() {
				"device" => {
					access_point.device = as_string(&assignment.value, diags).unwrap_or_default();
				}
				"channel" => {
					access_point.channel =
						as_u32(&assignment.value, diags).and_then(|n| u16::try_from(n).ok());
				}
				"band" => access_point.band = as_string(&assignment.value, diags),
				"regdom" => access_point.regdom = as_string(&assignment.value, diags),
				"hidden" => {
					if let Some(flag) = as_bool(&assignment.value, diags) {
						access_point.hidden = flag;
					}
				}
				"ssid" => {
					if let Some(text) = as_string(&assignment.value, diags) {
						match Ssid::from_hex(&text) {
							Ok(ssid) => access_point.ssid = ssid,
							Err(error) => diags.push(Diagnostic::new(
								assignment.span,
								format!("`{text}` is not a usable ssid: {error}"),
							)),
						}
					}
				}
				other => diags.push(Diagnostic::new(
					assignment.span,
					format!("unknown access_point key `{other}`"),
				)),
			},
			Item::Block(inner) if inner.head == "wifi" => {
				security_seen = true;
				// An access point's security is the same shape as a station's,
				// so it is parsed by the same code -- but through a throwaway
				// network, since the keys that only mean something to a client
				// (priority, autoconnect) have nowhere to go here.
				let mut carrier = station_placeholder();
				lower_network_wifi(inner, &mut carrier, diags);
				access_point.security = carrier.security;
			}
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside `access_point`", inner.head),
			)),
			_ => {}
		}
	}

	if access_point.device.is_empty() {
		diags.push(
			Diagnostic::new(
				block.span,
				format!("access point `{label}` does not say which radio runs it"),
			)
			.with_help(
				"add `device = \"wlan0\"`; unlike a `network`, an access point is one radio",
			),
		);
		return None;
	}
	if !security_seen {
		diags.push(
			Diagnostic::new(
				block.span,
				format!("access point `{label}` has no `wifi` block, so it would be open"),
			)
			.with_help("add `wifi { psk = \"@secret:NAME\" }`, or `wifi { open = true }`"),
		);
		return None;
	}

	Some(access_point)
}

/// A throwaway station profile, for parsing security out of a context that has
/// no network of its own.
fn station_placeholder() -> WifiNetwork {
	WifiNetwork {
		id: String::new(),
		ssid: Ssid::new(Vec::new()).unwrap_or_else(|_| unreachable!("empty is valid")),
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
	}
}

/// An `ethtool` block inside `interface`. Compiled, then refused at use.
fn lower_ethtool(block: &Block, settings: &mut LinkSettings, diags: &mut Diagnostics) {
	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		let toggle = |diags: &mut Diagnostics| -> Option<Toggle> {
			let name = as_string(&assignment.value, diags)?;
			match name.as_str() {
				"on" | "true" => Some(Toggle::On),
				"off" | "false" => Some(Toggle::Off),
				"unmanaged" => Some(Toggle::Unmanaged),
				other => {
					diags.push(
						Diagnostic::new(assignment.span, format!("`{other}` is not a toggle"))
							.with_help("one of on, off, unmanaged"),
					);
					None
				}
			}
		};
		match assignment.key.as_str() {
			"autoneg" => {
				if let Some(value) = toggle(diags) {
					settings.autoneg = value;
				}
			}
			"gro" => {
				if let Some(value) = toggle(diags) {
					settings.gro = value;
				}
			}
			"gso" => {
				if let Some(value) = toggle(diags) {
					settings.gso = value;
				}
			}
			"tso" => {
				if let Some(value) = toggle(diags) {
					settings.tso = value;
				}
			}
			"rx_checksum" => {
				if let Some(value) = toggle(diags) {
					settings.rx_checksum = value;
				}
			}
			"tx_checksum" => {
				if let Some(value) = toggle(diags) {
					settings.tx_checksum = value;
				}
			}
			"speed" => settings.speed = as_u32(&assignment.value, diags),
			"rx_ring" => settings.rx_ring = as_u32(&assignment.value, diags),
			"tx_ring" => settings.tx_ring = as_u32(&assignment.value, diags),
			"duplex" => {
				if let Some(name) = as_string(&assignment.value, diags) {
					if name == "full" || name == "half" {
						settings.duplex = Some(name);
					} else {
						diags.push(
							Diagnostic::new(
								assignment.span,
								format!("`{name}` is not a duplex setting"),
							)
							.with_help("one of full, half"),
						);
					}
				}
			}
			"wol" => settings.wol = as_string(&assignment.value, diags),
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown ethtool key `{other}`"),
			)),
		}
	}
}

/// The `mac_policy` key. Its own function only because the enum arm made
/// [`lower_wifi_device`] longer than the style allows.
fn lower_mac_policy(
	policy: &mut WifiDevicePolicy,
	assignment: &Assignment,
	diags: &mut Diagnostics,
) {
	let Some(name) = as_string(&assignment.value, diags) else {
		return;
	};
	match name.as_str() {
		"permanent" => policy.mac_policy = MacPolicy::Permanent,
		"per_network" => policy.mac_policy = MacPolicy::PerNetwork,
		"per_connection" => policy.mac_policy = MacPolicy::PerConnection,
		other => diags.push(
			Diagnostic::new(assignment.span, format!("`{other}` is not a MAC policy"))
				.with_help("one of permanent, per_network, per_connection"),
		),
	}
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
				"mac_policy" => lower_mac_policy(&mut policy, assignment, diags),
				"scan_randomization" => {
					if let Some(flag) = as_bool(&assignment.value, diags) {
						policy.scan_randomization = flag;
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

/// One `key = value` inside an interface's `dot1x` block.
///
/// The same keys as a wifi network's EAP, minus the ones that only mean
/// something on a radio. Sharing [`WifiKeys`] rather than duplicating the
/// parsing means the two cannot drift into accepting different spellings of
/// the same thing.
fn lower_dot1x_key(keys: &mut WifiKeys, assignment: &Assignment, diags: &mut Diagnostics) {
	match assignment.key.as_str() {
		"psk" | "open" | "owe" | "proto" | "priority" | "autoconnect" => diags.push(
			Diagnostic::new(
				assignment.span,
				format!("`{}` means nothing on a wired port", assignment.key),
			)
			.with_help("`dot1x` is EAP only: eap, identity, password, ca_cert, client_cert, private_key, phase2"),
		),
		_ => {
			// `network` is not in scope here, and none of the keys reaching
			// this arm touch it.
			let mut unused = WifiNetwork {
				id: String::new(),
				ssid: Ssid::new(Vec::new()).unwrap_or_else(|_| unreachable!("empty is valid")),
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
			lower_wifi_key(keys, &mut unused, assignment, diags);
		}
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
		ipv6_token: None,
		link_settings: None,
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
				"ipv6_token" => {
					if let Some(text) = as_string(&assignment.value, diags) {
						// A token is an interface identifier, so the prefix
						// bits must be zero -- `::5`, not `2001:db8::5`. The
						// kernel accepts a full address and silently uses only
						// the host part, which means a config that looks like
						// it pins a whole address quietly pins half of one.
						match text.parse::<std::net::Ipv6Addr>() {
							Ok(address) if address.octets()[..8].iter().all(|byte| *byte == 0) => {
								interface.ipv6_token = Some(text);
							}
							Ok(_) => diags.push(
								Diagnostic::new(
									assignment.span,
									format!("`{text}` has bits set in the prefix half"),
								)
								.with_help(
									"a token is the host part only, such as `::5`; the prefix \
									 comes from the router advertisement",
								),
							),
							Err(_) => diags.push(Diagnostic::new(
								assignment.span,
								format!("`{text}` is not an IPv6 address"),
							)),
						}
					}
				}
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
				// Wired 802.1X. Decision 0008 puts this on the interface
				// rather than inside a wifi profile, because port-based access
				// control predates radios and is ordinary on campus and
				// corporate wired networks -- nesting it under an SSID made
				// the wired case inexpressible.
				"dot1x" => {
					let mut keys = WifiKeys::default();
					for item in &inner.items {
						match item {
							Item::Assignment(assignment) => {
								lower_dot1x_key(&mut keys, assignment, diags);
							}
							Item::Block(nested) => diags.push(Diagnostic::new(
								nested.span,
								format!("`{}` is not valid inside `dot1x`", nested.head),
							)),
							_ => {}
						}
					}
					if keys.eap.is_none() {
						diags.push(
							Diagnostic::new(inner.span, "a `dot1x` block needs an `eap` method")
								.with_help("one of peap, ttls, tls, pwd"),
						);
					} else if let Some(Security::Eap(config)) = build_security(keys, inner, diags) {
						interface.dot1x = Some(config);
					}
				}
				"vxlan" => {
					if let Some(kind) = lower_vxlan(inner, diags) {
						interface.kind = kind;
					}
				}
				"veth" => {
					if let Some(kind) = lower_veth(inner, diags) {
						interface.kind = kind;
					}
				}
				"ethtool" => {
					let mut settings = LinkSettings::default();
					lower_ethtool(inner, &mut settings, diags);
					if !settings.is_empty() {
						interface.link_settings = Some(settings);
					}
				}
				"wireguard" => {
					if let Some(kind) = lower_wireguard(inner, diags) {
						interface.kind = kind;
					}
				}
				// The last M4 link type still to come. Named rather than
				// reported as an unknown block, because "`pppoe` is not valid
				// inside `interface`" reads as a typo when it is a gap.
				"pppoe" => diags.push(
					Diagnostic::new(inner.span, "pppoe is not supported by this build").with_help(
						"`pppoe` needs the netcfgd-ppp backend, which lands in M4; \
							 see project.md section 7",
					),
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

fn lower_wireguard(block: &Block, diags: &mut Diagnostics) -> Option<InterfaceKind> {
	let mut private_key = None;
	let mut listen_port = None;
	let mut fwmark = None;
	let mut peers = Vec::new();

	for item in &block.items {
		match item {
			Item::Assignment(assignment) => match assignment.key.as_str() {
				"private_key" => private_key = as_secret(&assignment.value, diags),
				"listen_port" => {
					listen_port =
						as_u32(&assignment.value, diags).and_then(|n| u16::try_from(n).ok());
				}
				"fwmark" => fwmark = as_u32(&assignment.value, diags),
				other => diags.push(Diagnostic::new(
					assignment.span,
					format!("unknown wireguard key `{other}`"),
				)),
			},
			Item::Block(inner) if inner.head == "peer" => {
				if let Some(peer) = lower_wg_peer(inner, diags) {
					peers.push(peer);
				}
			}
			Item::Block(inner) => diags.push(Diagnostic::new(
				inner.span,
				format!("`{}` is not valid inside `wireguard`", inner.head),
			)),
			_ => {}
		}
	}

	let Some(private_key) = private_key else {
		diags.push(
			Diagnostic::new(block.span, "a wireguard device needs a `private_key`").with_help(
				"`private_key = \"@secret:NAME\"`; `wg genkey` produces one and it never \
				 belongs in the config",
			),
		);
		return None;
	};

	// Two peers with one public key is two halves of one entry: the key is the
	// peer's identity, so the kernel would keep whichever came last and the
	// other's allowed IPs would silently vanish.
	for (index, peer) in peers.iter().enumerate() {
		if peers[..index]
			.iter()
			.any(|earlier| earlier.public_key == peer.public_key)
		{
			diags.push(
				Diagnostic::new(
					block.span,
					format!("two peers share the public key `{}`", peer.public_key),
				)
				.with_help("a public key is a peer's identity; merge the two blocks"),
			);
			return None;
		}
	}

	Some(InterfaceKind::WireGuard(WireGuardConfig {
		private_key,
		listen_port,
		fwmark,
		peers,
	}))
}

fn lower_wg_peer(block: &Block, diags: &mut Diagnostics) -> Option<WgPeer> {
	let name = require_label(block, diags)?;
	let mut public_key = None;
	let mut preshared_key = None;
	let mut endpoint = None;
	let mut allowed_ips = Vec::new();
	let mut keepalive = None;

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		match assignment.key.as_str() {
			"public_key" => {
				if let Some(text) = as_string(&assignment.value, diags) {
					match netcfgd_model::Key::parse(&text) {
						Ok(key) => public_key = Some(key),
						Err(error) => diags.push(Diagnostic::new(
							assignment.value.span,
							format!("`{text}` is not a public key: {error}"),
						)),
					}
				}
			}
			"preshared_key" => preshared_key = as_secret(&assignment.value, diags),
			"endpoint" => endpoint = as_string(&assignment.value, diags),
			"allowed_ips" => {
				allowed_ips = as_words(&assignment.value, diags)
					.into_iter()
					.filter_map(|word| {
						if parse_prefix(&word.node).is_some() {
							Some(word.node)
						} else {
							diags.push(Diagnostic::new(
								word.span,
								format!("`{}` is not a CIDR prefix", word.node),
							));
							None
						}
					})
					.collect();
			}
			"keepalive" => {
				keepalive = as_u32(&assignment.value, diags).and_then(|n| u16::try_from(n).ok());
			}
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown peer key `{other}`"),
			)),
		}
	}

	let Some(public_key) = public_key else {
		diags.push(Diagnostic::new(
			block.span,
			format!("peer `{name}` needs a `public_key`"),
		));
		return None;
	};
	// A peer with no allowed IPs receives nothing and is routed nothing. It is
	// legal to the kernel and never what anybody meant.
	if allowed_ips.is_empty() {
		diags.push(
			Diagnostic::new(
				block.span,
				format!("peer `{name}` has no `allowed_ips`, so nothing would route to it"),
			)
			.with_help("`allowed_ips = \"0.0.0.0/0\"` sends everything; a prefix sends some"),
		);
		return None;
	}

	Some(WgPeer {
		name,
		public_key,
		preshared_key,
		endpoint,
		allowed_ips,
		keepalive,
	})
}

/// `address/length`, which is what an allowed IP is.
fn parse_prefix(text: &str) -> Option<(std::net::IpAddr, u8)> {
	let (address, length) = text.split_once('/')?;
	let address: std::net::IpAddr = address.parse().ok()?;
	let length: u8 = length.parse().ok()?;
	let max = if address.is_ipv4() { 32 } else { 128 };
	(length <= max).then_some((address, length))
}

fn lower_vxlan(block: &Block, diags: &mut Diagnostics) -> Option<InterfaceKind> {
	let mut config = VxlanConfig {
		id: 0,
		parent: None,
		local: None,
		remote: None,
		port: None,
	};
	let mut id_seen = false;

	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		let address = |diags: &mut Diagnostics| -> Option<std::net::IpAddr> {
			let text = as_string(&assignment.value, diags)?;
			if let Ok(address) = text.parse() {
				Some(address)
			} else {
				diags.push(Diagnostic::new(
					assignment.value.span,
					format!("`{text}` is not an IP address"),
				));
				None
			}
		};
		match assignment.key.as_str() {
			"id" | "vni" => {
				if let Some(value) = as_u32(&assignment.value, diags) {
					// 24 bits. A VNI above that is silently truncated by the
					// kernel, so two tunnels that look distinct in the config
					// become one.
					if value < (1 << 24) {
						config.id = value;
						id_seen = true;
					} else {
						diags.push(Diagnostic::new(
							assignment.value.span,
							"a VNI is 24 bits, so at most 16777215",
						));
					}
				}
			}
			"parent" | "dev" => config.parent = as_string(&assignment.value, diags),
			"local" => config.local = address(diags),
			"remote" | "group" => config.remote = address(diags),
			"port" => {
				config.port = as_u32(&assignment.value, diags).and_then(|n| u16::try_from(n).ok());
			}
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown vxlan key `{other}`"),
			)),
		}
	}

	if !id_seen {
		diags.push(
			Diagnostic::new(block.span, "a vxlan needs an `id`")
				.with_help("the VNI, which identifies the overlay: `id = 100`"),
		);
		return None;
	}
	// Both families in one tunnel is not a thing the kernel will build, and
	// the error it gives says nothing about which end was wrong.
	if let (Some(local), Some(remote)) = (config.local, config.remote) {
		if local.is_ipv4() != remote.is_ipv4() {
			diags.push(Diagnostic::new(
				block.span,
				"`local` and `remote` must be the same address family",
			));
			return None;
		}
	}

	Some(InterfaceKind::Vxlan(config))
}

fn lower_veth(block: &Block, diags: &mut Diagnostics) -> Option<InterfaceKind> {
	let mut peer = None;
	for item in &block.items {
		let Item::Assignment(assignment) = item else {
			continue;
		};
		match assignment.key.as_str() {
			"peer" => peer = as_string(&assignment.value, diags),
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown veth key `{other}`"),
			)),
		}
	}

	let Some(peer) = peer else {
		diags.push(
			Diagnostic::new(block.span, "a veth needs a `peer`")
				.with_help("a veth is a pair, and both ends are named at creation"),
		);
		return None;
	};
	Some(InterfaceKind::Veth(VethConfig { peer }))
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
			"mode" => {
				if let Some(text) = as_string(&assignment.value, diags) {
					match BondMode::parse(&text) {
						Some(parsed) => mode = Some(parsed),
						None => diags.push(
							Diagnostic::new(
								assignment.span,
								format!("`{text}` is not a bonding mode"),
							)
							.with_help(
								"one of balance-rr, active-backup, balance-xor, broadcast, \
								 802.3ad, balance-tlb, balance-alb",
							),
						),
					}
				}
			}
			"miimon" => miimon = as_u32(&assignment.value, diags),
			other => diags.push(Diagnostic::new(
				assignment.span,
				format!("unknown bond key `{other}`"),
			)),
		}
	}

	let Some(mode) = mode else {
		diags.push(
			Diagnostic::new(block.span, "a bond needs a `mode`").with_help(
				"`active-backup` needs nothing of the switch; the others need a \
				 cooperating one",
			),
		);
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
