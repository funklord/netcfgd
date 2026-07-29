//! Turning what was written into what it means.
//!
//! Every diagnostic here can point at the text that caused it, which is why
//! the AST carries spans rather than being lowered as it is parsed.

use crate::ast::{Assignment, Block, Item, Spanned, Value};
use crate::diag::{Diagnostic, Diagnostics, Span};
use crate::hook::HookSink;
use crate::merge::Merged;
use netcfgd_model::address::{Delegated, PrefixRef, Static};
use netcfgd_model::dns::{DnsMode, RoutingDomain};
use netcfgd_model::interface::{BondConfig, BridgeConfig, VlanConfig, VlanProtocol};
use netcfgd_model::{
	AddressSource, Device, Dhcp4, Dhcp6, DnsPolicy, DnsServer, Document, DriftPolicy, HookPhase,
	HostnamePolicy, Interface, InterfaceKind, Route, Slaac,
};
use std::net::IpAddr;

/// Lower merged blocks into a document.
///
/// # Errors
///
/// Returns every diagnostic found.
pub fn lower(merged: &Merged, hooks: &mut dyn HookSink) -> Result<Document, Diagnostics> {
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
				if let Some(interface) = lower_interface(block, hooks, &mut diagnostics) {
					document.interfaces.push(interface);
				}
			}
			"network" => diagnostics.push(
				Diagnostic::new(block.span, "wifi networks are not supported by this build")
					.with_help("`network` blocks land in M3; see project.md section 7"),
			),
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
			Item::Block(inner) if inner.head == "wifi" => diags.push(
				Diagnostic::new(
					inner.span,
					"wifi device policy is not supported by this build",
				)
				.with_help("`wifi` blocks land in M3; see project.md section 7"),
			),
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

#[allow(clippy::too_many_lines)]
fn lower_interface(
	block: &Block,
	hooks: &mut dyn HookSink,
	diags: &mut Diagnostics,
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
							interface.addressing.push(source);
						}
					}
				}
				"routes" => {
					for line in as_lines(&assignment.value, diags) {
						if let Some(route) = parse_route(&line, diags) {
							interface.routes.push(route);
						}
					}
				}
				"mtu" => interface.mtu = as_u32(&assignment.value, diags),
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
					interface.guard = as_string(&assignment.value, diags)
						.map(|reason| netcfgd_model::Guard { reason });
				}
				"dns" | "dns_search" | "dns_mode" | "dns_domains" => {
					dns_touched = true;
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
