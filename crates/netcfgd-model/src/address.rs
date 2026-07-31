//! Addressing sources, and the indirection a delegated prefix arrives through.

use crate::Error;
use serde::{Deserialize, Serialize};

/// A statically configured address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Static {
	/// CIDR, for example `192.168.1.10/24`.
	pub address: String,
	/// Point-to-point peer address.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub peer: Option<String>,
	/// Preferred lifetime in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub preferred_lifetime: Option<u32>,
	/// Valid lifetime in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub valid_lifetime: Option<u32>,
}

/// A reference to a prefix another interface obtains by delegation.
///
/// The prefix itself is not known until a lease arrives, so the document
/// carries the reference and never the value -- the same discipline
/// [`crate::SecretRef`] applies to secrets, and for the same reason: a
/// document that embedded a runtime value would stop being a pure function of
/// the config files, and two compiles of one config would differ
/// (`docs/decisions/0009`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixRef {
	/// Interface whose delegation supplies the prefix.
	pub source: String,
	/// Which delegated prefix, when the lease carries more than one.
	#[serde(default)]
	pub index: u8,
	/// Sub-prefix selector within the delegation.
	#[serde(default)]
	pub subnet: u16,
}

/// An address derived from a delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegated {
	/// Where the prefix comes from.
	pub prefix: PrefixRef,
	/// Host part appended to the delegated prefix, for example `::1/64`.
	pub suffix: String,
}

/// Whether and how to send a hostname in a DHCP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnameMode {
	/// Send nothing.
	#[default]
	None,
	/// Send the short hostname.
	Send,
	/// Send the fully qualified name.
	SendFqdn,
}

/// Which `DHCPv4` client runs.
///
/// `Builtin` is recognised and unimplemented. It exists before the M4 freeze
/// because adding a variant afterwards is a major version bump, and a build
/// without the client must fail with "this build has no built-in DHCP client"
/// rather than "unknown value" (`docs/decisions/0004`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dhcp4Backend {
	/// Pick whichever client is present.
	#[default]
	Auto,
	/// dhcpcd.
	Dhcpcd,
	/// busybox udhcpc.
	Udhcpc,
	/// A client inside netcfgd. Reserved; no build implements it.
	Builtin,
}

/// A `DHCPv4` lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Dhcp4 {
	/// Hostname to send.
	pub hostname_mode: HostnameMode,
	/// Explicit client identifier.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub client_id: Option<String>,
	/// Metric for routes this lease installs.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub metric: Option<u32>,
	/// Additional DHCP options to request.
	pub request_options: Vec<u8>,
	/// Which client to run.
	pub backend: Dhcp4Backend,
}

impl Default for Dhcp4 {
	fn default() -> Self {
		Self {
			hostname_mode: HostnameMode::None,
			client_id: None,
			metric: None,
			request_options: Vec::new(),
			backend: Dhcp4Backend::Auto,
		}
	}
}

/// `DHCPv6` operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dhcp6Mode {
	/// Request addresses as well as other configuration.
	#[default]
	Managed,
	/// Take only other configuration; addresses come from SLAAC.
	OtherConf,
}

/// A request for a delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PdRequest {
	/// Preferred prefix to ask for, as a hint to the server.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub hint: Option<String>,
	/// Preferred prefix length.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub length: Option<u8>,
}

/// A `DHCPv6` lease, optionally including prefix delegation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Dhcp6 {
	/// Managed or other-config.
	pub mode: Dhcp6Mode,
	/// Whether to attempt rapid commit.
	pub rapid_commit: bool,
	/// Ask for a delegated prefix. Other interfaces reach it through
	/// [`PrefixRef`].
	#[serde(skip_serializing_if = "Option::is_none")]
	pub prefix_delegation: Option<PdRequest>,
}

/// IPv6 privacy address handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaacPrivacy {
	/// Stable addresses only.
	#[default]
	None,
	/// Generate and prefer temporary addresses.
	PreferTemporary,
}

/// Stateless address autoconfiguration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Slaac {
	/// Privacy address handling.
	pub privacy: SlaacPrivacy,
}

/// Addresses a modem helper reported for this interface.
///
/// The bearer's configuration is decided by the cellular network and told to
/// netcfgd through a file -- `docs/modem-report.md` is the contract, and
/// decisions 0044 and 0045 say why netcfgd neither connects the bearer nor
/// speaks a modem protocol to do it.
///
/// Unlike [`Dhcp4`], there is no backend to start: the helper is already
/// running and netcfgd does not supervise it. Unlike [`Delegated`], the value
/// is not derived from anything -- it is used as reported. What netcfgd does is
/// install what the report says, with its own tag, and withdraw it when the
/// report stops saying it.
///
/// A struct with no fields yet rather than a unit variant, so that the first
/// thing worth configuring here -- a metric, an APN the helper should be told
/// about -- is a field rather than a second variant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Modem {}

/// One way an interface acquires addresses.
///
/// The list of these on an interface is a composition, not a set of
/// alternatives -- dual-stack alone requires it. Order is significant for
/// exactly two things, default route metrics and DNS merge precedence, and is
/// not an execution sequence (`docs/decisions/0006`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AddressSource {
	/// A fixed address from the config.
	Static(Static),
	/// An address built from a prefix delegated to another interface.
	Delegated(Delegated),
	/// A `DHCPv4` lease.
	Dhcp4(Dhcp4),
	/// A `DHCPv6` lease.
	Dhcp6(Dhcp6),
	/// Router-advertised autoconfiguration.
	Slaac(Slaac),
	/// IPv4 link-local, per RFC 3927. Coexists with routable addresses rather
	/// than being a fallback; a timeout-triggered fallback would be state
	/// hidden in the reconciler that no config file explains.
	LinkLocal,
	/// Whatever a modem helper reported for this interface.
	Modem(Modem),
}

impl AddressSource {
	/// A stable name for diagnostics and for the multiplicity check.
	#[must_use]
	pub fn kind_name(&self) -> &'static str {
		match self {
			Self::Static(_) => "static",
			Self::Delegated(_) => "delegated",
			Self::Dhcp4(_) => "dhcp4",
			Self::Dhcp6(_) => "dhcp6",
			Self::Slaac(_) => "slaac",
			Self::LinkLocal => "link_local",
			Self::Modem(_) => "modem",
		}
	}

	/// Whether at most one of this kind may appear on one interface.
	///
	/// Two DHCP clients on one link is always a bug, so it is rejected at
	/// compile time rather than raced at runtime. Any number of `Static` and
	/// `Delegated` entries is legitimate.
	#[must_use]
	pub fn is_singleton(&self) -> bool {
		matches!(
			self,
			Self::Dhcp4(_) | Self::Dhcp6(_) | Self::Slaac(_) | Self::LinkLocal | Self::Modem(_)
		)
	}
}

/// Reject an interface that repeats a source which may appear at most once.
pub(crate) fn check_multiplicity(interface: &str, sources: &[AddressSource]) -> Result<(), Error> {
	let mut seen: Vec<&'static str> = Vec::new();
	for source in sources {
		if !source.is_singleton() {
			continue;
		}
		let name = source.kind_name();
		if seen.contains(&name) {
			return Err(Error::RepeatedAddressSource {
				interface: interface.to_owned(),
				source: name,
			});
		}
		seen.push(name);
	}
	Ok(())
}

/// Derive an address from a delegated prefix.
///
/// The one piece of arithmetic in the project, and the reason decision 0009
/// made `Delegated` a typed indirection rather than a string: what comes back
/// from the ISP is a prefix like `2001:db8:1234::/56`, and what goes on
/// `br-lan` is one `/64` carved out of it with a host part appended.
///
/// Three inputs, and each answers a different question:
///
/// - the delegation says which block the machine was given;
/// - `subnet` says which sub-prefix of that block this interface takes, so
///   several LANs can share one delegation without colliding;
/// - `suffix` supplies both the host part and the resulting prefix length --
///   `::1/64` means "the first address of a /64".
///
/// # Errors
///
/// Returns an error naming what does not fit. Every failure here is a config
/// that can never work rather than a transient one, so the message has to be
/// actionable: an operator told only "invalid" would have to work out which of
/// three numbers was wrong.
pub fn derive_from_delegation(
	delegation: &str,
	reference: &PrefixRef,
	suffix: &str,
) -> Result<String, String> {
	let (prefix, prefix_len) =
		parse_prefix6(delegation).ok_or_else(|| format!("`{delegation}` is not an IPv6 prefix"))?;
	let (host, subnet_len) = parse_prefix6(suffix)
		.ok_or_else(|| format!("`{suffix}` is not an IPv6 address with a prefix length"))?;

	// A sub-prefix has to be longer than the block it is carved from.
	// Equal is legal and means the whole delegation, so only shorter is
	// refused -- and it is worth refusing loudly: it would silently widen the
	// interface's route to cover addresses the ISP did not give this machine.
	if subnet_len < prefix_len {
		return Err(format!(
			"a /{subnet_len} cannot be carved out of a /{prefix_len}; the suffix's prefix \
			 length must be at least as long as the delegation's"
		));
	}

	let spare_bits = u32::from(subnet_len - prefix_len);
	// `1 << 16` would overflow a u16 subnet anyway, so the check is on the
	// value rather than the shift.
	if spare_bits < 16 && u32::from(reference.subnet) >= (1_u32 << spare_bits) {
		return Err(format!(
			"subnet {} does not fit: a /{prefix_len} delegation split into /{subnet_len} \
			 blocks has {} of them",
			reference.subnet,
			1_u128 << spare_bits
		));
	}

	let mut bits = u128::from_be_bytes(prefix.octets());
	// Clear anything below the delegation's own length. An ISP that hands out
	// `2001:db8:1234:5678::/56` -- and they do -- would otherwise contribute
	// bits that belong to nobody.
	bits &= mask(prefix_len);
	bits |= u128::from(reference.subnet) << (128 - u32::from(subnet_len));
	// The host part is whatever the suffix sets below the sub-prefix.
	bits |= u128::from_be_bytes(host.octets()) & !mask(subnet_len);

	Ok(format!(
		"{}/{subnet_len}",
		std::net::Ipv6Addr::from(bits.to_be_bytes())
	))
}

/// A mask with the top `len` bits set.
fn mask(len: u8) -> u128 {
	if len == 0 {
		0
	} else if len >= 128 {
		u128::MAX
	} else {
		u128::MAX << (128 - u32::from(len))
	}
}

/// `address/length`, IPv6 only.
fn parse_prefix6(text: &str) -> Option<(std::net::Ipv6Addr, u8)> {
	let (address, length) = text.split_once('/')?;
	let address: std::net::Ipv6Addr = address.parse().ok()?;
	let length: u8 = length.parse().ok()?;
	(length <= 128).then_some((address, length))
}
