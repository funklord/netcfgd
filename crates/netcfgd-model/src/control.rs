//! Who may do what.
//!
//! Three tiers, because an operator's real question on a laptop is not "may
//! this user change the network" but two separate ones -- may they join a
//! wireless network, and may they change anything else. Design section 13's
//! socket permissions cannot express the difference; decision 0013 explains
//! why this is config rather than a fourth socket.

use serde::{Deserialize, Serialize};

/// Who a tier is open to.
///
/// Four shapes, deliberately, and no expression language. Every authorisation
/// system that grew one did so a reasonable extension at a time, and ended up
/// as something operators copy from forums without understanding.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
	/// Only uid 0. The default for every tier.
	#[default]
	Root,
	/// Anybody who can open the socket.
	Any,
	/// One named user, and root.
	User(String),
	/// Anybody in a named group, and root.
	Group(String),
}

impl Principal {
	/// Parse `root`, `any`, `user:NAME` or `group:NAME`.
	///
	/// # Errors
	///
	/// Returns the offending text, for a diagnostic that can quote it.
	pub fn parse(text: &str) -> Result<Self, String> {
		match text {
			"root" => Ok(Self::Root),
			"any" => Ok(Self::Any),
			_ => {
				if let Some(name) = text.strip_prefix("user:") {
					if name.is_empty() {
						return Err("user: needs a name after it".to_owned());
					}
					return Ok(Self::User(name.to_owned()));
				}
				if let Some(name) = text.strip_prefix("group:") {
					if name.is_empty() {
						return Err("group: needs a name after it".to_owned());
					}
					return Ok(Self::Group(name.to_owned()));
				}
				Err(format!(
					"`{text}` is not root, any, user:NAME or group:NAME"
				))
			}
		}
	}

	/// How it is written in a config file.
	#[must_use]
	pub fn render(&self) -> String {
		match self {
			Self::Root => "root".to_owned(),
			Self::Any => "any".to_owned(),
			Self::User(name) => format!("user:{name}"),
			Self::Group(name) => format!("group:{name}"),
		}
	}

	/// Whether reaching this tier requires being able to open a socket that
	/// root-only permissions would close.
	#[must_use]
	pub fn beyond_root(&self) -> bool {
		!matches!(self, Self::Root)
	}
}

/// What a caller is trying to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
	/// Ask what the network looks like. Reading is not writing, and a status
	/// display that must run as root is how status displays end up as root.
	Observe,
	/// Join, leave and scan wireless networks that the configuration already
	/// describes. Creating one is `Admin`, because creating a profile means
	/// writing config and config is the source of truth.
	Wifi,
	/// Change anything else.
	Admin,
}

impl Tier {
	/// A name for diagnostics.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Observe => "observe",
			Self::Wifi => "wifi",
			Self::Admin => "admin",
		}
	}
}

/// The policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Control {
	/// Who may ask what the network looks like.
	pub observe: Principal,
	/// Who may join, leave and scan wireless networks.
	pub wifi: Principal,
	/// Who may change anything else.
	pub admin: Principal,
}

impl Control {
	/// The principal for a tier.
	#[must_use]
	pub fn principal(&self, tier: Tier) -> &Principal {
		match tier {
			Tier::Observe => &self.observe,
			Tier::Wifi => &self.wifi,
			Tier::Admin => &self.admin,
		}
	}

	/// Whether any tier is open beyond root.
	///
	/// The socket's permissions follow this: a policy naming a group is a lie
	/// if the socket stays root-only, because the caller cannot connect to be
	/// told yes.
	#[must_use]
	pub fn opens_beyond_root(&self) -> bool {
		self.observe.beyond_root() || self.wifi.beyond_root() || self.admin.beyond_root()
	}

	/// Every group named by any tier, for the socket's ownership.
	#[must_use]
	pub fn named_groups(&self) -> Vec<&str> {
		let mut found: Vec<&str> = Vec::new();
		for principal in [&self.observe, &self.wifi, &self.admin] {
			if let Principal::Group(name) = principal {
				// Deduplicated, because the caller counts what this returns
				// and warns when there is more than one. The policy
				// `debian/postinst` prints names the same group for `observe`
				// and `wifi`, which is the ordinary desktop case -- and it
				// produced "the control policy names 2 groups (netcfgd,
				// netcfgd) ... Members of the others will not be able to
				// connect", warning about others that do not exist. A
				// diagnostic that fires on the recommended configuration is
				// one people learn to scroll past.
				if !found.contains(&name.as_str()) {
					found.push(name.as_str());
				}
			}
		}
		found
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The desktop policy names one group twice, and that is one group.
	///
	/// `debian/postinst` prints `--observe group:netcfgd --wifi group:netcfgd`,
	/// so the ordinary case has the same name in two tiers. The caller counts
	/// what this returns and warns when there is more than one, which turned
	/// that into "the control policy names 2 groups (netcfgd, netcfgd) ...
	/// Members of the others will not be able to connect" -- a warning about
	/// others that do not exist, printed on the configuration the package
	/// itself recommends. A diagnostic that fires on the recommended setup is
	/// one people learn to scroll past, which costs the warnings that are real.
	#[test]
	fn one_group_named_twice_is_one_group() {
		let control = Control {
			observe: Principal::Group("netcfgd".to_owned()),
			wifi: Principal::Group("netcfgd".to_owned()),
			admin: Principal::Root,
		};
		assert_eq!(control.named_groups(), vec!["netcfgd"]);
	}

	/// And two really different groups are still two, in policy order.
	///
	/// The pair: deduplicating by collapsing everything would silence the
	/// warning this exists to produce, which is the failure that matters more.
	#[test]
	fn two_different_groups_are_still_two() {
		let control = Control {
			observe: Principal::Group("netcfgd".to_owned()),
			wifi: Principal::Group("netdev".to_owned()),
			admin: Principal::Root,
		};
		assert_eq!(control.named_groups(), vec!["netcfgd", "netdev"]);
	}
}
