//! Deciding whether a caller may do what they asked.
//!
//! One function answers "who may do this?", so there is one place to read and
//! one place a mistake can be. Decision 0013 has the reasoning; this is the
//! part that runs.

use netcfgd_model::{Control, Principal, Tier};
use netcfgd_netlink::peer::{group_id, user_id, Peer};
use netcfgd_proto::Request;

/// Which tier a request belongs to.
///
/// Exhaustive on purpose. A request added without a tier fails to compile,
/// which is a better reminder than a review checklist -- the failure mode of a
/// permission system is a verb nobody remembered to cover.
#[must_use]
pub(crate) fn tier_of(request: &Request) -> Tier {
	match request {
		// Reading. Hello is here rather than unauthenticated because even
		// knowing which versions a daemon speaks is more than a stranger needs.
		Request::Hello
		| Request::Status
		| Request::Plan
		| Request::Show
		| Request::Explain { .. }
		| Request::Monitor
		// Asking what the radio is doing is reading, and a status display that
		// needs the wifi tier is a status display that ends up being given it.
		| Request::WifiStatus { .. } => Tier::Observe,

		// Scanning is not reading: it transmits probe requests, it interrupts
		// whatever the radio was doing, and it is one of the things design
		// section 13 could not express. Decision 0013 puts it here with the
		// other two.
		Request::WifiScan { .. } | Request::WifiConnect { .. } | Request::WifiDisconnect { .. } => {
			Tier::Wifi
		}

		// Everything that changes the machine. Apply is Admin even when the
		// only thing in the plan is a wifi association: a tier that could call
		// Apply could apply any config change at all, which would make the
		// wifi tier Admin wearing a hat.
		Request::Apply { .. } | Request::Confirm | Request::Revert | Request::Reload => Tier::Admin,
	}
}

/// Whether a peer satisfies a principal.
///
/// Root satisfies everything. That is not a special case bolted on: a
/// configuration that named a group and thereby locked root out would be
/// unrecoverable without editing the file the daemon is refusing to let you
/// reach.
#[must_use]
pub(crate) fn satisfies(peer: &Peer, principal: &Principal) -> bool {
	if peer.is_root() {
		return true;
	}
	match principal {
		Principal::Root => false,
		Principal::Any => true,
		Principal::User(name) => user_id(name).is_some_and(|uid| uid == peer.uid),
		Principal::Group(name) => group_id(name).is_some_and(|gid| peer.in_group(gid)),
	}
}

/// Why a request was refused, in words the caller can act on.
///
/// A permission error that says only "denied" sends the reader to the source.
/// This one names the tier, what the policy says, and where to change it.
#[must_use]
pub(crate) fn refusal(tier: Tier, principal: &Principal) -> String {
	format!(
		"not permitted: this needs the `{}` tier, which the configuration \
		 opens to `{}`. Change it in the `control` block of netcfgd.conf.",
		tier.name(),
		principal.render()
	)
}

/// Decide, and say why if the answer is no.
///
/// # Errors
///
/// Returns the refusal text, which names the tier, what the policy says, and
/// where to change it.
pub(crate) fn check(control: &Control, peer: &Peer, request: &Request) -> Result<(), String> {
	let tier = tier_of(request);
	let principal = control.principal(tier);
	if satisfies(peer, principal) {
		Ok(())
	} else {
		Err(refusal(tier, principal))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn peer(uid: u32, gid: u32, groups: &[u32]) -> Peer {
		Peer {
			pid: 1234,
			uid,
			gid,
			groups: groups.to_vec(),
		}
	}

	/// Root satisfies every tier, always. A config that locked root out would
	/// be unrecoverable without editing the file the daemon will not let you
	/// reach.
	#[test]
	fn root_is_never_locked_out() {
		let control = Control {
			observe: Principal::Group("nobody-real".to_owned()),
			wifi: Principal::User("nobody-real".to_owned()),
			admin: Principal::Group("nobody-real".to_owned()),
		};
		let root = peer(0, 0, &[]);
		for request in [Request::Status, Request::Reload] {
			assert!(check(&control, &root, &request).is_ok());
		}
	}

	/// The default denies everything to everybody but root, so a machine that
	/// never edits the block behaves exactly as design section 13 describes.
	#[test]
	fn the_default_is_root_only() {
		let control = Control::default();
		let user = peer(1000, 1000, &[]);
		assert!(check(&control, &user, &Request::Status).is_err());
		assert!(check(&control, &user, &Request::Reload).is_err());
	}

	/// The case the whole design exists for: a user may see the network, may
	/// not reconfigure it.
	#[test]
	fn observe_can_be_opened_without_opening_admin() {
		let control = Control {
			observe: Principal::Any,
			..Control::default()
		};
		let user = peer(1000, 1000, &[]);
		assert!(check(&control, &user, &Request::Status).is_ok());
		assert!(check(&control, &user, &Request::Plan).is_ok());
		assert!(check(&control, &user, &Request::Reload).is_err());
		assert!(check(
			&control,
			&user,
			&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new()
			}
		)
		.is_err());
	}

	/// Apply is Admin even though a plan may contain nothing but a wifi
	/// association, because a tier that can call Apply can apply anything.
	#[test]
	fn apply_is_admin_whatever_it_would_do() {
		assert_eq!(
			tier_of(&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new()
			}),
			Tier::Admin
		);
	}

	/// The case decision 0013 exists for, end to end: a laptop user joins
	/// wireless networks and cannot touch anything else. Two lines of config.
	#[test]
	fn the_desktop_case_works_as_advertised() {
		let control = Control {
			observe: Principal::Any,
			wifi: Principal::Group("netdev".to_owned()),
			admin: Principal::Root,
		};
		// Group 44 stands in for netdev; `satisfies` resolves the name through
		// /etc/group, which a test cannot arrange, so the tier mapping is what
		// is checked here and `satisfies` is covered separately.
		let user = peer(1000, 1000, &[44]);

		assert!(check(&control, &user, &Request::Status).is_ok());
		assert_eq!(
			tier_of(&Request::WifiScan {
				interface: "wlan0".to_owned()
			}),
			Tier::Wifi
		);
		assert_eq!(
			tier_of(&Request::WifiConnect {
				interface: "wlan0".to_owned(),
				network: "home".to_owned()
			}),
			Tier::Wifi
		);
		// And the tier that would let them rewrite the network is not open.
		assert!(check(&control, &user, &Request::Reload).is_err());
		assert!(check(
			&control,
			&user,
			&Request::Apply {
				confirm: None,
				allow_disruption: Vec::new()
			}
		)
		.is_err());
	}

	/// Asking what the radio is doing is reading. A status display that needs
	/// the wifi tier is one that ends up being given it.
	#[test]
	fn wifi_status_is_only_observe() {
		let control = Control {
			observe: Principal::Any,
			..Control::default()
		};
		let user = peer(1000, 1000, &[]);
		let interface = "wlan0".to_owned();

		assert!(check(
			&control,
			&user,
			&Request::WifiStatus {
				interface: interface.clone()
			}
		)
		.is_ok());
		// But scanning transmits, so it is not.
		assert!(check(&control, &user, &Request::WifiScan { interface }).is_err());
	}

	/// Supplementary groups count. Checking the primary gid alone would deny
	/// nearly everybody a `group:` rule is meant to allow, while appearing to
	/// work -- the worst kind of security control.
	#[test]
	fn a_supplementary_group_satisfies_a_group_rule() {
		let member = peer(1000, 1000, &[27, 44]);
		assert!(member.in_group(44), "supplementary membership must count");
		assert!(member.in_group(1000), "and so must the primary group");
		assert!(!member.in_group(999));
	}

	/// A refusal names the tier, the policy and where to change it. "Denied"
	/// on its own sends the reader to the source code.
	#[test]
	fn a_refusal_says_what_to_do_about_it() {
		let message = refusal(Tier::Wifi, &Principal::Group("netdev".to_owned()));
		assert!(message.contains("wifi"));
		assert!(message.contains("group:netdev"));
		assert!(message.contains("netcfgd.conf"));
	}
}
