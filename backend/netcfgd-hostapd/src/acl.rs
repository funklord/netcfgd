//! hostapd's live station lists, and changing them without a restart.
//!
//! Decision 0039 left the station list applied only at startup: hostapd reads
//! `deny_mac_file` once and nothing afterwards notices the document changed.
//! Restarting is the wrong repair -- it deauthenticates every client on the
//! radio, and this feature exists to make a handoff smooth -- so the list is
//! converged over the control socket instead. Decision 0041.
//!
//! ## What hostapd 2.10's own source said, twice, that its documentation did not
//!
//! Both of these were read out of `hostapd/ctrl_iface.c` and
//! `hostapd/config_file.c`, and both changed the design:
//!
//! - **`DENY_ACL ADD_MAC` disconnects the station by itself.** The command
//!   calls `hostapd_disassoc_deny_mac`, which walks `hapd->sta_list` and
//!   disconnects everything now on the list. `ACCEPT_ACL DEL_MAC` and
//!   `ACCEPT_ACL CLEAR` call `hostapd_disassoc_accept_mac` for the same reason.
//!   So netcfgd sends no `DEAUTHENTICATE` at all -- 0039 said it would need to,
//!   from reading `strings` on the binary, and the source says the work is
//!   already done. A `DEAUTHENTICATE` after an `ADD_MAC` would be a second
//!   deauthentication of a station that has already gone.
//! - **`SET deny_mac_file <path>` appends; it does not replace.**
//!   `hostapd_config_read_maclist` only ever *adds* -- the sole removal is a
//!   line prefixed with `-`, and nothing clears the list first. So re-pointing
//!   hostapd at the regenerated file would leave every previously denied
//!   station denied forever, which is the exact failure this converges to
//!   avoid. That is why this walks the difference rather than reloading a file
//!   that netcfgd has already written.
//!
//! ## And what it means for `CLEAR`
//!
//! `DENY_ACL CLEAR` is never sent. Emptying a deny list and refilling it is a
//! window, however short, in which every denied station may associate; the
//! per-address commands pass through no such state. `ACCEPT_ACL CLEAR` is
//! avoided for the symmetrical reason -- under `macaddr_acl=1` an empty accept
//! list denies everybody.

use netcfgd_model::AclPolicy;
use std::path::Path;

/// What hostapd's two lists currently hold.
///
/// Both, because hostapd keeps both regardless of which one `macaddr_acl`
/// selects. The document names one (decision 0039), so the other is expected
/// to be empty -- and observing that it is not is the only way, from outside
/// the process, to see that a running access point is not the one the document
/// describes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Live {
	/// Addresses in `deny_mac`, normalised and sorted.
	pub denied: Vec<String>,
	/// Addresses in `accept_mac`, normalised and sorted.
	pub accepted: Vec<String>,
}

impl Live {
	/// The list one policy reads.
	#[must_use]
	pub fn list(&self, policy: AclPolicy) -> &[String] {
		match policy {
			AclPolicy::Deny => &self.denied,
			AclPolicy::Allow => &self.accepted,
		}
	}
}

/// Ask hostapd what is in both of its lists.
///
/// Two round trips per access point per reconcile. That is a different cost
/// from the station walk decision 0040 kept off the reconcile loop, which is a
/// round trip *per station* and grows with who is in the building: this is
/// bounded by the number of access points on the host, which is one or two.
///
/// It is also the reason for the short deadline. The reconcile loop runs on
/// every netlink event, and a hostapd that is alive with its socket bound but
/// not answering would hold it for the client's full ten seconds twice per
/// access point, every time. A `SHOW` formats a list hostapd already holds in
/// memory, so a second is generous for a local datagram round trip -- and being
/// wrong here costs an observation that says "netcfgd could not ask", which the
/// planner already knows how to do nothing about.
///
/// # Errors
///
/// Returns a message naming the device when hostapd cannot be reached, which is
/// the ordinary case for an access point that is not running.
pub fn read(run_dir: &Path, device: &str) -> Result<Live, String> {
	let client = crate::connect(run_dir, device, netcfgd_supplicant::IMPATIENT)?;

	let show = |policy: AclPolicy| -> Result<Vec<String>, String> {
		let command = format!("{} SHOW", policy.ctrl_command());
		client
			.ask(&command)
			.map(|reply| parse_show(&reply))
			.map_err(|error| format!("could not read {device}'s access control list: {error}"))
	};

	Ok(Live {
		denied: show(AclPolicy::Deny)?,
		accepted: show(AclPolicy::Allow)?,
	})
}

/// Parse a `DENY_ACL SHOW` or `ACCEPT_ACL SHOW` reply.
///
/// `hostapd_ctrl_iface_acl_show_mac` prints one entry per line as
/// `MACSTR " VLAN_ID=%d"`, and `MACSTR` is `%02x:...`, so the address arrives
/// in exactly the form [`netcfgd_model::normalize_station`] produces. It is
/// normalised anyway rather than trusted: this is one daemon reading another's
/// output, the comparison it feeds decides whether a station is denied, and a
/// mismatched case would silently re-add an address that is already there on
/// every reconcile.
///
/// An empty list is an empty reply -- the function returns zero bytes when
/// there is nothing to print -- so an empty list and a list of nothing are the
/// same answer, and both are the empty vector.
///
/// The VLAN suffix is dropped. netcfgd never writes one (decision 0039: putting
/// a station on a VLAN is an `interface` question), so the only value it can
/// see is hostapd's default of 0, and carrying a field the document cannot
/// express would be state nothing could ever reconcile.
#[must_use]
pub fn parse_show(reply: &str) -> Vec<String> {
	let mut addresses: Vec<String> = reply
		.lines()
		.filter_map(|line| {
			let address = line.split_whitespace().next()?;
			netcfgd_model::normalize_station(address).ok()
		})
		.collect();
	addresses.sort();
	addresses.dedup();
	addresses
}

/// Put one station on one of hostapd's lists.
///
/// On the deny list this also disconnects it, because hostapd does that itself
/// -- see this module's documentation. Idempotent: `ADD_MAC` for an address
/// already present is a no-op that answers `OK`.
///
/// # Errors
///
/// Returns a message naming the station when hostapd refuses or is unreachable.
pub fn add(run_dir: &Path, device: &str, list: AclPolicy, station: &str) -> Result<(), String> {
	send(run_dir, device, list, "ADD_MAC", station)
}

/// Take one station off one of hostapd's lists.
///
/// Off the accept list this also disconnects it, for the same reason. Also
/// idempotent: `DEL_MAC` for an address that is not there answers `OK`, as does
/// one against an empty list.
///
/// # Errors
///
/// Returns a message naming the station when hostapd refuses or is unreachable.
pub fn remove(run_dir: &Path, device: &str, list: AclPolicy, station: &str) -> Result<(), String> {
	send(run_dir, device, list, "DEL_MAC", station)
}

/// One `<LIST> <verb> <address>` command.
///
/// The address is normalised before it is sent rather than passed through.
/// Everything reaching here has already been through the compiler, so this is a
/// backstop -- but it is the backstop that keeps a value from the document out
/// of a control command unexamined, and `hwaddr_aton` failing inside hostapd
/// reports against a station netcfgd would not name.
fn send(
	run_dir: &Path,
	device: &str,
	list: AclPolicy,
	verb: &str,
	station: &str,
) -> Result<(), String> {
	let address = netcfgd_model::normalize_station(station)?;
	let client = crate::connect(run_dir, device, crate::PATIENT)?;
	let command = format!("{} {verb} {address}", list.ctrl_command());
	client.command(&command).map_err(|error| {
		format!("hostapd would not change {device}'s access control list: `{command}`: {error}")
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Exactly what `hostapd_ctrl_iface_acl_show_mac` prints: `MACSTR
	/// " VLAN_ID=%d\n"` per entry, and hostapd's own default vlan of 0.
	const SHOW: &str = "00:11:22:33:44:55 VLAN_ID=0\n\
		aa:bb:cc:dd:ee:ff VLAN_ID=0\n";

	#[test]
	fn a_show_reply_is_read() {
		assert_eq!(
			parse_show(SHOW),
			vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
		);
	}

	#[test]
	fn an_empty_list_is_an_empty_reply() {
		// Not an error and not a failure: the printer returns zero bytes when
		// there is nothing to print, so this is what "denies nobody" looks like
		// on the wire.
		assert!(parse_show("").is_empty());
		assert!(parse_show("\n").is_empty());
	}

	#[test]
	fn a_vlan_assignment_is_still_a_station() {
		// hostapd prints a nonzero VLAN_ID for a list netcfgd did not write --
		// somebody's hostapd_cli, or a file left from another configuration.
		// The address still names a station, and dropping it would leave
		// netcfgd unable to see an entry it then could not remove.
		assert_eq!(
			parse_show("aa:bb:cc:dd:ee:ff VLAN_ID=7\n"),
			["aa:bb:cc:dd:ee:ff"]
		);
	}

	#[test]
	fn the_list_comes_back_sorted_and_deduplicated() {
		// So that comparing it against the document's stations -- which the
		// compiler sorts and deduplicates (decision 0039) -- is a comparison of
		// two lists rather than of two sets pretending to be lists. Without
		// this a plan would differ on ordering alone and never converge.
		let jumbled = "aa:bb:cc:dd:ee:ff VLAN_ID=0\n\
			00:11:22:33:44:55 VLAN_ID=0\n\
			AA:BB:CC:DD:EE:FF VLAN_ID=0\n";
		assert_eq!(
			parse_show(jumbled),
			vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
		);
	}

	#[test]
	fn what_is_not_an_address_is_not_a_station() {
		// `FAIL`, `UNKNOWN COMMAND` and a truncated line all reach here as
		// text. None of them may become an entry netcfgd then tries to delete.
		assert!(parse_show("FAIL\n").is_empty());
		assert!(parse_show("UNKNOWN COMMAND\n").is_empty());
		assert!(parse_show("aa:bb:cc VLAN_ID=0\n").is_empty());
	}

	#[test]
	fn the_two_lists_are_told_apart_by_policy() {
		let live = Live {
			denied: vec!["00:11:22:33:44:55".to_owned()],
			accepted: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
		};
		assert_eq!(live.list(AclPolicy::Deny), ["00:11:22:33:44:55"]);
		assert_eq!(live.list(AclPolicy::Allow), ["aa:bb:cc:dd:ee:ff"]);
	}
}
