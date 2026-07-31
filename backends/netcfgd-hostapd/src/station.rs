//! Who is actually associated, read back from hostapd.
//!
//! The other half of decision 0039's station list. A deny list whose addresses
//! have to be typed from memory is a deny list nobody uses correctly: the
//! operation an operator wants is "that one, off this access point", and that
//! sentence needs a list of the ones that are on it.
//!
//! This is a **live query and not part of [`netcfgd_model::Observed`]**, for
//! the same reason `wifi scan` is not. There is no desired station list to
//! reconcile against -- who associates is decided by people walking around
//! with laptops -- so a station in the observation would be state the planner
//! could come to depend on, and a plan that changes with who is in the
//! building is not a plan. It also keeps the cost off the reconcile loop.
//!
//! ## The reply format
//!
//! Read out of hostapd 2.10's own `src/ap/ctrl_iface_ap.c` rather than guessed
//! from its documentation, which matters in two places that a plausible parser
//! gets wrong:
//!
//! - **Everything except the address is optional.** `hostapd_get_sta_info`
//!   writes nothing at all when `hostapd_drv_read_sta_data` fails, so a
//!   station with no `signal=`, no `rx_bytes=` and no `connected_time=` is a
//!   normal reply and not a malformed one.
//! - **The walk ends on an empty reply.** `hostapd_ctrl_iface_sta_mib` returns
//!   zero bytes for a null station, so `STA-FIRST` with nobody associated and
//!   `STA-NEXT <last>` at the end of the list are the same answer.
//!
//! ```text
//! aa:bb:cc:dd:ee:ff
//! flags=[AUTH][ASSOC][AUTHORIZED][WMM][HT]
//! aid=1
//! capability=0x431
//! listen_interval=10
//! supported_rates=02 04 0b 16
//! timeout_next=NULLFUNC POLL
//! rx_packets=1234
//! tx_packets=5678
//! rx_bytes=100000
//! tx_bytes=200000
//! inactive_msec=40
//! signal=-52
//! connected_time=3600
//! ```

/// One associated station, as hostapd reports it.
///
/// Defined here rather than in `netcfgd-proto` for the same reason the scan
/// parser's type is: a backend describes what it read, and the daemon decides
/// what of that belongs on the wire. Every field but the address is optional
/// because hostapd genuinely omits them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
	/// The station's hardware address, normalised the way an
	/// `access_control` list is.
	pub address: String,
	/// Whether it finished authenticating, rather than merely associating.
	pub authorized: bool,
	/// Signal level in dBm. Closer to zero is stronger.
	pub signal_dbm: Option<i32>,
	/// How long it has been associated.
	pub connected_seconds: Option<u64>,
	/// How long since hostapd last heard from it.
	pub inactive_msec: Option<u64>,
	/// Bytes received from it.
	pub rx_bytes: Option<u64>,
	/// Bytes sent to it.
	pub tx_bytes: Option<u64>,
}

/// Ask hostapd who is associated with one access point.
///
/// The walk is `STA-FIRST` then `STA-NEXT <address>`, which is the only
/// listing hostapd offers -- there is no "all stations" command, and each step
/// is a separate round trip.
///
/// # Errors
///
/// Returns a message naming the device when hostapd cannot be reached, which
/// is the ordinary case for an access point that is not running.
pub fn stations(run_dir: &std::path::Path, device: &str) -> Result<Vec<Station>, String> {
	let dir = crate::ctrl_dir(run_dir);
	let client =
		netcfgd_supplicant::Client::connect(&dir, device).map_err(|error| {
			format!("no access point is running on {device}, or its control socket is unreachable: {error}")
		})?;

	let mut stations = Vec::new();
	let mut reply = client
		.ask("STA-FIRST")
		.map_err(|error| format!("could not list the stations on {device}: {error}"))?;

	// Bounded rather than `loop`. hostapd walks its own list and terminates,
	// but this is a network daemon reading another process's answers, and a
	// reply that echoed an address back unchanged would spin forever. 2007 is
	// past any real association count -- hostapd's own `aid` space is 2007
	// (`MAX_AID`), so a list longer than that is hostapd misbehaving.
	for _ in 0..2007 {
		let Some(station) = parse(&reply) else { break };
		let address = station.address.clone();
		stations.push(station);
		reply = client
			.ask(&format!("STA-NEXT {address}"))
			.map_err(|error| format!("could not list the stations on {device}: {error}"))?;
	}

	stations.sort_by(|a, b| a.address.cmp(&b.address));
	Ok(stations)
}

/// One station's MIB block, or `None` at the end of the walk.
///
/// `None` for an empty reply and for `FAIL`, which is what hostapd answers for
/// an address it does not know -- both mean "no more", and neither is an error
/// worth showing somebody.
#[must_use]
pub fn parse(reply: &str) -> Option<Station> {
	let mut lines = reply.lines();
	let address = netcfgd_model::normalize_station(lines.next()?.trim()).ok()?;

	let mut station = Station {
		address,
		authorized: false,
		signal_dbm: None,
		connected_seconds: None,
		inactive_msec: None,
		rx_bytes: None,
		tx_bytes: None,
	};

	for line in lines {
		let Some((key, value)) = line.split_once('=') else {
			continue;
		};
		match key {
			// The flag that separates a station that completed authentication
			// from one part way through it. An unauthorized station is
			// associated and cannot pass traffic, which is worth showing
			// differently rather than not at all.
			"flags" => station.authorized = value.contains("[AUTHORIZED]"),
			"signal" => station.signal_dbm = value.trim().parse().ok(),
			"connected_time" => station.connected_seconds = value.trim().parse().ok(),
			"inactive_msec" => station.inactive_msec = value.trim().parse().ok(),
			"rx_bytes" => station.rx_bytes = value.trim().parse().ok(),
			"tx_bytes" => station.tx_bytes = value.trim().parse().ok(),
			_ => {}
		}
	}

	Some(station)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Exactly what hostapd 2.10 prints, in its order, taken from
	/// `hostapd_ctrl_iface_sta_mib` and `hostapd_get_sta_info`.
	const FULL: &str = "aa:bb:cc:dd:ee:ff\n\
		flags=[AUTH][ASSOC][AUTHORIZED][SHORT_PREAMBLE][WMM][HT]\n\
		aid=1\n\
		capability=0x431\n\
		listen_interval=10\n\
		supported_rates=02 04 0b 16 0c 12 18 24 30 48 60 6c\n\
		timeout_next=NULLFUNC POLL\n\
		rx_packets=1234\n\
		tx_packets=5678\n\
		rx_bytes=100000\n\
		tx_bytes=200000\n\
		inactive_msec=40\n\
		signal=-52\n\
		rx_rate_info=650 mcs 7 shortGI\n\
		tx_rate_info=650 mcs 7 shortGI\n\
		connected_time=3600\n";

	#[test]
	fn a_full_reply_is_read() {
		let station = parse(FULL).expect("a station");
		assert_eq!(station.address, "aa:bb:cc:dd:ee:ff");
		assert!(station.authorized);
		assert_eq!(station.signal_dbm, Some(-52));
		assert_eq!(station.connected_seconds, Some(3600));
		assert_eq!(station.inactive_msec, Some(40));
		assert_eq!(station.rx_bytes, Some(100_000));
		assert_eq!(station.tx_bytes, Some(200_000));
	}

	#[test]
	fn a_station_with_no_driver_statistics_is_still_a_station() {
		// `hostapd_get_sta_info` writes nothing at all when the driver read
		// fails, so this is a normal reply. A parser that required `signal=`
		// would drop a client that is really there, which is the worst way for
		// this feature to be wrong.
		let bare = "aa:bb:cc:dd:ee:ff\n\
			flags=[AUTH][ASSOC]\n\
			aid=1\n\
			capability=0x431\n\
			listen_interval=10\n\
			supported_rates=02 04\n\
			timeout_next=NULLFUNC POLL\n";
		let station = parse(bare).expect("a station");
		assert_eq!(station.address, "aa:bb:cc:dd:ee:ff");
		assert_eq!(station.signal_dbm, None);
		assert_eq!(station.rx_bytes, None);
		// Associated but not through authentication yet, which is a real state
		// and not a parse failure.
		assert!(!station.authorized);
	}

	#[test]
	fn the_end_of_the_walk_is_not_a_station() {
		// Both spellings hostapd uses for "no more": an empty reply from a
		// null station, and FAIL for an address it does not know.
		assert!(parse("").is_none());
		assert!(parse("\n").is_none());
		assert!(parse("FAIL\n").is_none());
		// And a reply whose first line is not an address is not trusted into
		// the list either.
		assert!(parse("UNKNOWN COMMAND\n").is_none());
	}

	#[test]
	fn the_address_is_normalised_like_every_other_station_address() {
		// So that a station read back from hostapd compares equal to one
		// written in an `access_control` block, which is what makes "deny the
		// one I can see" a string comparison.
		let station = parse("AA-BB-CC-DD-EE-FF\nflags=[AUTH]\n").expect("a station");
		assert_eq!(station.address, "aa:bb:cc:dd:ee:ff");
	}
}
