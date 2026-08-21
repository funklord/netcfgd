//! The control protocol's text, in and out.
//!
//! Pure: strings to structs and back. `wpa_supplicant` is not on every machine
//! that builds netcfgd, and association needs a radio besides, so the part
//! that can be tested exhaustively without either is kept separate from the
//! part that cannot.
//!
//! The quoting rules below are the reason this file is worth reading. A
//! control socket that takes `SET_NETWORK 0 ssid "..."` is a place where a
//! value from a config file becomes protocol syntax, and an SSID is 32
//! arbitrary octets chosen by whoever named the network -- including, if they
//! like, ones containing a quote.

use netcfgd_model::Ssid;

/// What the supplicant said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
	/// `OK`.
	Ok,
	/// `FAIL`, or an unsolicited failure.
	Fail,
	/// Anything else: the body, with the trailing newline removed.
	Data(String),
}

impl Reply {
	/// Parse a raw reply.
	#[must_use]
	pub fn parse(raw: &str) -> Self {
		let trimmed = raw.trim_end_matches(['\n', '\0']);
		match trimmed {
			"OK" => Self::Ok,
			"FAIL" | "UNKNOWN COMMAND" => Self::Fail,
			other => Self::Data(other.to_owned()),
		}
	}

	/// The body, or an error naming the command that produced the failure.
	///
	/// # Errors
	///
	/// Returns a message for `FAIL`.
	pub fn body(self, command: &str) -> Result<String, String> {
		match self {
			Self::Ok => Ok("OK".to_owned()),
			Self::Fail => Err(format!("wpa_supplicant refused `{command}`")),
			Self::Data(body) => Ok(body),
		}
	}
}

/// Whether a line is an unsolicited event rather than a reply.
///
/// `wpa_supplicant` prefixes events with a priority in angle brackets --
/// `<3>CTRL-EVENT-CONNECTED ...` -- and sends them on the same socket as
/// replies once a client has attached. A client that does not separate them
/// will eventually read an event as the answer to a command and act on it.
#[must_use]
pub fn is_event(line: &str) -> bool {
	line.starts_with('<') && line.find('>').is_some_and(|end| end <= 3)
}

/// An unsolicited event, with its priority stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
	/// Priority, 0 (most) to 4 (least).
	pub priority: u8,
	/// The text after the priority.
	pub text: String,
}

impl Event {
	/// Parse an event line, or `None` if it is not one.
	#[must_use]
	pub fn parse(line: &str) -> Option<Self> {
		let rest = line.strip_prefix('<')?;
		let end = rest.find('>')?;
		let priority = rest[..end].parse().ok()?;
		Some(Self {
			priority,
			text: rest[end + 1..].trim_end().to_owned(),
		})
	}

	/// The event's name: the first word, such as `CTRL-EVENT-CONNECTED`.
	#[must_use]
	pub fn name(&self) -> &str {
		self.text.split_whitespace().next().unwrap_or("")
	}

	/// The access point a `CTRL-EVENT-CONNECTED` says was joined.
	///
	/// The format is `wpa_supplicant`'s own, read out of the binary rather than
	/// from documentation, which does not give it:
	///
	/// ```text
	/// CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d id_str=%s%s]
	/// ```
	///
	/// So the address is the fifth word. Positional rather than pattern-matched
	/// on "Connection to", because that phrase is prose and the shape around it
	/// is what the format string fixes -- and a reader keyed on the prose would
	/// break on a translation that never comes while missing a reordering that
	/// might.
	///
	/// `None` for every other event, including a connect that did not name an
	/// address: a caller comparing addresses must not be handed an empty one,
	/// which would read as "moved to nowhere".
	#[must_use]
	pub fn connected_bssid(&self) -> Option<&str> {
		if self.name() != "CTRL-EVENT-CONNECTED" {
			return None;
		}
		let bssid = self.text.split_whitespace().nth(4)?;
		// Shape-checked, because the fifth word being an address is the whole
		// assumption: six hex pairs separated by colons.
		let looks_right = bssid.len() == 17
			&& bssid.split(':').count() == 6
			&& bssid
				.split(':')
				.all(|pair| pair.len() == 2 && pair.chars().all(|c| c.is_ascii_hexdigit()));
		looks_right.then_some(bssid)
	}
}

/// Decode `wpa_supplicant`'s escaping of a text field.
///
/// The supplicant does not hand back the octets it was given. It runs them
/// through `printf_encode`, which escapes a quote, a backslash, `\n`, `\r`,
/// `\t`, `\e`, and **every byte outside printable ASCII** as `\xHH`. So an
/// SSID of `caf\u{e9}` comes back as the eleven characters `caf\xc3\xa9`, and a
/// reader that takes the field literally shows that to the operator.
///
/// This was found by running against a real supplicant rather than by reading
/// the documentation, which does not mention it. Returns octets rather than a
/// string because the encoding is bytewise: a multi-byte character arrives as
/// several `\xHH` escapes and only becomes text again once they are joined.
#[must_use]
pub fn printf_decode(text: &str) -> Vec<u8> {
	let source = text.as_bytes();
	let mut out = Vec::with_capacity(source.len());
	let mut index = 0;
	while index < source.len() {
		if source[index] != b'\\' {
			out.push(source[index]);
			index += 1;
			continue;
		}
		// A trailing backslash is not an escape. Keeping it is what the
		// supplicant's own decoder does.
		let Some(&escape) = source.get(index + 1) else {
			out.push(b'\\');
			break;
		};
		match escape {
			b'n' => out.push(b'\n'),
			b'r' => out.push(b'\r'),
			b't' => out.push(b'\t'),
			b'e' => out.push(0x1b),
			b'x' => {
				// Two hex digits, or it was never an escape. The index only
				// advances past what was actually consumed, so a malformed
				// one loses nothing -- `\xzz` is four characters of a name,
				// not a decode failure.
				let high = source.get(index + 2).copied().and_then(hex_value);
				let low = source.get(index + 3).copied().and_then(hex_value);
				if let (Some(high), Some(low)) = (high, low) {
					out.push((high << 4) | low);
					index += 4;
				} else {
					out.extend_from_slice(b"\\x");
					index += 2;
				}
				continue;
			}
			// `\\`, `\"`, and anything else: the character itself. Matching
			// the supplicant's decoder, which passes unknown escapes through.
			other => out.push(other),
		}
		index += 2;
	}
	out
}

fn hex_value(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

/// One scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
	/// The access point's address.
	pub bssid: String,
	/// Centre frequency in MHz.
	pub frequency: u32,
	/// Signal level in dBm.
	pub signal: i32,
	/// The flags string, for example `[WPA2-PSK-CCMP][ESS]`.
	pub flags: String,
	/// The network name, as octets.
	pub ssid: Ssid,
}

impl ScanResult {
	/// Whether this access point requires a passphrase.
	#[must_use]
	pub fn is_secured(&self) -> bool {
		self.flags.contains("WPA") || self.flags.contains("WEP") || self.flags.contains("SAE")
	}

	/// Whether it advertises 802.11r fast transition.
	///
	/// Read from the flags, which cost nothing because they are already
	/// parsed: `wpa_supplicant` spells the key management `FT/PSK`, `FT/SAE`
	/// or `FT/EAP` when the BSS does it. This is not the mobility *domain* --
	/// two access points can both do fast transition and belong to different
	/// domains -- it is the cheap test for whether asking about the domain is
	/// worth a round trip at all.
	#[must_use]
	pub fn does_fast_transition(&self) -> bool {
		self.flags.contains("FT/")
	}
}

/// The mobility domain id from a `BSS <bssid>` reply.
///
/// **802.11r, and what it is for.** Access points an operator configured into
/// one mobility domain advertise the same two-octet id, and a client that has
/// done the initial handshake with any of them can transition to another
/// without a full re-authentication. It is the only standard, machine-readable
/// statement that two BSSes belong to one system -- everything else (adjacent
/// addresses, a shared manufacturer prefix) is convention.
///
/// **It is not a trust signal, and nothing here should treat it as one.** The
/// element is unauthenticated bytes in a beacon, so anything can advertise any
/// id. What it is good for is diagnosis: two access points a client will not
/// roam between, both claiming fast transition, are worth looking at
/// differently depending on whether they claim the same domain.
///
/// Absent rather than guessed when the reply has no `mdid=`, which is the
/// ordinary case for a BSS that does not do fast transition at all.
#[must_use]
pub fn parse_mobility_domain(body: &str) -> Option<String> {
	body.lines()
		.find_map(|line| line.strip_prefix("mdid="))
		.map(str::trim)
		.filter(|id| !id.is_empty())
		.map(str::to_owned)
}

/// Parse `SCAN_RESULTS`.
///
/// The first line is a header and is skipped. A row netcfgd cannot make sense
/// of is skipped rather than failing the whole scan: one malformed entry from
/// a misbehaving access point should not make a laptop unable to list
/// networks.
#[must_use]
pub fn parse_scan_results(body: &str) -> Vec<ScanResult> {
	body.lines()
		.skip(1)
		.filter_map(|line| {
			let mut fields = line.split('\t');
			let bssid = fields.next()?.to_owned();
			let frequency = fields.next()?.parse().ok()?;
			let signal = fields.next()?.parse().ok()?;
			let flags = fields.next()?.to_owned();
			// The SSID is the last field and is escaped, so a tab inside a
			// name arrives as `\t` and cannot be confused with a separator.
			// Taking the remainder anyway costs nothing and means a future
			// column added to the end does not silently truncate names.
			let ssid = fields.collect::<Vec<_>>().join("\t");
			Some(ScanResult {
				bssid,
				frequency,
				signal,
				flags,
				ssid: Ssid::new(printf_decode(&ssid)).ok()?,
			})
		})
		.collect()
}

/// One entry of `LIST_NETWORKS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEntry {
	/// The supplicant's id for it.
	pub id: u32,
	/// Its name, decoded from the supplicant's escaping.
	pub ssid: Ssid,
	/// Flags such as `[CURRENT]` or `[DISABLED]`.
	pub flags: String,
}

impl NetworkEntry {
	/// Whether this is the network currently selected.
	#[must_use]
	pub fn is_current(&self) -> bool {
		self.flags.contains("CURRENT")
	}
}

/// Parse `LIST_NETWORKS`.
#[must_use]
pub fn parse_network_list(body: &str) -> Vec<NetworkEntry> {
	body.lines()
		.skip(1)
		.filter_map(|line| {
			let mut fields = line.split('\t');
			let id = fields.next()?.parse().ok()?;
			let ssid = Ssid::new(printf_decode(fields.next()?)).ok()?;
			let _bssid = fields.next()?;
			let flags = fields.next().unwrap_or("").to_owned();
			Some(NetworkEntry { id, ssid, flags })
		})
		.collect()
}

/// Parse `STATUS`, which is `key=value` lines.
#[must_use]
pub fn parse_status(body: &str) -> Vec<(String, String)> {
	body.lines()
		.filter_map(|line| {
			let (key, value) = line.split_once('=')?;
			Some((key.to_owned(), value.to_owned()))
		})
		.collect()
}

/// The value of one `STATUS` key.
#[must_use]
pub fn status_field<'a>(status: &'a [(String, String)], key: &str) -> Option<&'a str> {
	status
		.iter()
		.find(|(name, _)| name == key)
		.map(|(_, value)| value.as_str())
}

/// Render an SSID for `SET_NETWORK`, as hex.
///
/// `wpa_supplicant` accepts either a quoted string or an unquoted hex blob, and
/// netcfgd always sends hex. Three reasons, in increasing order of how much
/// they matter:
///
/// - The model already stores an SSID as octets with hex as its canonical
///   encoding, so this is a direct mapping rather than a conversion.
/// - An SSID is not required to be UTF-8, and quoting one that is not means
///   choosing an escaping scheme for bytes that have no text.
/// - An SSID is 32 arbitrary octets chosen by whoever named the network, and
///   quoting is where a value from a config file becomes protocol syntax. A
///   network called `"; REMOVE_NETWORK all; "` should be a network with a
///   silly name, not a command. Hex removes the question rather than
///   answering it carefully.
#[must_use]
pub fn ssid_argument(ssid: &Ssid) -> String {
	ssid.to_hex()
}

/// Render a passphrase for `SET_NETWORK psk`.
///
/// Unlike an SSID this cannot be hex: an unquoted 64-character hex value means
/// a pre-computed PMK rather than a passphrase, so a quoted string is the only
/// way to say "this is the text the user typed". The escaping is therefore
/// load-bearing, and the same injection concern applies.
///
/// `wpa_supplicant`'s parser understands C-style escapes inside quotes, so a
/// quote and a backslash are the two characters that must not pass through
/// unaltered.
#[must_use]
pub fn passphrase_argument(passphrase: &str) -> String {
	let mut out = String::with_capacity(passphrase.len() + 2);
	out.push('"');
	for character in passphrase.chars() {
		match character {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			other => out.push(other),
		}
	}
	out.push('"');
	out
}

/// Whether a passphrase can be sent at all.
///
/// A newline would end the command, and everything after it would be read as
/// the next one. There is no escape for it in the control protocol, so the
/// only safe answer is to refuse -- WPA passphrases are 8 to 63 printable
/// characters, so nothing legitimate is being turned away.
#[must_use]
pub fn passphrase_is_sendable(passphrase: &str) -> bool {
	!passphrase.contains(['\n', '\r', '\0'])
}
