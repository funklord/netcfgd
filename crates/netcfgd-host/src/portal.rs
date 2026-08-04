//! Is something answering requests that were not meant for it?
//!
//! A captive portal gives a machine an address, a gateway and a DNS server, and
//! then answers every request with its own login page. Everything looks
//! configured and nothing works, which is the failure an operator spends
//! twenty minutes on before thinking to open a browser.
//!
//! **The URL is the operator's.** 0061 refused a boolean with an address inside
//! netcfgd and 0095 kept that: a daemon reaching out to a fixed host to decide
//! whether the internet works is a third party being told when this machine
//! joins a network. No URL, no probe -- which is every machine that did not ask.
//!
//! **In clear, always.** A portal detects by intercepting, and TLS exists to
//! stop interception: over `https` a portal produces a certificate error rather
//! than a redirect, so a check that cannot be intercepted cannot detect
//! interception. The compiler refuses an `https` URL with that sentence.
//!
//! No HTTP library. The request is one line and the answer that matters is the
//! status on the first line of the response -- reading further would mean
//! parsing a body this does not care about, from a host it has already decided
//! not to trust.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long the whole probe may take.
///
/// A portal answers immediately -- it is on the local network and it wants to
/// be found. A network with no route anywhere hangs, and this is what stops
/// that hanging anything else. Short enough that a laptop is not waiting on it,
/// long enough that a slow but working link is not called a portal.
const DEADLINE: Duration = Duration::from_secs(5);

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
	/// The expected answer arrived: nothing is in the way.
	Clear,
	/// Something answered, and not with what was asked for.
	Portal {
		/// What it said, for the operator and for the hook.
		detail: String,
	},
	/// Nothing answered. Not a portal -- a portal is a thing that *replies*.
	Unreachable {
		/// Why, in the words of whatever failed.
		detail: String,
	},
}

/// Whether an address is one that could reach anything.
///
/// **A link-local is not connectivity**, and this is the whole of why it
/// matters here: every interface that is up has an `fe80::` address the moment
/// the kernel brings it up, so a check for "has an address" is true from the
/// instant the link exists and never changes. A probe that fired on that
/// transition would fire once, at startup, and never again on any real machine
/// -- which is what the first version of this did.
///
/// An IPv4 link-local (`169.254.`) is the same statement in the other family:
/// the machine gave up on DHCP and picked an address, which is not a network
/// that can be behind a portal.
#[must_use]
pub fn is_routable(address: &str) -> bool {
	// The address may carry a prefix length; the family is decided by what is
	// in front of it.
	let host = address.split('/').next().unwrap_or(address);
	let lower = host.to_ascii_lowercase();

	!(lower.starts_with("fe80:")
		|| lower.starts_with("169.254.")
		|| lower.starts_with("127.")
		|| lower == "::1")
}

/// Split `http://host[:port]/path` into what a request needs.
///
/// Returns the authority to connect to and the path to ask for. Not a general
/// URL parser: the compiler has already refused anything that is not
/// `http://` with a host, so this is the rest of that same shape.
fn split(url: &str) -> Option<(String, String)> {
	let rest = url.strip_prefix("http://")?;
	let (authority, path) = match rest.find('/') {
		Some(at) => (&rest[..at], &rest[at..]),
		None => (rest, "/"),
	};
	if authority.is_empty() {
		return None;
	}
	// The `Host:` header is the authority as written, port and all, which is
	// what a server expects; the connect target needs a port whether or not the
	// URL gave one.
	let target = if authority.contains(':') {
		authority.to_owned()
	} else {
		format!("{authority}:80")
	};
	Some((target, path.to_owned()))
}

/// Fetch the URL and say what answered.
///
/// `expect` is the status that means nothing is in the way -- 204 by
/// convention, which is what a `generate_204` endpoint is for.
#[must_use]
pub fn probe(url: &str, expect: u16) -> Verdict {
	let Some((target, path)) = split(url) else {
		return Verdict::Unreachable {
			detail: format!("`{url}` is not a URL this can fetch"),
		};
	};

	// Resolution is the first thing a portal interferes with and the first
	// thing that fails on a network with none, so its failure is reported as
	// its own sentence rather than folded into "could not connect".
	let mut addresses = match target.to_socket_addrs() {
		Ok(addresses) => addresses,
		Err(error) => {
			return Verdict::Unreachable {
				detail: format!("cannot resolve {target}: {error}"),
			}
		}
	};
	let Some(address) = addresses.next() else {
		return Verdict::Unreachable {
			detail: format!("{target} resolved to nothing"),
		};
	};

	let stream = match TcpStream::connect_timeout(&address, DEADLINE) {
		Ok(stream) => stream,
		Err(error) => {
			return Verdict::Unreachable {
				detail: format!("cannot reach {target}: {error}"),
			}
		}
	};
	let _ = stream.set_read_timeout(Some(DEADLINE));
	let _ = stream.set_write_timeout(Some(DEADLINE));

	match exchange(stream, &target, &path) {
		Ok(status) => verdict(&status, expect),
		Err(error) => Verdict::Unreachable {
			detail: format!("{target} did not answer: {error}"),
		},
	}
}

/// Send the request and read back the status line's code.
fn exchange(mut stream: TcpStream, host: &str, path: &str) -> std::io::Result<String> {
	// `Connection: close` so the server hangs up rather than waiting for a
	// second request this will never send -- without it the read below waits
	// out the deadline on every well-behaved server.
	let request = format!(
		"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netcfgd\r\n\
		 Accept: */*\r\nConnection: close\r\n\r\n"
	);
	stream.write_all(request.as_bytes())?;
	stream.flush()?;

	// The status line and nothing more. Bounded because the far side is a host
	// this has already decided not to trust: a portal that answered forever
	// would otherwise be a portal that hung netcfgd.
	let mut buffer = [0_u8; 1024];
	let mut filled = 0;
	while filled < buffer.len() {
		let read = stream.read(&mut buffer[filled..])?;
		if read == 0 {
			break;
		}
		filled += read;
		if buffer[..filled].windows(2).any(|pair| pair == b"\r\n") {
			break;
		}
	}
	Ok(String::from_utf8_lossy(&buffer[..filled])
		.lines()
		.next()
		.unwrap_or("")
		.to_owned())
}

/// A status line into a verdict.
fn verdict(status_line: &str, expect: u16) -> Verdict {
	// `HTTP/1.1 204 No Content` -- the code is the second word.
	let code = status_line
		.split_whitespace()
		.nth(1)
		.and_then(|code| code.parse::<u16>().ok());

	match code {
		Some(code) if code == expect => Verdict::Clear,
		Some(code) => Verdict::Portal {
			detail: format!("expected {expect}, got {code}"),
		},
		// Something answered on port 80 and it was not HTTP. That is not
		// "unreachable" -- something is there -- and calling it clear would be
		// worse than calling it a portal.
		None => Verdict::Portal {
			detail: format!("the answer was not an HTTP status line: {status_line:?}"),
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A link-local address is not a network to check.
	///
	/// Every up interface has an `fe80::` one, so treating it as connectivity
	/// makes "became addressed" true from the moment the link exists -- and a
	/// probe that fires on that transition fires once, at startup, and never
	/// again. Found by watching a real daemon miss the second join.
	#[test]
	fn a_link_local_address_is_not_connectivity() {
		for local in [
			"fe80::ccdf:86ff:fe9c:f9c7/64",
			"FE80::1",
			"169.254.10.4/16",
			"127.0.0.1/8",
			"::1",
		] {
			assert!(!is_routable(local), "{local} should not count");
		}
		for real in [
			"10.3.3.1/24",
			"192.0.2.7",
			"2001:db8::5/64",
			"203.0.113.9/32",
		] {
			assert!(is_routable(real), "{real} should count");
		}
	}

	#[test]
	fn a_url_splits_into_what_a_request_needs() {
		assert_eq!(
			split("http://example.com/generate_204"),
			Some(("example.com:80".to_owned(), "/generate_204".to_owned()))
		);
		// No path is a request for the root, which is what a browser does.
		assert_eq!(
			split("http://example.com"),
			Some(("example.com:80".to_owned(), "/".to_owned()))
		);
		// An explicit port is kept, and stays in the Host header too.
		assert_eq!(
			split("http://example.com:8080/x"),
			Some(("example.com:8080".to_owned(), "/x".to_owned()))
		);
		assert_eq!(split("https://example.com/x"), None);
		assert_eq!(split("http:///x"), None);
	}

	/// The expected status is clear and anything else is not.
	#[test]
	fn a_status_line_decides() {
		assert_eq!(verdict("HTTP/1.1 204 No Content", 204), Verdict::Clear);

		// The two a portal actually produces: a redirect to its login page, or
		// the page itself with a 200.
		for line in ["HTTP/1.1 302 Found", "HTTP/1.1 200 OK"] {
			assert!(
				matches!(verdict(line, 204), Verdict::Portal { .. }),
				"{line} should be a portal"
			);
		}
	}

	/// Something answering with something that is not HTTP is not "clear".
	///
	/// A transparent proxy that speaks nothing recognisable is still something
	/// in the way, and the safe reading of an unparseable answer is that the
	/// network is not what it claims -- not that everything is fine.
	#[test]
	fn an_answer_that_is_not_http_is_not_clear() {
		for line in ["", "hello", "220 smtp ready"] {
			assert!(
				matches!(verdict(line, 204), Verdict::Portal { .. }),
				"{line:?} should not read as clear"
			);
		}
	}
}
