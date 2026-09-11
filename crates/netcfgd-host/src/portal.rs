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

/// The name this binary answers to when it is its own probe.
///
/// Never installed and never a symlink: `netcfgd` execs itself with this in
/// `argv[0]`, so the only way to reach it is to be netcfgd. A copy of the
/// binary renamed to it by hand resolves a URL and prints a status line with
/// no privileges, which is a thing anybody could already do with `curl`.
pub const HELPER_NAME: &str = "netcfgd-probe";

/// How long the child may live, whatever it is doing.
///
/// One second past the socket deadline, so that a stuck read is reported as a
/// read that did not finish rather than as a child that was killed.
const CHILD_LIFETIME: u32 = 6;

/// Fetch the URL and say what answered -- from a child that holds nothing.
///
/// **The parent must not do this itself, and the reason is `getaddrinfo`.**
/// Resolving the URL means glibc's resolver, its NSS modules, and a DNS
/// response chosen by the network being probed, all in C. Running that in the
/// process holding `CAP_NET_ADMIN` is the arrangement CVE-2015-7547 turned
/// into a root compromise on a great many machines. Decision 0162.
///
/// **`exec`, not just `fork`.** netcfgd is multithreaded -- the rfkill
/// watcher, one thread per control connection -- and after `fork` a child of a
/// multithreaded process may call only async-signal-safe functions until it
/// execs, because another thread may have been holding malloc's lock at the
/// moment of the fork. `getaddrinfo` allocates. So the child is a fresh
/// single-threaded image of this same binary, invoked under [`HELPER_NAME`],
/// which is what the multi-call layout is for.
///
/// **The child bounds itself.** It sets an alarm before doing anything, so
/// reading its output to end of file cannot hang: end of file is the child
/// exiting, and the child cannot outlive its alarm.
///
/// `expect` is the status that means nothing is in the way -- 204 by
/// convention, which is what a `generate_204` endpoint is for.
#[must_use]
pub fn probe(url: &str, expect: u16) -> Verdict {
	use std::os::unix::process::CommandExt as _;

	let child = std::process::Command::new("/proc/self/exe")
		.arg0(HELPER_NAME)
		.arg(url)
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::null())
		.output();

	let output = match child {
		Ok(output) => output,
		// `/proc/self/exe` is how a process finds its own image, and a machine
		// without `/proc` is one where this cannot be done safely at all --
		// so it is not done unsafely instead.
		Err(error) => {
			return Verdict::Unreachable {
				detail: format!("could not start the probe helper: {error}"),
			}
		}
	};

	let said = String::from_utf8_lossy(&output.stdout)
		.trim_end()
		.to_owned();
	match output.status.code() {
		Some(0) => verdict(&said, expect),
		Some(1) => Verdict::Unreachable { detail: said },
		// The child refused to do the work because it could not give up what
		// it holds. Reported as its own sentence: a probe that ran anyway
		// would be the thing this exists to prevent, quietly.
		Some(2) => Verdict::Unreachable {
			detail: format!(
				"the probe helper would not drop its privileges, so it did not run: {said}"
			),
		},
		// Killed, which on this path means its own alarm.
		None => Verdict::Unreachable {
			detail: format!("the probe of {url} did not finish"),
		},
		Some(other) => Verdict::Unreachable {
			detail: format!("the probe helper exited with {other}"),
		},
	}
}

/// The child: give everything up, then do the hostile part.
///
/// Exits 0 with the status line on stdout, 1 with a reason, or 2 when it could
/// not shed privilege -- in which case it has done nothing else.
#[must_use]
pub fn helper_main() -> std::process::ExitCode {
	let Some(url) = std::env::args().nth(1) else {
		println!("usage: {HELPER_NAME} <url>");
		return std::process::ExitCode::from(1);
	};

	// Before the alarm and before anything is resolved or opened. A failure
	// here is the whole reason to stop.
	match netcfgd_sys::privilege::shed() {
		// Always said, and always to stderr, which the parent discards. It
		// costs nothing in production and it is how a test watching this
		// child can tell which of the two it got.
		Ok(reached) => eprintln!("{HELPER_NAME}: {}", reached.describe()),
		Err(error) => {
			println!("{error}");
			return std::process::ExitCode::from(2);
		}
	}
	netcfgd_sys::privilege::die_after(CHILD_LIFETIME);

	match fetch(&url) {
		Ok(status) => {
			println!("{status}");
			std::process::ExitCode::SUCCESS
		}
		Err(detail) => {
			println!("{detail}");
			std::process::ExitCode::from(1)
		}
	}
}

/// Resolve, connect, and read back the status line. Runs only in the child.
fn fetch(url: &str) -> Result<String, String> {
	let Some((target, path)) = split(url) else {
		return Err(format!("`{url}` is not a URL this can fetch"));
	};

	// Resolution is the first thing a portal interferes with and the first
	// thing that fails on a network with none, so its failure is reported as
	// its own sentence rather than folded into "could not connect".
	let mut addresses = match target.to_socket_addrs() {
		Ok(addresses) => addresses,
		Err(error) => return Err(format!("cannot resolve {target}: {error}")),
	};
	let Some(address) = addresses.next() else {
		return Err(format!("{target} resolved to nothing"));
	};

	let stream = match TcpStream::connect_timeout(&address, DEADLINE) {
		Ok(stream) => stream,
		Err(error) => return Err(format!("cannot reach {target}: {error}")),
	};
	let _ = stream.set_read_timeout(Some(DEADLINE));
	let _ = stream.set_write_timeout(Some(DEADLINE));

	exchange(stream, &target, &path).map_err(|error| format!("{target} did not answer: {error}"))
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

/// As much of a hostile answer as is safe to repeat.
///
/// **This string reaches a root shell.** A `Portal` verdict's `detail` becomes
/// `NCFG_REASON` for the `portal`-phase hooks, which netcfgd runs as root, and
/// on this branch the content is whatever answered on port 80 -- a machine on
/// a network this has already decided not to trust. It was passed through
/// `{:?}`, which escapes quotes, newlines and non-printables and leaves
/// `` ` ``, `$`, `;`, `|`, `&` and `*` exactly as they arrived.
///
/// An environment variable is not re-parsed by a shell, and an unquoted
/// expansion word-splits and globs rather than running anything, so this is not
/// command injection by itself. It is attacker-chosen text in a root script's
/// environment, which is a thing to hand somebody only if they asked for it --
/// and a hook that `eval`s its reason is a mistake netcfgd should not be making
/// possible.
///
/// So: printable ASCII from a small set, everything else a dot, and 64
/// characters. `HTTP/1.0 302 Found` survives intact, which is the case an
/// operator is actually reading this for.
fn legible(text: &str) -> String {
	const KEEP: &str = " .,:/-_=";
	let mut out: String = text
		.chars()
		.take(64)
		.map(|c| {
			if c.is_ascii_alphanumeric() || KEEP.contains(c) {
				c
			} else {
				'.'
			}
		})
		.collect();
	if text.chars().nth(64).is_some() {
		out.push_str("...");
	}
	out
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
			detail: format!(
				"the answer was not an HTTP status line: {}",
				legible(status_line)
			),
		},
	}
}

#[cfg(test)]
mod tests {
	/// **The verdict is what reaches the hook, so the verdict is what is
	/// asserted.**
	///
	/// The test below covers `legible` and would stay green with the call site
	/// bypassed -- measured, by bypassing it. This drives `verdict`, which is
	/// the function whose output becomes `NCFG_REASON`, and it is the one that
	/// fails when the sanitising is skipped rather than merely removed.
	#[test]
	fn the_detail_a_hook_receives_is_sanitised() {
		let nasty = "\x16\x03\x01 $(id) `id` ; rm -rf / | tee & glob*";
		let Verdict::Portal { detail } = super::verdict(nasty, 204) else {
			panic!("something answered and it was not HTTP, so this is a portal");
		};
		for bad in ['$', '`', ';', '|', '&', '*'] {
			assert!(
				!detail.contains(bad),
				"`{bad}` reached the hook environment in `{detail}`"
			);
		}
		// Still says what happened, or it is not a diagnostic.
		assert!(detail.contains("not an HTTP status line"), "{detail}");

		// And the ordinary case is untouched: a real portal's code is a number
		// and says which one.
		let Verdict::Portal { detail } = super::verdict("HTTP/1.1 302 Found", 204) else {
			panic!("302 is not 204");
		};
		assert_eq!(detail, "expected 204, got 302");
	}

	/// **What a hostile answer may put in a root script's environment.**
	///
	/// A `Portal` verdict's detail becomes `NCFG_REASON` for the `portal`
	/// hooks, which run as root. This branch carries whatever answered on
	/// port 80, so the characters a careless hook could be hurt by are the
	/// ones to remove -- and the ones an operator reads it for are the ones
	/// to keep.
	#[test]
	fn a_hostile_answer_reaches_the_hook_declawed() {
		// The case this exists for: it stays readable.
		assert_eq!(legible("HTTP/1.0 302 Found"), "HTTP/1.0 302 Found");

		// And the case it exists against.
		let nasty = "$(id);`id`;rm -rf /|tee&x*?<>'\"\\";
		let out = legible(nasty);
		for bad in ['$', '`', ';', '|', '&', '*', '?', '<', '>', '\'', '"', '\\'] {
			assert!(!out.contains(bad), "`{bad}` survived into `{out}`");
		}

		// Bounded, because 1024 bytes of somebody else's choosing is not a
		// diagnostic.
		let long = legible(&"A".repeat(500));
		assert_eq!(long.len(), 67, "64 kept plus an ellipsis: {long}");
	}

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
