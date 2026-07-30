//! `ncfg tui`: the full-screen client.
//!
//! Design section 7.2. The machines that most need netcfgd are reached over
//! SSH, where a tray applet is useless and `nmtui` has long been the least-bad
//! option.
//!
//! **It speaks the public socket and nothing else** (principle 9). There is no
//! private request, no shortcut through the compiler, and nothing here that a
//! third-party client could not do. That is not politeness -- it is the test
//! that keeps the socket honest, because a pane that needed something the
//! socket could not express would mean the socket gets it, publicly.
//!
//! Answers are read as `serde_json::Value` rather than as the typed
//! `Response`, for the reason `client::Answer` is narrow: the derived
//! deserialiser for the full document is hundreds of kilobytes, and the whole
//! install is 1.75 MB. A pane reads the four fields it draws.
//!
//! Degrades as section 7.2 requires: 80x24, no mouse, and no colour or
//! unicode. Emphasis is reverse video, which every terminal back to a VT100
//! has, and `$NO_COLOR` turns even that off.

use crate::client;
use crate::Options;
use netcfgd_host::state;
use netcfgd_netlink::term;
use netcfgd_proto::Request;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

/// Which pane is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
	Devices,
	Wifi,
	Plan,
	Events,
}

impl Pane {
	fn title(self) -> &'static str {
		match self {
			Self::Devices => "devices",
			Self::Wifi => "wifi",
			Self::Plan => "plan",
			Self::Events => "events",
		}
	}
}

/// How many events to keep. A screenful on a tall terminal, and bounded
/// because this runs for days on a server and the ring is in RAM.
const EVENT_HISTORY: usize = 200;

/// Everything drawn, refetched when a pane is entered or `r` is pressed.
struct App {
	pane: Pane,
	selected: usize,
	/// The last error or confirmation, shown on the status line until the next
	/// action replaces it.
	message: String,
	status: Option<serde_json::Value>,
	plan: Option<serde_json::Value>,
	scan: Option<serde_json::Value>,
	events: Arc<Mutex<Vec<String>>>,
	socket: std::path::PathBuf,
	colour: bool,
}

/// Run the TUI until `q`.
///
/// # Errors
///
/// Returns a message naming what could not be reached. Refuses when standard
/// input is not a terminal rather than writing escape sequences into a pipe.
pub(crate) fn run(options: &Options) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let socket = client::socket_path(&run_dir);

	// Checked before the terminal is touched, so a machine with no daemon gets
	// a sentence rather than a cleared screen and a sentence.
	client::ask(&socket, &Request::Hello)?;

	let (raw, _) = term::enter().map_err(|error| {
		format!("{error}\n`ncfg tui` needs a terminal; for a pipe use `ncfg status --json`")
	})?;
	raw.set_read_timeout(10)
		.map_err(|error| format!("cannot set a read timeout: {error}"))?;

	let mut app = App {
		pane: Pane::Devices,
		selected: 0,
		message: String::from("? for keys"),
		status: None,
		plan: None,
		scan: None,
		events: Arc::new(Mutex::new(Vec::new())),
		socket: socket.clone(),
		colour: std::env::var_os("NO_COLOR").is_none(),
	};
	subscribe(&socket, &app.events);

	let mut out = std::io::stdout();
	// Alternate screen and no cursor. Both are undone before returning, on
	// every path, or the operator gets their shell back with an invisible
	// cursor.
	let _ = out.write_all(b"\x1b[?1049h\x1b[?25l");
	app.refresh();

	let result = event_loop(&mut app, &raw, &mut out);

	let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
	let _ = out.flush();
	drop(raw);
	result
}

/// Read keys and redraw until asked to stop.
fn event_loop(
	app: &mut App,
	raw: &term::RawMode,
	out: &mut std::io::Stdout,
) -> Result<ExitCode, String> {
	let mut input = std::io::stdin();
	loop {
		// Re-read the size every frame rather than catching SIGWINCH, which
		// would need a signal handler. One ioctl per second costs nothing and
		// it makes a resize just work.
		let size = term::size(raw.fd());
		let frame = draw(app, size);
		let _ = out.write_all(frame.as_bytes());
		let _ = out.flush();

		let mut byte = [0u8; 1];
		let read = input.read(&mut byte).unwrap_or(0);
		if read == 0 {
			// The timeout expired. Events may have arrived, so redraw; and on
			// the panes that watch the machine, refetch.
			if matches!(app.pane, Pane::Devices | Pane::Plan) {
				app.refresh();
			}
			continue;
		}
		if !app.key(byte[0]) {
			return Ok(ExitCode::SUCCESS);
		}
	}
}

/// Subscribe to the event stream on a thread of its own.
///
/// A thread rather than multiplexing the socket with the keyboard, because the
/// alternative is `poll` on two descriptors and this client has no other
/// reason to reach for one. It is detached: when the process ends the thread
/// goes with it, and a daemon restart ends the stream, which the pane says.
fn subscribe(socket: &std::path::Path, events: &Arc<Mutex<Vec<String>>>) {
	let socket = socket.to_path_buf();
	let events = Arc::clone(events);
	std::thread::spawn(move || {
		let sink = |line: String| {
			if let Ok(mut held) = events.lock() {
				held.push(line);
				let excess = held.len().saturating_sub(EVENT_HISTORY);
				held.drain(..excess);
			}
		};
		match client::stream_lines(&socket, &sink) {
			Ok(()) => sink("-- the daemon closed the stream --".to_owned()),
			Err(error) => sink(format!("-- the stream ended: {error} --")),
		}
	});
}

impl App {
	/// Re-ask the daemon for whatever the current pane draws.
	fn refresh(&mut self) {
		match self.pane {
			Pane::Devices => self.status = self.fetch(&Request::Status),
			Pane::Plan => self.plan = self.fetch(&Request::Plan),
			Pane::Wifi => {
				// Status first: the scan needs an interface name, and the
				// operator should not have to supply one they can see.
				self.status = self.fetch(&Request::Status);
				if let Some(interface) = self.radio() {
					self.scan = self.fetch(&Request::WifiScan { interface });
				} else {
					"no wireless device in the configuration".clone_into(&mut self.message);
				}
			}
			Pane::Events => {}
		}
	}

	fn fetch(&mut self, request: &Request) -> Option<serde_json::Value> {
		match client::ask_value(&self.socket, request) {
			Ok(value) => {
				if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
					message.clone_into(&mut self.message);
					return None;
				}
				Some(value)
			}
			Err(error) => {
				self.message = error;
				None
			}
		}
	}

	/// The first interface whose observed link looks like a radio.
	///
	/// From the status answer rather than from the config, because the pane is
	/// drawing what the machine has.
	fn radio(&self) -> Option<String> {
		let links = self.status.as_ref()?.get("links")?.as_array()?;
		links
			.iter()
			.find(|link| {
				link.get("kind").and_then(serde_json::Value::as_str) == Some("wlan")
					|| link
						.get("name")
						.and_then(serde_json::Value::as_str)
						.is_some_and(|name| name.starts_with("wl"))
			})
			.and_then(|link| link.get("name")?.as_str())
			.map(ToOwned::to_owned)
	}

	/// Handle one keystroke. Returns false to quit.
	fn key(&mut self, byte: u8) -> bool {
		match byte {
			// `q` and ^C are the same thing: in raw mode ISIG is off, so ^C is
			// a byte, and treating it as anything but "leave" would strand
			// somebody whose reflex it is.
			b'q' | 0x03 => return false,
			b'd' => self.go(Pane::Devices),
			b'w' => self.go(Pane::Wifi),
			b'p' => self.go(Pane::Plan),
			b'e' => self.go(Pane::Events),
			b'r' => {
				"refreshed".clone_into(&mut self.message);
				self.refresh();
			}
			b'j' => self.selected = self.selected.saturating_add(1),
			b'k' => self.selected = self.selected.saturating_sub(1),
			b'a' if self.pane == Pane::Plan => self.apply(),
			b'c' if self.pane == Pane::Wifi => self.connect(),
			// The other half of `a`. Offering the window and then not
			// answering these would be worse than not offering it: the
			// operator would sit through the timeout believing they had
			// confirmed.
			b'y' => self.settle(&Request::Confirm, "confirmed; the change stands"),
			b'n' => self.settle(&Request::Revert, "reverted to the last-good configuration"),
			b'?' => HELP.clone_into(&mut self.message),
			_ => {}
		}
		true
	}

	fn go(&mut self, pane: Pane) {
		self.pane = pane;
		self.selected = 0;
		self.refresh();
	}

	/// Apply, always inside a confirm window.
	///
	/// Section 7.2 is explicit that this is the context where you are one bad
	/// route away from losing the session, so there is no unprotected apply
	/// here at all -- not a default that can be turned off, an absence.
	fn apply(&mut self) {
		let request = Request::Apply {
			confirm: Some(60),
			allow_disruption: Vec::new(),
		};
		match client::ask(&self.socket, &request) {
			Ok(client::Answer::Error { message }) => self.message = message,
			Ok(_) => {
				"applied with a 60s window -- press y to keep it, n to undo now"
					.clone_into(&mut self.message);
			}
			Err(error) => self.message = error,
		}
		self.refresh();
	}

	/// Join the selected network, if the configuration describes it.
	fn connect(&mut self) {
		let Some(entry) = self.scan_entries().get(self.selected).cloned() else {
			return;
		};
		let Some(id) = entry.get("configured").and_then(serde_json::Value::as_str) else {
			// Decision 0013's boundary, said before it is hit rather than
			// discovered as a refusal.
			"that network is not in the configuration; `ncfg` cannot join it until it is"
				.clone_into(&mut self.message);
			return;
		};
		let Some(interface) = self.radio() else {
			return;
		};
		let request = Request::WifiConnect {
			interface,
			network: id.to_owned(),
		};
		match client::ask(&self.socket, &request) {
			Ok(client::Answer::Error { message }) => self.message = message,
			Ok(_) => self.message = format!("joining {id}"),
			Err(error) => self.message = error,
		}
	}

	/// Answer an open confirm window.
	fn settle(&mut self, request: &Request, done: &str) {
		match client::ask(&self.socket, request) {
			Ok(client::Answer::Error { message }) => self.message = message,
			Ok(_) => done.clone_into(&mut self.message),
			Err(error) => self.message = error,
		}
		self.refresh();
	}

	fn scan_entries(&self) -> Vec<serde_json::Value> {
		self.scan
			.as_ref()
			.and_then(|value| value.get("entries"))
			.and_then(serde_json::Value::as_array)
			.cloned()
			.unwrap_or_default()
	}
}

/// The footer. Always on screen, because a full-screen client that hides its
/// keys behind a keystroke is one nobody finds their way out of.
const KEYS: &str =
	"d devices  w wifi  p plan  e events | j/k move  r refresh  a apply  c connect  q quit";

/// What `?` adds: the things the footer cannot say in one line.
///
/// Not a repeat of `KEYS`. A help key that prints what is already on the
/// screen teaches the operator that help is useless.
const HELP: &str = "a applies with a 60s window: y keeps it, n undoes it now, \
	 nothing reverts it. `c` marks networks the config can join.";

/// Build one frame.
///
/// Returned as a string and written in one go, because writing line by line to
/// a terminal over SSH is what makes a redraw visibly crawl.
fn draw(app: &App, size: term::Size) -> String {
	let width = usize::from(size.columns).max(20);
	let height = usize::from(size.rows).max(6);
	let mut lines: Vec<String> = Vec::with_capacity(height);

	// Header: which pane, and which are available.
	let tabs: Vec<String> = [Pane::Devices, Pane::Wifi, Pane::Plan, Pane::Events]
		.iter()
		.map(|pane| {
			if *pane == app.pane {
				format!("[{}]", pane.title())
			} else {
				format!(" {} ", pane.title())
			}
		})
		.collect();
	lines.push(emphasise(
		&fit(&format!("ncfg  {}", tabs.join("")), width),
		app.colour,
	));

	let body_height = height.saturating_sub(3);
	let body = match app.pane {
		Pane::Devices => devices(app, width),
		Pane::Wifi => wifi(app, width),
		Pane::Plan => plan(app, width),
		Pane::Events => events(app, width),
	};

	// Scroll so the selection stays on screen, without a scrollbar to draw.
	let first = app.selected.saturating_sub(body_height.saturating_sub(1));
	for (index, line) in body.iter().skip(first).take(body_height).enumerate() {
		let selected = first + index == app.selected && app.pane != Pane::Events;
		lines.push(if selected {
			emphasise(&fit(line, width), app.colour)
		} else {
			fit(line, width)
		});
	}
	while lines.len() < height.saturating_sub(2) {
		lines.push(String::new());
	}

	lines.push(fit(&app.message, width));
	lines.push(emphasise(&fit(KEYS, width), app.colour));

	// Home, then each line cleared to its end. Clearing per line rather than
	// the whole screen first is what stops the display flickering on a slow
	// link.
	let mut frame = String::from("\x1b[H");
	for line in lines.iter().take(height) {
		frame.push_str(line);
		frame.push_str("\x1b[K\r\n");
	}
	frame.push_str("\x1b[J");
	frame
}

fn devices(app: &App, width: usize) -> Vec<String> {
	let Some(links) = app
		.status
		.as_ref()
		.and_then(|value| value.get("links"))
		.and_then(serde_json::Value::as_array)
	else {
		return vec!["(no status yet)".to_owned()];
	};
	let addresses = app
		.status
		.as_ref()
		.and_then(|value| value.get("addresses"))
		.and_then(serde_json::Value::as_array)
		.cloned()
		.unwrap_or_default();

	let mut out = Vec::new();
	for link in links {
		let name = string(link, "name");
		let up = link.get("up").and_then(serde_json::Value::as_bool) == Some(true);
		let carrier = link.get("carrier").and_then(serde_json::Value::as_bool) == Some(true);
		out.push(fit(
			&format!(
				"{:<14} {:<5} {:<10} mtu {}",
				name,
				if up { "up" } else { "down" },
				if carrier { "carrier" } else { "no carrier" },
				link.get("mtu")
					.and_then(serde_json::Value::as_u64)
					.unwrap_or(0)
			),
			width,
		));
		for address in &addresses {
			if string(address, "interface") == name {
				out.push(format!(
					"    {} [{}]",
					string(address, "address"),
					string(address, "ownership")
				));
			}
		}
	}
	if out.is_empty() {
		out.push("(no interfaces)".to_owned());
	}
	out
}

fn wifi(app: &App, width: usize) -> Vec<String> {
	let entries = app.scan_entries();
	if entries.is_empty() {
		return vec!["(no scan; press r to rescan)".to_owned()];
	}
	entries
		.iter()
		.map(|entry| {
			let name = entry
				.get("name")
				.and_then(serde_json::Value::as_str)
				.unwrap_or("<not text>");
			let signal = entry
				.get("signal")
				.and_then(serde_json::Value::as_i64)
				.unwrap_or(0);
			let secured = entry.get("secured").and_then(serde_json::Value::as_bool) == Some(true);
			// The marker that makes decision 0013's boundary visible: `c` is
			// joinable now, blank needs config written first.
			let known = if entry.get("configured").is_some() {
				"c"
			} else {
				" "
			};
			fit(
				&format!(
					"{known} {:<28} {:>4} dBm  {}",
					name,
					signal,
					if secured { "secured" } else { "open" }
				),
				width,
			)
		})
		.collect()
}

fn plan(app: &App, width: usize) -> Vec<String> {
	let Some(plan) = app.plan.as_ref() else {
		return vec!["(no plan yet)".to_owned()];
	};
	let actions = plan
		.get("actions")
		.and_then(serde_json::Value::as_array)
		.cloned()
		.unwrap_or_default();
	let mut out = Vec::new();

	if actions.is_empty() {
		out.push("nothing to do -- the machine matches the configuration".to_owned());
	}
	for action in &actions {
		let op = action
			.get("op")
			.and_then(|op| op.get("op"))
			.and_then(serde_json::Value::as_str)
			.unwrap_or("?");
		let reason = action.get("reason");
		let interface = reason
			.and_then(|r| r.get("interface"))
			.and_then(serde_json::Value::as_str)
			.unwrap_or("");
		let field = reason
			.and_then(|r| r.get("field"))
			.and_then(serde_json::Value::as_str)
			.unwrap_or("");
		let desired = reason
			.and_then(|r| r.get("desired"))
			.and_then(serde_json::Value::as_str)
			.unwrap_or("");
		let observed = reason
			.and_then(|r| r.get("observed"))
			.and_then(serde_json::Value::as_str)
			.unwrap_or("");
		out.push(fit(
			&format!("{op:<22} {interface:<12} {field}: {observed} -> {desired}"),
			width,
		));
	}

	for warning in plan
		.get("warnings")
		.and_then(serde_json::Value::as_array)
		.unwrap_or(&Vec::new())
	{
		out.push(fit(&format!("! {}", string(warning, "message")), width));
	}
	for refusal in plan
		.get("refusals")
		.and_then(serde_json::Value::as_array)
		.unwrap_or(&Vec::new())
	{
		out.push(fit(
			&format!(
				"refused {} on {}: {}",
				string(refusal, "op"),
				string(refusal, "interface"),
				string(refusal, "guard")
			),
			width,
		));
	}
	out
}

fn events(app: &App, width: usize) -> Vec<String> {
	let Ok(held) = app.events.lock() else {
		return vec!["(the event thread stopped)".to_owned()];
	};
	if held.is_empty() {
		return vec!["(waiting for events)".to_owned()];
	}
	held.iter().map(|line| fit(line, width)).collect()
}

/// A field as a string, or empty.
fn string(value: &serde_json::Value, key: &str) -> String {
	value
		.get(key)
		.and_then(serde_json::Value::as_str)
		.unwrap_or_default()
		.to_owned()
}

/// Pad or truncate to exactly `width` columns.
///
/// Counted in `char`s, which is right for the ASCII this project restricts
/// itself to and wrong for double-width glyphs -- an SSID can contain
/// anything. Truncation is what keeps a wide one from wrapping and pushing the
/// rest of the frame down a line.
fn fit(text: &str, width: usize) -> String {
	let mut out: String = text.chars().take(width).collect();
	let length = out.chars().count();
	if length < width {
		out.push_str(&" ".repeat(width - length));
	}
	out
}

/// Reverse video, or plain text where colour is off.
fn emphasise(text: &str, colour: bool) -> String {
	if colour {
		format!("\x1b[7m{text}\x1b[0m")
	} else {
		text.to_owned()
	}
}

#[cfg(test)]
mod tests {
	use super::{draw, fit, App, Pane};
	use netcfgd_netlink::term::Size;
	use std::sync::{Arc, Mutex};

	/// An app with canned answers and no daemon.
	///
	/// Drawing is a pure function of what the socket returned, which is what
	/// makes the layout testable with no terminal, no privileges and no
	/// kernel. The parts that need a real terminal are in `term`, and were
	/// checked against a pty.
	fn app(pane: Pane, status: &str, plan: &str) -> App {
		App {
			pane,
			selected: 0,
			message: "msg".to_owned(),
			status: serde_json::from_str(status).ok(),
			plan: serde_json::from_str(plan).ok(),
			scan: None,
			events: Arc::new(Mutex::new(Vec::new())),
			socket: std::path::PathBuf::from("/nonexistent"),
			colour: false,
		}
	}

	const STATUS: &str = r#"{
		"links": [{"name": "eth0", "up": true, "carrier": true, "mtu": 1500}],
		"addresses": [{"interface": "eth0", "address": "10.0.0.2/24", "ownership": "ours"}]
	}"#;

	const PLAN: &str = r#"{
		"actions": [{
			"op": {"op": "addr.add"},
			"reason": {"interface": "eth0", "field": "addressing",
			           "desired": "10.0.0.2/24", "observed": "<absent>"}
		}],
		"warnings": [{"message": "something worth knowing"}],
		"refusals": []
	}"#;

	/// Every line is exactly the terminal's width, so nothing wraps.
	///
	/// A single over-long line wraps and pushes the whole frame down one row,
	/// which on a full-screen client means the footer scrolls off and never
	/// comes back.
	#[test]
	fn every_line_is_exactly_the_width() {
		for columns in [80_u16, 100, 40] {
			let size = Size { rows: 24, columns };
			let frame = draw(&app(Pane::Devices, STATUS, PLAN), size);
			for line in frame.split("\r\n") {
				let text = line.replace("\x1b[H", "").replace("\x1b[K", "");
				if text.is_empty() || text.starts_with('\x1b') {
					continue;
				}
				assert_eq!(
					text.chars().count(),
					usize::from(columns),
					"at {columns} columns: {text:?}"
				);
			}
		}
	}

	/// It fills 80x24 exactly -- section 7.2's floor.
	///
	/// Equality rather than "at most", which is what this asserted first and
	/// which could not fail: the frame is built to a fixed length, so a bug
	/// that drew too few rows would have passed. Too few leaves the previous
	/// screen showing through the bottom of the pane.
	#[test]
	fn it_fills_eighty_by_twentyfour_exactly() {
		for size in [
			Size::default(),
			Size {
				rows: 40,
				columns: 132,
			},
		] {
			let frame = draw(&app(Pane::Devices, STATUS, PLAN), size);
			assert_eq!(
				frame.matches("\r\n").count(),
				usize::from(size.rows),
				"at {size:?}"
			);
		}
	}

	/// The device pane shows the interface, its state and its addresses.
	#[test]
	fn the_device_pane_draws_what_the_kernel_has() {
		let frame = draw(&app(Pane::Devices, STATUS, PLAN), Size::default());
		assert!(frame.contains("eth0"), "{frame}");
		assert!(frame.contains("10.0.0.2/24"), "{frame}");
		assert!(frame.contains("carrier"), "{frame}");
	}

	/// The plan pane shows the reason, not just the op.
	///
	/// An action list without reasons is the black box this project exists to
	/// not be, and the pane is the place an operator reads it.
	#[test]
	fn the_plan_pane_shows_why() {
		let frame = draw(&app(Pane::Plan, STATUS, PLAN), Size::default());
		assert!(frame.contains("addr.add"), "{frame}");
		assert!(frame.contains("<absent> -> 10.0.0.2/24"), "{frame}");
		assert!(frame.contains("something worth knowing"), "{frame}");
	}

	/// An empty plan says so rather than drawing a blank pane.
	#[test]
	fn an_empty_plan_says_so() {
		let frame = draw(
			&app(Pane::Plan, STATUS, r#"{"actions": []}"#),
			Size::default(),
		);
		assert!(frame.contains("nothing to do"), "{frame}");
	}

	/// With colour off there are no attribute sequences at all.
	#[test]
	fn no_colour_means_no_escapes_beyond_positioning() {
		let frame = draw(&app(Pane::Devices, STATUS, PLAN), Size::default());
		assert!(!frame.contains("\x1b[7m"), "reverse video with colour off");
		assert!(!frame.contains("\x1b[0m"), "a reset with colour off");
	}

	/// Truncation and padding both land on the width.
	#[test]
	fn fit_pads_and_truncates() {
		assert_eq!(fit("ab", 5), "ab   ");
		assert_eq!(fit("abcdefg", 3), "abc");
		assert_eq!(fit("", 2), "  ");
	}
}
