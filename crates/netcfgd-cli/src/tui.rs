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
use netcfgd_proto::Request;
use netcfgd_sys::{curses, signals, term};
use std::ffi::c_int;
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

/// Which pane is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
	Devices,
	Wifi,
	Clients,
	Plan,
	Events,
}

impl Pane {
	fn title(self) -> &'static str {
		match self {
			Self::Devices => "devices",
			Self::Wifi => "wifi",
			Self::Clients => "clients",
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
	stations: Option<serde_json::Value>,
	events: Arc<Mutex<Vec<String>>>,
	socket: std::path::PathBuf,
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

	// Refused before ncurses starts. `initscr` exits the process outright when
	// it cannot set up a terminal, so a redirected run has to be turned away
	// here or it dies without a message.
	if !term::is_terminal(std::io::stdin().as_raw_fd()) {
		return Err("`ncfg tui` needs a terminal; for a pipe use `ncfg status --json`".to_owned());
	}

	let mut app = App {
		pane: Pane::Devices,
		selected: 0,
		message: String::from("? for keys"),
		status: None,
		plan: None,
		stations: None,
		scan: None,
		events: Arc::new(Mutex::new(Vec::new())),
		socket: socket.clone(),
	};
	// Before any thread is spawned, and that ordering is load-bearing.
	// `sigprocmask` sets the *calling thread's* mask, and a thread inherits
	// whatever mask was in force when it was created -- so blocking after the
	// subscriber exists leaves that thread able to take the signal, where the
	// default disposition kills the whole process before `endwin` can run.
	// Measured: with the calls the other way round, SIGHUP killed it outright
	// and SIGTERM survived only by luck of which thread the kernel picked.
	//
	// Termination has to leave by the same path as `q`, or the operator's
	// shell is handed back unusable.
	let signals =
		signals::Signals::new().map_err(|error| format!("cannot watch for signals: {error}"))?;

	subscribe(&socket, &app.events);

	let screen = curses::Screen::open().map_err(|error| error.to_string())?;
	app.refresh();

	let result = event_loop(&mut app, &screen, &signals);
	// Explicit, so the terminal is restored before anything else can print.
	drop(screen);
	result
}

/// Read keys and redraw until asked to stop.
fn event_loop(
	app: &mut App,
	screen: &curses::Screen,
	signals: &signals::Signals,
) -> Result<ExitCode, String> {
	let stdin = std::io::stdin().as_raw_fd();
	let mut layout = Layout::new(screen)?;

	loop {
		layout.paint(screen, app)?;

		match signals::wait(stdin, signals, 1000) {
			// Leave the way `q` leaves, so `endwin` runs.
			Ok(signals::Ready::Signal) | Err(_) => return Ok(ExitCode::SUCCESS),
			Ok(signals::Ready::Timeout) => {
				if matches!(app.pane, Pane::Devices | Pane::Plan) {
					app.refresh();
					layout.touch();
				}
			}
			Ok(signals::Ready::Input) => {
				// One key per wake, and the read blocks. That pairing is the
				// point: blocking is the only mode in which ncurses decodes an
				// escape sequence, and it is safe because ncurses takes the
				// descriptor a byte at a time -- so a burst leaves its
				// remainder in the kernel, where the next `poll` finds it,
				// rather than in a userspace buffer where nothing can.
				let Some(key) = screen.key() else {
					return Ok(ExitCode::SUCCESS);
				};
				if key == curses::KEY_RESIZE {
					layout = Layout::new(screen)?;
					continue;
				}
				if !app.key(key) {
					return Ok(ExitCode::SUCCESS);
				}
				layout.touch();
			}
		}
	}
}

/// The three windows, and the size they were built for.
///
/// Rebuilt rather than resized on `KEY_RESIZE`, which is one allocation on an
/// event a person generates by dragging a window edge.
struct Layout {
	header: curses::Pane,
	body: curses::Pane,
	footer: curses::Pane,
	columns: u16,
}

impl Layout {
	fn new(screen: &curses::Screen) -> Result<Self, String> {
		let (rows, columns) = screen.size();
		// Header, footer and a status line are fixed; the body takes the rest.
		// A terminal too short for all of them still gets one body row rather
		// than an arithmetic underflow.
		let body_rows = rows.saturating_sub(3).max(1);
		let build =
			|rows, y| curses::Pane::new(rows, columns, y, 0).map_err(|error| error.to_string());
		Ok(Self {
			header: build(1, 0)?,
			body: build(body_rows, 1)?,
			footer: build(2, 1 + body_rows)?,
			columns,
		})
	}

	/// Mark every pane as needing a redraw.
	///
	/// Pane granularity is as fine as this client needs: a keystroke can
	/// change the tab bar, the body and the status line at once, and ncurses
	/// narrows each window to the cells that actually differ.
	fn touch(&mut self) {
		self.header.touch();
		self.body.touch();
		self.footer.touch();
	}

	fn paint(&mut self, screen: &curses::Screen, app: &App) -> Result<(), String> {
		// A resize between frames that ncurses has not reported yet.
		if screen.size().1 != self.columns {
			*self = Self::new(screen)?;
		}
		if !self.header.is_dirty() && !self.body.is_dirty() && !self.footer.is_dirty() {
			return Ok(());
		}

		let width = usize::from(self.columns).max(20);
		if self.header.is_dirty() {
			self.header.draw(&[tabs(app, width)], Some(0));
		}
		if self.body.is_dirty() {
			let lines = body(app, width);
			// Scroll so the selection stays on screen, without a scrollbar to
			// draw or a scroll offset to keep in sync.
			let visible = lines.len().min(64);
			let first = app.selected.saturating_sub(visible.saturating_sub(1));
			let shown: Vec<String> = lines.iter().skip(first).cloned().collect();
			let highlight = (app.pane != Pane::Events).then(|| app.selected.saturating_sub(first));
			self.body.draw(&shown, highlight);
		}
		if self.footer.is_dirty() {
			self.footer
				.draw(&[fit(&app.message, width), fit(KEYS, width)], Some(1));
		}
		screen.flush();
		Ok(())
	}
}

/// The tab bar.
fn tabs(app: &App, width: usize) -> String {
	let tabs: Vec<String> = [
		Pane::Devices,
		Pane::Wifi,
		Pane::Clients,
		Pane::Plan,
		Pane::Events,
	]
	.iter()
	.map(|pane| {
		if *pane == app.pane {
			format!("[{}]", pane.title())
		} else {
			format!(" {} ", pane.title())
		}
	})
	.collect();
	fit(&format!("ncfg  {}", tabs.join("")), width)
}

/// Whichever pane's content is showing.
fn body(app: &App, width: usize) -> Vec<String> {
	match app.pane {
		Pane::Devices => devices(app, width),
		Pane::Wifi => wifi(app, width),
		Pane::Clients => clients(app, width),
		Pane::Plan => plan(app, width),
		Pane::Events => events(app, width),
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
			Pane::Clients => {
				// The same shape as the scan: the operator should not have to
				// name a radio they can already see on the devices pane.
				self.status = self.fetch(&Request::Status);
				if let Some(interface) = self.radio() {
					self.stations = self.fetch(&Request::ApStations { interface });
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

	/// Handle one key. Returns false to quit.
	///
	/// Takes what ncurses returns, not a byte: `KEY_UP` and friends are values
	/// above 255 decoded from the terminal's own terminfo entry, which is why
	/// arrows work here and did not in the hand-rolled version.
	fn key(&mut self, key: c_int) -> bool {
		let byte = u8::try_from(key).unwrap_or(0);
		match (key, byte) {
			// `q` and `^C` are the same thing. ncurses leaves `ISIG` off under
			// `cbreak`, so `^C` arrives as a key, and treating it as anything
			// but "leave" would strand somebody whose reflex it is.
			(_, b'q' | 0x03) => return false,
			(_, b'd') => self.go(Pane::Devices),
			(_, b'w') => self.go(Pane::Wifi),
			// `s` for stations rather than `c`, which is already `connect` on
			// the wifi pane. A pane key that works everywhere except one pane
			// is worse than a letter that does not match the tab name.
			(_, b's') => self.go(Pane::Clients),
			(_, b'p') => self.go(Pane::Plan),
			(_, b'e') => self.go(Pane::Events),
			(_, b'r') => {
				"refreshed".clone_into(&mut self.message);
				self.refresh();
			}
			(curses::KEY_DOWN, _) | (_, b'j') => {
				self.selected = self.selected.saturating_add(1);
			}
			(curses::KEY_UP, _) | (_, b'k') => {
				self.selected = self.selected.saturating_sub(1);
			}
			(_, b'a') if self.pane == Pane::Plan => self.apply(),
			(_, b'c') if self.pane == Pane::Wifi => self.connect(),
			// The other half of `a`. Offering the window and then not
			// answering these would be worse than not offering it: the
			// operator would sit through the timeout believing they had
			// confirmed.
			(_, b'y') => self.settle(&Request::Confirm, "confirmed; the change stands"),
			(_, b'n') => self.settle(&Request::Revert, "reverted to the last-good configuration"),
			(_, b'?') => HELP.clone_into(&mut self.message),
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
			// Neither consent is offered from the TUI, for the reason the
			// comment above gives about guards: a keystroke is the wrong place
			// to agree to leave a key on hardware that is walking away.
			strand_credentials: Vec::new(),
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

	/// The same app showing a different pane, for tests.
	#[cfg(test)]
	fn clone_for(&self, pane: Pane) -> Self {
		Self {
			pane,
			selected: self.selected,
			message: self.message.clone(),
			status: self.status.clone(),
			plan: self.plan.clone(),
			scan: self.scan.clone(),
			stations: self.stations.clone(),
			events: Arc::clone(&self.events),
			socket: self.socket.clone(),
		}
	}

	fn station_entries(&self) -> Vec<serde_json::Value> {
		self.stations
			.as_ref()
			.and_then(|value| value.get("stations"))
			.and_then(serde_json::Value::as_array)
			.cloned()
			.unwrap_or_default()
	}

	fn scan_entries(&self) -> Vec<serde_json::Value> {
		self.scan
			.as_ref()
			.and_then(|value| value.get("access_points"))
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
const HELP: &str = "d w s p e switch panes (s is clients). a applies with a 60s window: \
	 y keeps it, n undoes it now, nothing reverts it. `c` marks networks the config can \
	 join; `!` marks a station the access point should not be talking to.";

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
		out.extend(reported_on(app, &name, width));
		out.extend(backends_on(app, &name, width));
	}
	if out.is_empty() {
		out.push("(no interfaces)".to_owned());
	}
	out
}

/// What something outside netcfgd reported for this interface, and did not
/// apply.
///
/// `ncfg status` has marked these since the modem work and this pane did not,
/// which made the TUI the one view where a bearer that is up and an interface
/// that is configured look the same. The difference is the whole question when
/// a modem is not working: "the network gave us nothing" and "netcfgd has not
/// acted on it" send somebody to different places.
fn reported_on(app: &App, interface: &str, width: usize) -> Vec<String> {
	let Some(report) = app
		.status
		.as_ref()
		.and_then(|value| value.get("reports"))
		.and_then(serde_json::Value::as_array)
		.and_then(|reports| {
			reports
				.iter()
				.find(|report| string(report, "interface") == interface)
		})
	else {
		return Vec::new();
	};
	let list = |key: &str| -> Vec<String> {
		report
			.get(key)
			.and_then(serde_json::Value::as_array)
			.map(|values| {
				values
					.iter()
					.filter_map(|value| value.as_str().map(ToOwned::to_owned))
					.collect()
			})
			.unwrap_or_default()
	};

	let mut out = Vec::new();
	for address in list("addresses") {
		out.push(fit(&format!("    {address} [reported]"), width));
	}
	for gateway in list("gateways") {
		out.push(fit(&format!("    via {gateway} [reported]"), width));
	}
	let servers = list("nameservers");
	if !servers.is_empty() {
		out.push(fit(
			&format!("    dns {} [reported]", servers.join(" ")),
			width,
		));
	}
	out
}

/// What netcfgd started here, and whether it is still what the document says.
///
/// The plan pane shows the restart while it is pending; this shows the reason
/// it is pending, on the interface, where somebody looking at a radio is
/// already looking. Only the answers that mean something is wrong -- decisions
/// 0052 and 0053 -- because a line every reader skips is how the one that
/// matters gets skipped with it.
fn backends_on(app: &App, interface: &str, width: usize) -> Vec<String> {
	let Some(backends) = app
		.status
		.as_ref()
		.and_then(|value| value.get("backends"))
		.and_then(serde_json::Value::as_array)
	else {
		return Vec::new();
	};
	let mut out = Vec::new();
	for backend in backends
		.iter()
		.filter(|backend| string(backend, "interface") == interface)
		.filter(|backend| backend.get("running").and_then(serde_json::Value::as_bool) == Some(true))
	{
		let stale = [
			("secret_matches", "the passphrase has changed"),
			("config_matches", "its configuration file has changed"),
		]
		.iter()
		.find_map(|(key, said)| {
			(backend.get(*key).and_then(serde_json::Value::as_bool) == Some(false)).then_some(*said)
		});
		let kind = string(backend, "kind");
		match stale {
			Some(said) => out.push(fit(
				&format!("    {kind}: running, {said}; it will be restarted"),
				width,
			)),
			None => out.push(fit(&format!("    {kind}: running"), width)),
		}
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

/// Who is on the access point.
///
/// The marker column is the point of showing this next to a station list at
/// all: `!` means the document's `access_control` block and what hostapd is
/// enforcing disagree, which happens because hostapd reads the list once at
/// startup (decision 0039).
fn clients(app: &App, width: usize) -> Vec<String> {
	let entries = app.station_entries();
	if entries.is_empty() {
		return vec!["(nobody associated; press r to refresh)".to_owned()];
	}
	let policy = app
		.stations
		.as_ref()
		.and_then(|value| value.get("access_control"))
		.and_then(serde_json::Value::as_str);

	entries
		.iter()
		.map(|entry| {
			let address = entry
				.get("address")
				.and_then(serde_json::Value::as_str)
				.unwrap_or("<no address>");
			let signal = entry
				.get("signal")
				.and_then(serde_json::Value::as_i64)
				.map_or_else(|| "  -- ".to_owned(), |dbm| format!("{dbm:>4} "));
			let connected = entry
				.get("connected_seconds")
				.and_then(serde_json::Value::as_u64)
				.map_or_else(|| "--".to_owned(), |seconds| format!("{}m", seconds / 60));
			let listed = entry.get("listed").and_then(serde_json::Value::as_bool) == Some(true);
			let authorized =
				entry.get("authorized").and_then(serde_json::Value::as_bool) == Some(true);
			let marker = match (policy, listed) {
				(Some("deny"), true) | (Some("allow"), false) => "!",
				_ if !authorized => "?",
				_ => " ",
			};
			fit(
				&format!("{marker} {address:<19} {signal}dBm  {connected:>6}"),
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

#[cfg(test)]
mod tests {
	use super::{body, fit, tabs, App, Pane};
	use serde_json::Value;
	use std::sync::{Arc, Mutex};

	/// A witness from `docs/schema/`, which is the daemon's own bytes.
	///
	/// These tests used to carry fixtures written by hand, and one of them was
	/// wrong for as long as it existed. The plan fixture said
	/// `"op": {"op": "addr.add"}`; the wire said `addr_add` until 0083, so the
	/// pane drew a word this test never saw and the test passed anyway. A
	/// fixture written to match what somebody believed agrees with itself and
	/// proves nothing -- which is the whole argument for `docs/schema/`, and
	/// this is the last crate that was not taking it.
	///
	/// It is also not hypothetical twice over: the wifi pane read `entries`
	/// where the daemon sends `access_points`, for the same reason.
	fn witness(name: &str) -> Value {
		let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../../docs/schema")
			.join(name);
		let text = std::fs::read_to_string(&path)
			.unwrap_or_else(|error| panic!("{}: {error}", path.display()));

		serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
	}

	/// One response line from the socket witness, by its tag.
	///
	/// `socket.json` pins the *envelopes*, one JSON object per line. Several are
	/// complete answers on their own -- a scan, a station list -- and those are
	/// used here exactly as they are.
	fn socket_witness(response: &str) -> Value {
		let path =
			std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/schema/socket.json");
		let text = std::fs::read_to_string(&path)
			.unwrap_or_else(|error| panic!("{}: {error}", path.display()));

		for line in text.lines() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let value: Value = serde_json::from_str(line).expect("a witness line parses");
			if value.get("response").and_then(Value::as_str) == Some(response) {
				return value;
			}
		}
		panic!("the socket witness pins no `{response}` response");
	}

	/// Content under its envelope.
	///
	/// The two answers the panes lean on hardest are pinned in two places and
	/// neither is enough alone: `socket.json` has the `status` and `plan`
	/// envelopes but with every list empty, and `observed.json` and `plan.json`
	/// have the content but no envelope. The daemon sends the content flattened
	/// under the tag, so that is what these compose -- and
	/// `the_envelopes_these_tests_compose_are_the_ones_the_socket_pins` is why
	/// composing it is a reading of the witnesses rather than a guess about
	/// them.
	fn under_envelope(response: &str, content: Value) -> Value {
		let mut object = content;
		object
			.as_object_mut()
			.expect("a witness is an object")
			.insert("response".to_owned(), Value::from(response));
		object
	}

	fn status_response() -> Value {
		under_envelope("status", witness("observed.json"))
	}

	fn plan_response() -> Value {
		under_envelope("plan", witness("plan.json"))
	}

	/// An app with the daemon's answers and no daemon.
	///
	/// Each pane's content is a pure function of what the socket returned,
	/// which is what keeps it testable with no terminal, no privileges and no
	/// kernel. Only the painting goes through ncurses, and that is covered by
	/// `tests/live/tui.py` against a real pty.
	fn app(pane: Pane, status: &Value, plan: &Value) -> App {
		App {
			pane,
			selected: 0,
			message: "msg".to_owned(),
			status: Some(status.clone()),
			plan: Some(plan.clone()),
			scan: None,
			stations: None,
			events: Arc::new(Mutex::new(Vec::new())),
			socket: std::path::PathBuf::from("/nonexistent"),
		}
	}

	/// A string member, or a failure naming the path rather than unwrapping.
	fn text<'a>(value: &'a Value, path: &[&str]) -> &'a str {
		let mut at = value;
		for step in path {
			at = at
				.get(step)
				.unwrap_or_else(|| panic!("the witness has no {}", path.join(".")));
		}
		at.as_str()
			.unwrap_or_else(|| panic!("{} is not a string", path.join(".")))
	}

	/// The composition above is the shape the daemon actually sends.
	///
	/// Every member of the pinned envelope has to come from the content
	/// witness, or these tests are feeding the panes an object no daemon would
	/// produce -- which is the mistake they are being moved off. The reverse is
	/// not required: `socket.json` pins an *empty* observation, and a member
	/// that is skipped when it is empty is absent there and present here.
	#[test]
	fn the_envelopes_these_tests_compose_are_the_ones_the_socket_pins() {
		for (tag, composed) in [("status", status_response()), ("plan", plan_response())] {
			let pinned = socket_witness(tag);
			let composed = composed.as_object().expect("an object");

			for key in pinned.as_object().expect("an object").keys() {
				assert!(
					composed.contains_key(key),
					"the {tag} envelope has `{key}` and the content witness does not, \
					 so these tests compose an answer netcfgd never sends"
				);
			}
		}
	}

	/// Every line is exactly the pane's width.
	///
	/// ncurses clears to end of line, so a short line is not a display bug --
	/// but a line *longer* than the window wraps and pushes everything below
	/// it down a row, which on a full-screen client scrolls the footer away.
	#[test]
	fn no_line_exceeds_the_width() {
		for width in [80_usize, 132, 40] {
			let app = app(Pane::Devices, &status_response(), &plan_response());
			for pane in [Pane::Devices, Pane::Wifi, Pane::Plan, Pane::Events] {
				let mut app = app.clone_for(pane);
				app.selected = 0;
				for line in body(&app, width) {
					assert!(
						line.chars().count() <= width,
						"{pane:?} at {width}: {line:?}"
					);
				}
			}
			assert_eq!(tabs(&app, width).chars().count(), width);
		}
	}

	/// The device pane shows the interface, its state and its addresses.
	///
	/// The names are read out of the witness rather than written here, so that
	/// re-blessing an observation cannot leave this test asserting an interface
	/// netcfgd no longer reports -- it would go on passing against a pane that
	/// had stopped drawing anything.
	#[test]
	fn the_device_pane_draws_what_the_kernel_has() {
		let status = status_response();
		let interface = text(&status["links"][0], &["name"]);
		let lines = body(&app(Pane::Devices, &status, &plan_response()), 132).join("\n");

		assert!(
			lines.contains(interface),
			"{interface} missing from {lines}"
		);
		let address = status["addresses"]
			.as_array()
			.expect("the witness observes addresses")
			.iter()
			.find(|entry| entry["interface"] == status["links"][0]["name"])
			.map(|entry| text(entry, &["address"]))
			.expect("the witness gives that interface an address");
		assert!(lines.contains(address), "{address} missing from {lines}");
		assert!(lines.contains("carrier"), "{lines}");
	}

	/// The plan pane shows the reason, not just the op.
	///
	/// An action list without reasons is the black box this project exists to
	/// not be, and the pane is where an operator reads it.
	///
	/// The op is the witness's own spelling. That is the assertion this file
	/// most needed: it read `addr.add` from a fixture while the pane drew
	/// `addr_add` from the wire, for as long as both existed (0083).
	#[test]
	fn the_plan_pane_shows_why() {
		let plan = plan_response();
		let action = &plan["actions"][0];
		let op = text(action, &["op", "op"]);
		let reason = format!(
			"{} -> {}",
			text(action, &["reason", "observed"]),
			text(action, &["reason", "desired"])
		);
		let warning = text(&plan["warnings"][0], &["message"]);
		let lines = body(&app(Pane::Plan, &status_response(), &plan), 132).join("\n");

		assert!(lines.contains(op), "{op} missing from {lines}");
		assert!(lines.contains(&reason), "{reason} missing from {lines}");
		assert!(lines.contains(warning), "{warning} missing from {lines}");
	}

	/// An empty plan says so rather than drawing a blank pane.
	///
	/// The socket witness pins an empty plan on its own, which is the answer a
	/// machine that matches its configuration actually gets.
	#[test]
	fn an_empty_plan_says_so() {
		let lines = body(
			&app(Pane::Plan, &status_response(), &socket_witness("plan")),
			80,
		)
		.join("\n");
		assert!(lines.contains("nothing to do"), "{lines}");
	}

	/// The tab bar marks exactly the pane that is showing.
	#[test]
	fn the_tab_bar_marks_one_pane() {
		for pane in [Pane::Devices, Pane::Wifi, Pane::Plan, Pane::Events] {
			let bar = tabs(&app(pane, &status_response(), &plan_response()), 80);
			assert!(bar.contains(&format!("[{}]", pane.title())), "{bar}");
			assert_eq!(bar.matches('[').count(), 1, "{bar}");
		}
	}

	/// Truncation and padding both land on the width.
	#[test]
	fn fit_pads_and_truncates() {
		assert_eq!(fit("ab", 5), "ab   ");
		assert_eq!(fit("abcdefg", 3), "abc");
		assert_eq!(fit("", 2), "  ");
	}

	/// A station list with one of each case that renders differently.
	///
	/// The witness pins one station -- on the list, authorized, with
	/// statistics -- and the pane has three cases. The other two are **derived**
	/// from that one rather than written out: same members, different values,
	/// and the "no statistics" case made by removing the members the daemon
	/// omits when it has none. So the field names still come from netcfgd even
	/// where the combination does not, and a renamed member breaks this instead
	/// of quietly rendering dashes.
	fn stations_response() -> Value {
		let mut report = socket_witness("ap_stations");
		let listed = report["stations"][0].clone();

		let mut unlisted = listed.clone();
		let object = unlisted.as_object_mut().expect("a station is an object");
		object.insert("address".to_owned(), Value::from("aa:bb:cc:dd:ee:ff"));
		object.insert("listed".to_owned(), Value::from(false));
		// What a station that has only just associated looks like: hostapd has
		// reported it and has no numbers for it yet.
		for absent in [
			"signal",
			"connected_seconds",
			"inactive_msec",
			"rx_bytes",
			"tx_bytes",
		] {
			object.remove(absent);
		}

		let mut unauthorized = listed.clone();
		let object = unauthorized
			.as_object_mut()
			.expect("a station is an object");
		object.insert("address".to_owned(), Value::from("66:77:88:99:aa:bb"));
		object.insert("listed".to_owned(), Value::from(false));
		object.insert("authorized".to_owned(), Value::from(false));

		report["stations"] = Value::from(vec![listed, unlisted, unauthorized]);
		report
	}

	fn clients_app() -> App {
		let mut app = app(Pane::Clients, &status_response(), &plan_response());
		app.stations = Some(stations_response());
		app
	}

	#[test]
	fn the_clients_pane_marks_a_station_the_acl_should_have_stopped() {
		let lines = body(&clients_app(), 60);
		assert_eq!(lines.len(), 3, "{lines:?}");
		// On the deny list and connected anyway: hostapd was never told the
		// list changed. That is the marker worth having on screen. The address
		// comes from the witness, so a witness that renames the member fails
		// here rather than matching an empty prefix.
		let listed = text(&stations_response()["stations"][0], &["address"]).to_owned();
		assert!(
			lines[0].starts_with(&format!("! {listed}")),
			"{:?}",
			lines[0]
		);
		// Not listed, authorized, ordinary.
		let ordinary = text(&stations_response()["stations"][1], &["address"]).to_owned();
		assert!(
			lines[1].starts_with(&format!("  {ordinary}")),
			"{:?}",
			lines[1]
		);
		// Associated but not authorized.
		let unauthorized = text(&stations_response()["stations"][2], &["address"]).to_owned();
		assert!(
			lines[2].starts_with(&format!("? {unauthorized}")),
			"{:?}",
			lines[2]
		);
	}

	#[test]
	fn a_station_with_no_statistics_still_gets_a_line() {
		let stations = stations_response();
		let lines = body(&clients_app(), 60);

		assert!(lines[1].contains("--"), "{:?}", lines[1]);
		// And one that has them shows them rather than dashes.
		let signal = stations["stations"][0]["signal"].to_string();
		assert!(lines[0].contains(&signal), "{signal} in {:?}", lines[0]);
	}

	#[test]
	fn an_empty_station_list_says_so_rather_than_drawing_nothing() {
		let mut app = app(Pane::Clients, &status_response(), &plan_response());
		let mut empty = stations_response();
		empty["stations"] = Value::from(Vec::<Value>::new());
		app.stations = Some(empty);
		let lines = body(&app, 60);
		assert!(lines[0].contains("nobody associated"), "{lines:?}");
	}

	/// The wifi pane read a field the daemon has never sent.
	///
	/// `ScanReport`'s list is `access_points`; the pane asked for `entries`, so
	/// every scan rendered as "(no scan)" from the day the TUI was written.
	/// Nothing caught it because `tests/live/tui.py` never opens this pane --
	/// and the fixture that replaced it was written from the same reading of
	/// the type that got it wrong the first time. This one is the witness, so
	/// the pane is checked against what the socket pins rather than against
	/// somebody's second look at `ScanReport`.
	#[test]
	fn the_wifi_pane_reads_the_field_the_daemon_sends() {
		let scan = socket_witness("wifi_scan");
		let point = &scan["access_points"][0];
		let name = text(point, &["name"]).to_owned();
		let signal = point["signal"].to_string();

		let mut app = app(Pane::Wifi, &status_response(), &plan_response());
		app.scan = Some(scan.clone());
		let lines = body(&app, 60);

		assert!(lines[0].contains(&name), "{name} in {lines:?}");
		assert!(lines[0].contains(&signal), "{signal} in {lines:?}");
	}
}
