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

/// The width [`App::last_row`] counts rows at.
///
/// Any value gives the same count -- see that function -- so this is the
/// terminal everybody has rather than a number with meaning.
const ROW_COUNT_WIDTH: usize = 80;

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
	/// The radios this machine has, and what netcfgd is doing about each.
	///
	/// Fetched with the scan rather than once at startup: a USB radio can be
	/// plugged in while the pane is open, and a list taken at startup would go
	/// on saying it is not there.
	radios: Option<serde_json::Value>,
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

	// Installed before the screen is opened, so a panic during setup is
	// covered too. This is the one exit path `signals` cannot reach: it says
	// so itself, and under the release profile's `panic = "abort"` no
	// destructor runs, so without this an aborting client leaves the shell
	// with echo off and prints the reason into a terminal that cannot show it.
	curses::restore_on_panic();

	let mut app = App {
		pane: Pane::Devices,
		selected: 0,
		message: String::from("? for keys"),
		status: None,
		plan: None,
		stations: None,
		scan: None,
		radios: None,
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
				self.radios = self.fetch(&Request::Radios);
				if let Some(interface) = self.radio() {
					self.scan = self.fetch(&Request::WifiScan { interface });
				} else {
					// **Not an error any more, and that is the point.** A
					// machine with a radio nobody has activated is the
					// ordinary starting state, not a misconfiguration -- and
					// the pane can now do something about it, so saying "no
					// wireless device in the configuration" and stopping would
					// be describing the problem to somebody standing in front
					// of the fix.
					self.scan = None;
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
				crate::is_radio(
					link.get("kind").and_then(serde_json::Value::as_str),
					link.get("name")
						.and_then(serde_json::Value::as_str)
						.unwrap_or(""),
				)
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
				// Clamped to the last row there is. `saturating_add` alone
				// only stops at usize::MAX, so holding the key walked the
				// highlight off the end of the list and into blank space --
				// where `c` on the wifi pane had nothing to join and the
				// operator had no way to tell an empty row from a real one.
				self.selected = self.selected.saturating_add(1).min(self.last_row());
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

	/// Hand a radio to netcfgd.
	///
	/// The same key as joining a network, because it is the same intent from
	/// the operator's side: use this one. What differs is which row the
	/// highlight is on, and the pane says so on the row itself.
	fn activate(&mut self, interface: &str) {
		let request = Request::RadioSet {
			interface: interface.to_owned(),
			activate: true,
		};
		match client::ask(&self.socket, &request) {
			Ok(client::Answer::Error { message }) => self.message = message,
			Ok(_) => {
				self.message = format!("{interface} is netcfgd's now; scanning");
				// Straight into a scan rather than waiting for `r`: activating
				// is only ever a step towards looking at what is in range, and
				// the supplicant needs a moment either way.
				self.refresh();
			}
			Err(error) => self.message = error,
		}
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
			// Nor this one: killing a daemon that may only be busy is not a
			// thing to agree to with a keystroke either (0141).
			restart_wedged: Vec::new(),
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

	/// The index of the last row the current pane draws.
	///
	/// Asked of [`body`], which is what the renderer draws, so the two cannot
	/// disagree about how many rows there are -- the alternative is a second
	/// count per pane, and five of those would drift the first time a pane
	/// grew a heading.
	///
	/// **The width passed here does not affect the answer.** [`fit`] truncates
	/// and pads and never wraps, so a pane produces one line per thing it has
	/// to say whatever the terminal is. If that ever stops being true this
	/// becomes wrong, which is why it is stated rather than assumed.
	fn last_row(&self) -> usize {
		body(self, ROW_COUNT_WIDTH).len().saturating_sub(1)
	}

	/// Join the selected network, if the configuration describes it.
	///
	/// The selected *line* rather than the selected entry: since the pane
	/// groups radios under a network the two are no longer the same number,
	/// and indexing the entries by the line would join whatever network
	/// happened to sit at that position. `wifi_rows` says what each line
	/// stands for, and it is the same grouping the pane drew.
	fn connect(&mut self) {
		let row = wifi_rows(self, ROW_COUNT_WIDTH)
			.get(self.selected)
			.map_or(Row::Nothing, |(_, row)| row.clone());
		let at = match row {
			Row::Nothing => return,
			Row::Radio(interface) => return self.activate(&interface),
			Row::Network(at) => at,
		};
		let Some(entry) = self.scan_entries().get(at).cloned() else {
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
			radios: self.radios.clone(),
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
	"d devices  w wifi  p plan  e events | j/k move  r refresh  a apply  c use  q quit";

/// What `?` adds: the things the footer cannot say in one line.
///
/// Not a repeat of `KEYS`. A help key that prints what is already on the
/// screen teaches the operator that help is useless.
const HELP: &str = "d w s p e switch panes (s is clients). a applies with a 60s window: \
	 y keeps it, n undoes it now, nothing reverts it. `c` uses the selected row: it joins \
	 a network the config can join (marked `c`), or hands netcfgd a radio nobody has \
	 given it. `!` marks a station the access point should not be talking to.";

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

/// What a line in the wifi pane stands for.
///
/// Two kinds, because the pane now shows two: the radios netcfgd could be
/// given, and the networks it can see with the ones it has. `c` acts on the
/// selected line, and what it does follows the **row** rather than the pane --
/// activating a radio and joining a network are the same intent ("use this
/// one"), so making them the same key is the honest arrangement rather than a
/// shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Row {
	/// A heading, a blank, or an explanation. `c` does nothing.
	Nothing,
	/// A radio, by interface name, that `c` would activate.
	Radio(String),
	/// A network, by its index in the scan, that `c` would join.
	Network(usize),
}

/// The radios worth showing, which is not always all of them.
///
/// **Only when there is something to do about one.** A machine whose radios
/// are all activated and answering wants its wifi pane to be networks, and a
/// list of hardware above them is clutter that pushes the useful part down the
/// screen. A radio that is not activated, or activated with nothing answering,
/// is a reason the pane is emptier than expected -- and that is exactly when it
/// has to be visible.
fn radio_rows(app: &App) -> Vec<(String, Row)> {
	let radios = app
		.radios
		.as_ref()
		.and_then(|value| value.get("radios"))
		.and_then(serde_json::Value::as_array)
		.map(Vec::as_slice)
		.unwrap_or_default();

	let unfinished: Vec<&serde_json::Value> = radios
		.iter()
		.filter(|radio| {
			let activated =
				radio.get("activated").and_then(serde_json::Value::as_bool) == Some(true);
			let supplicant =
				radio.get("supplicant").and_then(serde_json::Value::as_bool) == Some(true);
			!activated || !supplicant
		})
		.collect();
	if unfinished.is_empty() {
		return Vec::new();
	}

	let mut out = vec![("radios".to_owned(), Row::Nothing)];
	for radio in unfinished {
		let name = radio
			.get("interface")
			.and_then(serde_json::Value::as_str)
			.unwrap_or("?");
		let activated = radio.get("activated").and_then(serde_json::Value::as_bool) == Some(true);
		let supplicant = radio.get("supplicant").and_then(serde_json::Value::as_bool) == Some(true);
		let (state, row) = match (activated, supplicant) {
			// The one a person gets stuck in: another manager holds this
			// radio, so activating changes nothing until that stops. Said
			// here rather than discovered by pressing `c` and waiting.
			(false, true) => (
				"another manager's -- stop it first".to_owned(),
				Row::Nothing,
			),
			(false, false) => (
				"not activated -- press c".to_owned(),
				Row::Radio(name.to_owned()),
			),
			(true, false) => (
				"activated, no supplicant answering".to_owned(),
				Row::Nothing,
			),
			(true, true) => (String::new(), Row::Nothing),
		};
		out.push((format!("  {name:<16} {state}"), row));
	}
	out.push((String::new(), Row::Nothing));
	out
}

fn wifi(app: &App, width: usize) -> Vec<String> {
	wifi_rows(app, width)
		.into_iter()
		.map(|(line, _)| line)
		.collect()
}

/// The wifi pane, with the scan entry each line stands for.
///
/// **One grouping, not two.** The pane groups radios under a network, so the
/// nth *line* stopped being the nth *entry* -- and `connect` indexed the
/// entries by the selected line. Selecting a heading below the first group
/// would have joined some other network entirely, which is the worst kind of
/// bug a list can have: it does something, confidently, to the wrong thing.
///
/// So the grouping happens once and says what each line means. A heading
/// carries its group's joinable entry; a detail row carries its own, so
/// pressing `c` on a radio joins the network that radio belongs to.
fn wifi_rows(app: &App, width: usize) -> Vec<(String, Row)> {
	let mut rows = radio_rows(app);
	let entries = app.scan_entries();
	if entries.is_empty() {
		rows.push((
			if rows.is_empty() {
				"(no scan; press r to rescan)".to_owned()
			} else {
				// With radios listed above, an empty scan is explained by
				// them rather than being a second mystery.
				"(nothing scanned yet)".to_owned()
			},
			Row::Nothing,
		));
		return rows;
	}

	// **Grouped by name and security, one heading per network, the radios
	// under it.** A dual-band access point broadcasts the same SSID from two
	// radios, and the flat list drew that as two rows differing by a few dBm
	// -- which is also what an evil twin looks like, and an operator asked
	// which they were seeing. With fifty networks in range the flat list is
	// also simply hard to read.
	//
	// **Security is part of the key, not just the heading.** Two entries with
	// the same name and *different* security are not one network: that is the
	// anomaly worth seeing, and collapsing them would hide the one difference
	// a person should act on. Same-name-same-security is a network; anything
	// else stays apart.
	//
	// Deliberately *not* grouped by anything cleverer. Adjacent addresses and
	// a shared manufacturer prefix say "one access point" to a reader and are
	// convention rather than fact, and the mobility domain is unauthenticated
	// -- grouping on either would be the display asserting something it
	// cannot know. The members are shown instead, and the reader draws the
	// conclusion with the evidence in front of them.
	let (order, groups, indices) = group_scan(&entries);

	let mut lines = rows;
	for key in order {
		let members = &groups[&key];
		let (name, security) = key;
		// The strongest member speaks for the group, because that is the one
		// a client would associate with and the number a reader is judging.
		let signal = members
			.iter()
			.filter_map(|entry| entry.get("signal").and_then(serde_json::Value::as_i64))
			.max()
			.unwrap_or(0);
		let configured = members
			.iter()
			.find_map(|entry| entry.get("configured").and_then(serde_json::Value::as_str));
		let known = if configured.is_some() { "c" } else { " " };
		let block = configured.map_or_else(String::new, |id| format!("  [{id}]"));
		let radios = if members.len() > 1 {
			format!("{} radios", members.len())
		} else {
			String::new()
		};
		// The heading stands for the strongest member, which is the one a
		// client would associate with.
		let strongest = members
			.iter()
			.enumerate()
			.max_by_key(|(_, entry)| {
				entry
					.get("signal")
					.and_then(serde_json::Value::as_i64)
					.unwrap_or(i64::MIN)
			})
			.map_or(0, |(at, _)| at);
		lines.push((
			fit(
				&format!("{known} {name:<28} {signal:>4} dBm  {security:<7}  {radios:<8}{block}"),
				width,
			),
			indices[&(name.clone(), security)]
				.get(strongest)
				.copied()
				.map_or(Row::Nothing, Row::Network),
		));

		// The detail, and only where there is something to tell apart. One
		// radio adds a line that says what the heading already said.
		if members.len() < 2 {
			continue;
		}
		for (at, member) in members.iter().enumerate() {
			let bssid = member
				.get("bssid")
				.and_then(serde_json::Value::as_str)
				.unwrap_or("");
			let band = band_of(
				member
					.get("frequency")
					.and_then(serde_json::Value::as_u64)
					.unwrap_or(0),
			);
			let member_signal = member
				.get("signal")
				.and_then(serde_json::Value::as_i64)
				.unwrap_or(0);
			// The mobility domain where the access point claims one. It says
			// the operator configured these to roam as one, which is worth
			// knowing when they do not -- and it is unauthenticated, so it is
			// shown as a claim beside the address rather than used to group.
			let domain = member
				.get("mobility_domain")
				.and_then(serde_json::Value::as_str)
				.map_or_else(String::new, |id| format!("  ft:{id}"));
			lines.push((
				fit(
					&format!("    {band:<7} {bssid:<17}  {member_signal:>4} dBm{domain}"),
					width,
				),
				indices[&(name.clone(), security)]
					.get(at)
					.copied()
					.map_or(Row::Nothing, Row::Network),
			));
		}
	}
	lines
}

/// One network's worth of scan entries, and where each came from.
type Grouped<'a> = (
	Vec<(String, &'static str)>,
	std::collections::HashMap<(String, &'static str), Vec<&'a serde_json::Value>>,
	std::collections::HashMap<(String, &'static str), Vec<usize>>,
);

/// Group scan entries by name and security, keeping the order they arrived in.
///
/// Split from the rendering because they are two thoughts and the function was
/// over its line budget holding both. The key is the interesting part and it
/// is deliberately dull: the name, and the security word shown beside it.
///
/// **The word rather than the booleans behind it**, so the key cannot be
/// coarser than what a reader sees. A key of "is it secured" would merge a
/// passphrase network and an enterprise one sharing an SSID -- which is a real
/// arrangement, not a curiosity -- under a heading that then described only
/// one of them.
///
/// **Nothing cleverer, on purpose.** Adjacent addresses and a shared
/// manufacturer prefix read as "one access point" and are convention rather
/// than fact; the mobility domain is unauthenticated. Grouping on either would
/// be the display asserting something it cannot know, so the members are shown
/// and the reader draws the conclusion with the evidence in front of them.
fn group_scan<'a>(entries: &'a [serde_json::Value]) -> Grouped<'a> {
	let mut order: Vec<(String, &'static str)> = Vec::new();
	let mut groups: std::collections::HashMap<(String, &'static str), Vec<&'a serde_json::Value>> =
		std::collections::HashMap::new();
	// The position each grouped member had in `scan_entries`, so a selected
	// line can name the entry it stands for.
	let mut indices: std::collections::HashMap<(String, &'static str), Vec<usize>> =
		std::collections::HashMap::new();

	for (at, entry) in entries.iter().enumerate() {
		let name = crate::access_point_name(
			entry.get("name").and_then(serde_json::Value::as_str),
			entry
				.get("ssid")
				.and_then(serde_json::Value::as_str)
				.unwrap_or(""),
		);
		let secured = entry.get("secured").and_then(serde_json::Value::as_bool) == Some(true);
		let enterprise = entry.get("enterprise").and_then(serde_json::Value::as_bool) == Some(true);
		// The word itself, not the booleans behind it, so the key and the
		// heading cannot come apart: a key coarser than what is displayed
		// merges two networks under a heading describing one of them.
		let key = (name, crate::access_point_security(secured, enterprise));
		if !groups.contains_key(&key) {
			order.push(key.clone());
		}
		groups.entry(key.clone()).or_default().push(entry);
		indices.entry(key).or_default().push(at);
	}
	(order, groups, indices)
}

/// The band a centre frequency is in, as a person names it.
///
/// Not the channel number, which is what the kernel and every scan tool
/// report: a reader trying to tell two rows apart wants "these are the two
/// radios of one access point", and `2.4GHz` beside `5GHz` says that where
/// `1` beside `44` does not.
///
/// An unrecognised frequency is printed as its megahertz rather than guessed
/// at or blanked. A band this does not know is one worth seeing the number
/// for, and a blank column would read as missing data.
fn band_of(frequency: u64) -> String {
	match frequency {
		0 => String::new(),
		2400..=2500 => "2.4GHz".to_owned(),
		4900..=5895 => "5GHz".to_owned(),
		5925..=7125 => "6GHz".to_owned(),
		other => format!("{other}M"),
	}
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
	use super::{body, curses, fit, tabs, App, Pane, ROW_COUNT_WIDTH};
	use serde_json::Value;
	use std::sync::{Arc, Mutex};

	/// A witness from `doc/schema/`, which is the daemon's own bytes.
	///
	/// These tests used to carry fixtures written by hand, and one of them was
	/// wrong for as long as it existed. The plan fixture said
	/// `"op": {"op": "addr.add"}`; the wire said `addr_add` until 0083, so the
	/// pane drew a word this test never saw and the test passed anyway. A
	/// fixture written to match what somebody believed agrees with itself and
	/// proves nothing -- which is the whole argument for `doc/schema/`, and
	/// this is the last crate that was not taking it.
	///
	/// It is also not hypothetical twice over: the wifi pane read `entries`
	/// where the daemon sends `access_points`, for the same reason.
	fn witness(name: &str) -> Value {
		let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../../doc/schema")
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
			std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../doc/schema/socket.json");
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
			radios: None,
			stations: None,
			events: Arc::new(Mutex::new(Vec::new())),
			socket: std::path::PathBuf::from("/nonexistent"),
		}
	}

	/// Two radios of one access point are one row, with the radios under it.
	///
	/// The case that produced this: an operator saw two `OpenPC.se` rows and
	/// asked whether somebody was spoofing them. Both were real -- one access
	/// point, 2.4 GHz and 5 GHz -- and the pane had drawn them as two lines
	/// identical but for a few dBm, which is also what an evil twin looks
	/// like. Grouping answers the question the flat list raised, and the
	/// detail rows keep the evidence a reader needs to check it.
	#[test]
	fn two_radios_of_one_access_point_group_under_one_heading() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.scan = Some(two_radio_scan());

		let lines = body(&app, ROW_COUNT_WIDTH);
		let headings: Vec<&String> = lines
			.iter()
			.filter(|line| line.contains("OpenPC.se"))
			.collect();
		assert_eq!(headings.len(), 1, "not one heading: {lines:?}");
		assert!(headings[0].contains("2 radios"), "{:?}", headings[0]);

		// Both radios are still there, each with its band and address, so the
		// reader can see the shared manufacturer prefix and adjacent
		// addresses that make it one access point.
		let detail: Vec<&String> = lines
			.iter()
			.filter(|line| line.starts_with("    "))
			.collect();
		assert_eq!(detail.len(), 2, "{lines:?}");
		// In the order the scan gave them, which the fixture deliberately does
		// not sort.
		assert!(detail[0].contains("5GHz") && detail[0].contains("f0:9f:c2:7e:bd:7d"));
		assert!(detail[1].contains("2.4GHz") && detail[1].contains("f0:9f:c2:7d:bd:7d"));
		// The mobility domain is shown as a claim beside the address.
		assert!(detail[0].contains("ft:a1b2"), "{:?}", detail[0]);
	}

	/// One SSID carrying an open, a passphrase and an enterprise network is
	/// three rows.
	///
	/// A real arrangement rather than a curiosity: a site offering a guest
	/// network, a staff one and 802.1X under one name is ordinary, and it is
	/// the case the grouping key was too coarse for. When the key was "is it
	/// secured" the passphrase network and the enterprise one merged, under a
	/// heading that said "secured" and described only one of them -- so an
	/// operator selecting that row got whichever came first.
	#[test]
	fn one_ssid_with_three_kinds_of_security_is_three_rows() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.scan = Some(serde_json::json!({
			"response": "wifi_scan",
			"access_points": [
				{
					"bssid": "f0:9f:c2:7d:bd:7d", "frequency": 2412, "signal": -40,
					"secured": true, "enterprise": false,
					"ssid": "4f70656e50432e7365", "name": "OpenPC.se"
				},
				{
					"bssid": "00:11:22:33:44:55", "frequency": 2437, "signal": -35,
					"secured": false, "enterprise": false,
					"ssid": "4f70656e50432e7365", "name": "OpenPC.se"
				},
				{
					"bssid": "00:11:22:33:44:66", "frequency": 5180, "signal": -50,
					"secured": true, "enterprise": true,
					"ssid": "4f70656e50432e7365", "name": "OpenPC.se"
				}
			]
		}));

		let lines = body(&app, ROW_COUNT_WIDTH);
		let headings: Vec<&String> = lines
			.iter()
			.filter(|line| line.contains("OpenPC.se"))
			.collect();
		assert_eq!(headings.len(), 3, "two were merged: {lines:?}");
		assert!(headings.iter().any(|line| line.contains("enterprise")));
		assert!(headings.iter().any(|line| line.contains("secured")));
		assert!(headings.iter().any(|line| line.contains("open")));
	}

	/// Same name, different security, is two networks and stays two.
	///
	/// The anomaly worth seeing, and the reason security is part of the
	/// grouping key rather than just something printed in the heading. An open
	/// clone of a secured network is the evil twin that can actually take
	/// your traffic, and collapsing it into the real one would hide the single
	/// difference a person should act on.
	#[test]
	fn the_same_name_with_different_security_is_not_grouped() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.scan = Some(serde_json::json!({
			"response": "wifi_scan",
			"access_points": [
				{
					"bssid": "f0:9f:c2:7d:bd:7d", "frequency": 2412, "signal": -40,
					"secured": true, "ssid": "4f70656e50432e7365", "name": "OpenPC.se"
				},
				{
					"bssid": "00:11:22:33:44:55", "frequency": 2437, "signal": -35,
					"secured": false, "ssid": "4f70656e50432e7365", "name": "OpenPC.se"
				}
			]
		}));

		let lines = body(&app, ROW_COUNT_WIDTH);
		let headings: Vec<&String> = lines
			.iter()
			.filter(|line| line.contains("OpenPC.se"))
			.collect();
		assert_eq!(headings.len(), 2, "an open clone was hidden: {lines:?}");
		assert!(headings.iter().any(|line| line.contains("secured")));
		assert!(headings.iter().any(|line| line.contains("open")));
	}

	/// A radio nobody has activated is offered, and the offer is actionable.
	///
	/// The state the machine that reported this was in: a radio, no `device`
	/// block, and a wifi pane that said "no wireless device in the
	/// configuration" and stopped -- describing the problem to somebody
	/// standing in front of the fix.
	#[test]
	fn an_unactivated_radio_is_offered_on_the_wifi_pane() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.radios = Some(serde_json::json!({
			"response": "radios",
			"radios": [{ "interface": "wlan0", "activated": false, "supplicant": false }]
		}));

		let rows = super::wifi_rows(&app, ROW_COUNT_WIDTH);
		let offered = rows
			.iter()
			.find(|(_, row)| matches!(row, super::Row::Radio(name) if name == "wlan0"))
			.expect("the radio is not offered: {rows:?}");
		assert!(offered.0.contains("wlan0"), "{:?}", offered.0);
		assert!(
			offered.0.contains("press c"),
			"the row does not say how to act on it: {:?}",
			offered.0
		);
	}

	/// A radio another manager holds is shown and is *not* actionable.
	///
	/// The state that wastes somebody's afternoon: pressing `c` would ask
	/// netcfgd to take a radio it declines to take while the other manager is
	/// running, so the row says who to stop instead of offering an action that
	/// cannot work.
	#[test]
	fn a_radio_another_manager_holds_is_named_and_not_offered() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.radios = Some(serde_json::json!({
			"response": "radios",
			"radios": [{ "interface": "wlan0", "activated": false, "supplicant": true }]
		}));

		let rows = super::wifi_rows(&app, ROW_COUNT_WIDTH);
		let line = rows
			.iter()
			.find(|(line, _)| line.contains("wlan0"))
			.expect("the radio is not shown");
		assert!(line.0.contains("another manager"), "{:?}", line.0);
		assert!(
			!matches!(line.1, super::Row::Radio(_)),
			"a radio that cannot be taken was offered anyway: {:?}",
			line.1
		);
	}

	/// A machine whose radios are all working shows networks and nothing else.
	///
	/// The other half, and the reason the list is conditional: hardware above
	/// the networks on every machine that is already working would push the
	/// useful part down the screen for ever.
	#[test]
	fn a_working_radio_is_not_listed_above_the_networks() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.radios = Some(serde_json::json!({
			"response": "radios",
			"radios": [{ "interface": "wlan0", "activated": true, "supplicant": true }]
		}));
		app.scan = Some(two_radio_scan());

		let rows = super::wifi_rows(&app, ROW_COUNT_WIDTH);
		assert!(
			!rows.iter().any(|(line, _)| line.contains("wlan0")),
			"a working radio is cluttering the pane: {rows:?}"
		);
		assert!(
			!rows.iter().any(|(line, _)| line == "radios"),
			"an empty radio section was drawn: {rows:?}"
		);
	}

	/// The selected line joins the network that line is about.
	///
	/// Grouping made the nth line stop being the nth entry, and `connect`
	/// indexed the entries by the line -- so selecting a heading below the
	/// first group would have joined some other network. That is the worst
	/// kind of list bug: it acts, confidently, on the wrong thing. This walks
	/// every line and asserts the entry it names is the one it displays.
	#[test]
	fn every_line_names_the_entry_it_is_about() {
		let (status, plan) = (status_response(), plan_response());
		let mut app = app(Pane::Wifi, &status, &plan);
		app.scan = Some(two_radio_scan());

		let rows = super::wifi_rows(&app, ROW_COUNT_WIDTH);
		let entries = app.scan_entries();
		assert!(rows.len() >= 3, "{rows:?}");

		for (line, row) in &rows {
			let super::Row::Network(at) = row else {
				continue;
			};
			let entry = entries.get(*at).expect("the index is in range");
			let bssid = entry
				.get("bssid")
				.and_then(serde_json::Value::as_str)
				.expect("a bssid");
			if line.starts_with("    ") {
				// A detail row names its own radio.
				assert!(line.contains(bssid), "{line} is not about {bssid}");
			} else {
				// A heading stands for its strongest member, which is the one
				// a client would associate with.
				assert_eq!(
					entry.get("signal").and_then(serde_json::Value::as_i64),
					Some(-40),
					"the heading points at the weaker radio: {line}"
				);
			}
		}
	}

	/// One access point, two radios, with a mobility domain on each.
	///
	/// **The weaker radio is listed first, deliberately.** The daemon sorts
	/// strongest-first, so in practice the first member of a group is its
	/// strongest and taking either would look right -- which is exactly why a
	/// fixture in that order proves nothing. Replacing the heading's
	/// strongest-member choice with "the first one" passed against a sorted
	/// fixture and fails against this, which is the difference between a test
	/// and a decoration.
	fn two_radio_scan() -> Value {
		serde_json::json!({
			"response": "wifi_scan",
			"access_points": [
				{
					"bssid": "f0:9f:c2:7e:bd:7d", "frequency": 5220, "signal": -45,
					"secured": true, "ssid": "4f70656e50432e7365", "name": "OpenPC.se",
					"mobility_domain": "a1b2"
				},
				{
					"bssid": "f0:9f:c2:7d:bd:7d", "frequency": 2412, "signal": -40,
					"secured": true, "ssid": "4f70656e50432e7365", "name": "OpenPC.se",
					"mobility_domain": "a1b2"
				}
			]
		})
	}

	/// The highlight cannot be moved off the end of the list.
	///
	/// Reported from a real terminal: holding the down key selected blank
	/// rows past the last device. `saturating_add` stops at `usize::MAX`,
	/// which is not a list length, so nothing bounded it.
	///
	/// Every pane, because the bound is one line of code and the reason to
	/// test all five is that each builds its rows differently -- the one that
	/// breaks will be the one nobody thought about. Events is included even
	/// though it draws no highlight: the index still moves, and a pane that
	/// starts drawing one later should not inherit the bug.
	#[test]
	fn the_highlight_stops_at_the_last_row() {
		let (status, plan) = (status_response(), plan_response());
		for pane in [
			Pane::Devices,
			Pane::Wifi,
			Pane::Clients,
			Pane::Plan,
			Pane::Events,
		] {
			let mut app = app(pane, &status, &plan);
			let rows = body(&app, ROW_COUNT_WIDTH).len();

			// Further than any pane here has rows, so the clamp is what stops
			// it rather than the loop running out.
			for _ in 0..(rows + 25) {
				app.key(curses::KEY_DOWN);
			}
			assert!(
				app.selected < rows.max(1),
				"{pane:?}: selected {} of {rows} rows",
				app.selected
			);

			// And the pair: it still reaches the last row. A clamp that pinned
			// the highlight at 0 would pass the assertion above and make the
			// pane useless.
			assert_eq!(
				app.selected,
				rows.saturating_sub(1),
				"{pane:?}: the last row is not reachable"
			);
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
