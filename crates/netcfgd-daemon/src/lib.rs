#![forbid(unsafe_code)]

//! `netcfgd`: watch, reconcile, and answer the control socket.
//!
//! The shape is three watcher threads feeding one `mpsc` receiver, and a
//! single-threaded loop that owns all the state. No locks, because nothing is
//! shared; no async runtime, because a daemon whose steady state is "asleep on
//! a channel" does not need one; no epoll, because that would mean `unsafe`
//! outside the one crate allowed it.

mod authorize;
mod confirm;
mod probe;
mod server;
mod sim;
mod state;
mod wifi;

use netcfgd_host::state as run_state;
use netcfgd_model::{Document, HookPhase};
use netcfgd_plan::PlanOptions;
use netcfgd_proto::{Event, Request, Response, DEFAULT_SOCKET};
use netcfgd_sys::socket::groups;
use netcfgd_sys::{Netlink, Watcher};
use server::Command;
use state::{Paths, State};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender, SyncSender};

const USAGE: &str = "\
netcfgd -- network configuration daemon

usage:
  netcfgd [options]

options:
  --config-dir PATH      default /etc/netcfgd, or $NCFG_CONFIG_DIR
  --factory-dir PATH     default /usr/share/netcfgd, or $NCFG_FACTORY_DIR.
                         Read before --config-dir, which overrides it
  --run-dir PATH         default /run/netcfgd, or $NCFG_RUN_DIR
  --socket PATH          default /run/netcfgd/netcfgd.sock
  --no-apply-on-start    observe and watch, but change nothing until asked
  --poll-config          use mtime polling rather than inotify
  -h, --help             this text
  --version              the version, and who holds the copyright
";

/// How long a quiet loop waits before looking anyway.
///
/// The watchers are event-driven, so this is a backstop rather than the
/// mechanism: it catches anything neither netlink nor the config watcher
/// reports, and it is what makes a missed event cost seconds rather than
/// forever.
const TICK_MS: i32 = 5_000;

/// The entry point, called by the multi-call binary rather than by the
/// runtime.
///
/// Both programs live in one binary that dispatches on `argv[0]`, because they
/// share most of their code and shipping it twice cost 775 KB of the install
/// -- three quarters of a megabyte of identical machine code, on the class of
/// device that has single-digit megabytes of flash free.
#[must_use]
pub fn main() -> ExitCode {
	let arguments: Vec<String> = std::env::args().skip(1).collect();
	match run(&arguments) {
		Ok(code) => code,
		Err(message) => {
			eprintln!("netcfgd: {message}");
			ExitCode::from(1)
		}
	}
}

struct Options {
	config_dir: Option<String>,
	factory_dir: Option<String>,
	run_dir: Option<String>,
	socket: Option<String>,
	apply_on_start: bool,
	poll_config: bool,
}

/// Parse the command line, or say what was wrong with it.
fn parse_options(arguments: &[String]) -> Result<Option<Options>, String> {
	let mut options = Options {
		config_dir: None,
		factory_dir: None,
		run_dir: None,
		socket: None,
		apply_on_start: true,
		poll_config: false,
	};

	let mut index = 0;
	while index < arguments.len() {
		let argument = arguments[index].as_str();
		let mut value = |name: &str| -> Result<String, String> {
			index += 1;
			arguments
				.get(index)
				.cloned()
				.ok_or_else(|| format!("{name} needs a value"))
		};
		match argument {
			"-h" | "--help" => {
				print!("{USAGE}");
				return Ok(None);
			}
			// The copyright surface harmonization.md names first. Shares
			// `netcfgd_model::COPYRIGHT` with `ncfg` so the two cannot drift
			// apart about a fact neither of them owns.
			"--version" => {
				println!("netcfgd {}", env!("CARGO_PKG_VERSION"));
				println!("{}", netcfgd_model::COPYRIGHT);
				return Ok(None);
			}
			"--config-dir" => options.config_dir = Some(value("--config-dir")?),
			"--factory-dir" => options.factory_dir = Some(value("--factory-dir")?),
			"--run-dir" => options.run_dir = Some(value("--run-dir")?),
			"--socket" => options.socket = Some(value("--socket")?),
			"--no-apply-on-start" => options.apply_on_start = false,
			"--poll-config" => options.poll_config = true,
			other => return Err(format!("unknown option `{other}`")),
		}
		index += 1;
	}
	Ok(Some(options))
}

fn run(arguments: &[String]) -> Result<ExitCode, String> {
	let Some(options) = parse_options(arguments)? else {
		return Ok(ExitCode::SUCCESS);
	};

	let paths = Paths {
		factory: netcfgd_host::config::resolve_factory_dir(options.factory_dir.as_deref()),
		config: netcfgd_host::config::resolve_dir(options.config_dir.as_deref()),
		run: run_state::resolve_dir(options.run_dir.as_deref()),
	};
	let socket_path = options
		.socket
		.map_or_else(|| paths.run.join("netcfgd.sock"), PathBuf::from);
	let _ = DEFAULT_SOCKET;

	let mut state = State::new(paths.clone());
	if let Some(diagnostics) = &state.diagnostics {
		eprintln!("netcfgd: config does not compile, running with none:\n{diagnostics}");
	}

	let (commands, incoming) = mpsc::channel();
	let control = state
		.desired
		.as_ref()
		.map(|document| document.globals.control.clone())
		.unwrap_or_default();
	bind_sockets(&socket_path, &control, &state, &commands)?;
	spawn_kernel_watcher(&commands);
	spawn_roam_watcher(&commands, netcfgd_supplicant::ctrl_dir());
	spawn_rfkill_watcher(
		&commands,
		// Overridable for the reason the supplicant's directory is: a network
		// namespace is not a device namespace, and a test that could not move
		// this would be reading the machine's own switches.
		std::env::var_os("NCFG_RFKILL_DEV")
			.map_or_else(|| PathBuf::from("/dev/rfkill"), PathBuf::from),
	);
	let mechanism = spawn_config_watcher(&commands, &paths, options.poll_config);

	eprintln!(
		"netcfgd: watching {} via {mechanism}, socket {}",
		paths.config.display(),
		socket_path.display()
	);
	report_contention(&state);

	// Before anything else: a window found here was opened by a daemon that is
	// no longer running, so nobody can have confirmed it.
	let startup_events = confirm::resolve_on_startup(&mut state);
	let reverted_at_startup = !startup_events.is_empty();

	establish_first_last_good(&state);

	let mut holding = start_up(&mut state, options.apply_on_start, reverted_at_startup);

	let mut subscribers: Vec<SyncSender<Event>> = Vec::new();
	// `recv` rather than `for .. in incoming`, because the burst-collapsing
	// below needs the receiver again inside the loop body.
	while let Ok(command) = incoming.recv() {
		// Collapse a burst into one pass. Bringing an interface up produces a
		// run of netlink messages, and re-reading once per message would make
		// the daemon's cost scale with the kernel's chattiness.
		let mut kernel_changed = false;
		let mut config_changed = false;
		let mut confirm_expired = false;
		let mut ticked = false;
		let mut requests = Vec::new();
		let mut roamed: Vec<(String, String)> = Vec::new();

		for command in std::iter::once(command).chain(server::drain(&incoming)) {
			match command {
				Command::KernelChanged => kernel_changed = true,
				Command::ConfigChanged => config_changed = true,
				Command::ConfirmExpired => confirm_expired = true,
				// **The backstop, which used to be discarded.** `TICK_MS`'s own
				// comment says it "catches anything neither netlink nor the
				// config watcher reports, and it is what makes a missed event
				// cost seconds rather than forever" -- and nothing consumed
				// it, so a machine that drifted in a way netlink did not
				// announce stayed drifted until something else woke the loop.
				//
				// It is what makes this a verification loop rather than an
				// apply: the plan computed below *is* the verification, and
				// its actions are the fix. A tick that finds nothing outstanding
				// costs one observation and stops.
				Command::Tick => ticked = true,
				// Not collapsed the way a netlink burst is: two roams are two
				// events, and a station that moved twice moved twice.
				Command::Roamed { interface, bssid } => roamed.push((interface, bssid)),
				Command::Subscribe { events } => subscribers.push(events),
				Command::Request {
					request,
					peer,
					origin,
					reply,
				} => requests.push((request, peer, origin, reply)),
			}
		}

		// **A timer resolves the window it was spawned for, and no other.**
		// `ConfirmExpired` carries no identity, so a timer outliving its own
		// window -- confirmed early, or reverted by hand -- used to revert
		// whatever window happened to be open when it fired. Measured: a
		// window confirmed at three seconds left its six-second timer running,
		// a second change armed a new window at five, and at six the first
		// timer reverted the second window two seconds into its life. The log
		// said "the window closed unconfirmed" about a window nobody had had
		// time to confirm.
		//
		// Asking the window whether it has actually expired costs one clock
		// read and cannot be fooled by an extra timer: a window with time left
		// is not one that closed. A stale timer now finds nothing to do, which
		// is what `spawn_expiry_timer`'s comment always claimed happened.
		if confirm_expired {
			resolve_expired_window(&mut state, &mut subscribers);
		}

		// Before the reobserve below, so a `roam` script sees the machine as
		// the move left it. Nothing here re-plans: a station moving within its
		// own network changes no desired state, which is why this is a hook and
		// not drift.
		for (interface, bssid) in &roamed {
			run_roam_hooks(&state, interface, bssid);
		}

		// **"The file was written" is not "the configuration changed"**, and the
		// confirm window turns on the difference. `Command::ConfigChanged` is
		// sent for any inotify event, so an editor writing the same bytes, or
		// a configuration-management tool rewriting the file on a timer, sets
		// it -- and a reload that fails to compile sets it while leaving the
		// desired document exactly as it was.
		//
		// Either of those on a pass that is also correcting drift used to arm
		// a window over the drift correction, which 0157 says never happens.
		// Measured with a sysctl, whose drift the kernel does not announce and
		// which is therefore still outstanding when the rewrite wakes the
		// loop: a byte-identical write armed a window over netcfgd putting
		// `forwarding` back. On expiry that reverts netcfgd's own repair, the
		// drift is found again on the next pass, and the machine oscillates.
		//
		// Comparing the document either side of the reload is what makes the
		// exclusion true rather than intended.
		let config_is_new = config_changed && reload_configuration(&mut state, &mut subscribers);

		// Whatever is due, and only a *changed* verdict counts as movement.
		// A probe that has agreed with itself for an hour should cost the
		// program it runs and nothing else -- no re-observation, no plan, no
		// event. Run before the block below so a verdict that did change goes
		// round the same path a carrier change does (0119).
		let probe_changed = state.probes.run_due(state.desired.as_ref());

		advance_failed_sims(&mut state, probe_changed);

		if kernel_changed || config_changed || probe_changed || ticked {
			announce_links(state.reobserve(), &mut subscribers);
			let drift = state.detect_drift();
			for event in &drift {
				server::broadcast(&mut subscribers, event);
			}
			// Before the reconcile, so a `drift` script sees the machine as it
			// drifted rather than as netcfgd has just put it back. That is the
			// only ordering that makes the hook worth having under
			// `reconcile`, where the window between the two is milliseconds.
			let told = state.run_drift_hooks(&drift);
			remember_drift(&state, &told);
			// After the drift hooks and before the reconcile, for the same
			// reason: a script sees the machine as the change left it.
			remember_told(&state, HookPhase::Portal, &run_portal_checks(&state));
			// **Observing is not holding.** `--no-apply-on-start` says the
			// daemon should observe and be told when to act, so only the
			// acting is held -- everything above still runs. Gating the
			// observation too left the daemon planning against what it saw at
			// startup, which is worse than not looking: it answers `apply`
			// with a plan for a machine that has since moved, and the operator
			// gets an apply that does the wrong work and reports success.
			// Before the reconcile, and not inside it: once netcfgd holds a
			// backend the plan says "nothing to do" for that interface and
			// `reconcile_drift` returns early, so a claim that appears after
			// netcfgd took the radio was never looked at again.
			release_contended(&mut state);
			if !holding && !defers_to_a_window(&state, &requests) {
				reconcile_drift(&mut state, &mut subscribers, config_is_new, &commands);
			}
		}

		if holding && releases_the_hold(&requests) {
			holding = false;
		}

		serve_requests(&mut state, requests, &mut subscribers, &commands);
	}

	Ok(ExitCode::SUCCESS)
}

/// Make a confirm window possible on the very first apply.
///
/// A window reverts to the last-good configuration, and until netcfgd has
/// applied once there is none -- so `ncfg apply --confirm-within` was refused
/// exactly when an operator most wanted it, on the first apply on a machine
/// they were still unsure about.
///
/// The missing document is an empty one, and that is not a placeholder: before
/// netcfgd's first apply its desired state genuinely was nothing. Reverting to
/// it removes every address, route, link and backend netcfgd installed and
/// touches nothing it did not, which is the exact undo of a first apply.
///
/// What it does *not* do is restore connectivity that netcfgd was not
/// providing. If a device was handed over from `NetworkManager` and netcfgd's
/// config is wrong, reverting leaves the device unconfigured rather than back
/// on `NetworkManager` -- that is what "the way it was" means once the handover
/// has happened, and doc/first-run.md says so.
///
/// Written before the startup apply and only when absent, so the ordinary
/// reboot case is untouched: `converge` overwrites it with the real document a
/// moment later.
fn establish_first_last_good(state: &State) {
	if netcfgd_host::confirm::read_last_good(&state.paths.run).is_some() {
		return;
	}
	let empty = netcfgd_model::Document::default();
	if netcfgd_host::confirm::write_last_good(&state.paths.run, &empty).is_ok() {
		eprintln!(
			"netcfgd: no previous configuration recorded, so a revert would undo \
			 everything netcfgd does from here. `ncfg apply --confirm-within N` \
			 works from the first apply."
		);
	}
}

/// The plan, with what stands in the way of it.
///
/// Split from [`answer`] for its line budget, and it is a coherent piece: a
/// plan a client reads should carry everything netcfgd knows about whether it
/// can be carried out.
fn plan_response(state: &State) -> Response {
	if let Some(diagnostics) = &state.diagnostics {
		return Response::error(diagnostics.clone());
	}
	let mut plan = state.plan(&PlanOptions::default());
	add_contention_warnings(state, &mut plan);
	Response::Plan(Box::new(plan))
}

/// Put "something else manages this interface" into the plan netcfgd serves.
///
/// **It was only ever rendered by `ncfg plan`, locally.** The CLI computed
/// contention itself and printed it beside the daemon's warnings, so the one
/// client that read `/run` was the one that needed it least -- and every other
/// client was told nothing. The GUI's wifi tab therefore had no way to say why
/// scans on a contended radio fail every other attempt, which is the report
/// this came from: a scan whose control socket vanishes for a moment answers
/// "is `wpa_supplicant` running?", which is true and the wrong question.
///
/// The daemon already works it out at startup for the log. Doing it here as
/// well puts it where every client can see it, which is what a plan is for --
/// it is netcfgd's account of what it would do and what stands in the way.
fn add_contention_warnings(state: &State, plan: &mut netcfgd_plan::Plan) {
	let Some(desired) = &state.desired else {
		return;
	};
	let claimed: Vec<(String, u32)> = desired
		.interfaces
		.iter()
		.filter_map(|interface| {
			state
				.observed
				.link(&interface.name)
				.map(|link| (interface.name.clone(), link.index))
		})
		.collect();

	for contender in netcfgd_host::contention::contenders(&claimed) {
		let message = netcfgd_host::contention::describe(&contender);
		// One warning per interface rather than one naming several: a client
		// filters by the interface it is showing, and a warning naming three
		// belongs to none of them.
		for interface in &contender.interfaces {
			plan.warnings.push(netcfgd_plan::Warning {
				message: message.clone(),
				interface: Some(interface.clone()),
			});
		}
	}
}

/// Say so at startup if another daemon manages an interface this config
/// claims.
///
/// At startup rather than only in a plan, because the daemon is the case where
/// nobody is reading a plan: it comes up at boot, applies, and the operator
/// sees the result hours later. A line in the log at the moment it starts is
/// the only warning they will get.
fn report_contention(state: &State) {
	let Some(desired) = &state.desired else {
		return;
	};
	let claimed: Vec<(String, u32)> = desired
		.interfaces
		.iter()
		.filter_map(|interface| {
			state
				.observed
				.link(&interface.name)
				.map(|link| (interface.name.clone(), link.index))
		})
		.collect();

	for contender in netcfgd_host::contention::contenders(&claimed) {
		eprintln!(
			"netcfgd: {}",
			netcfgd_host::contention::describe(&contender)
		);
	}
}

/// Apply whatever the config asks for, reporting failures to stderr.
/// Configure the machine at startup, and say whether the loop is held.
///
/// **A latch, not a startup skip.** `--no-apply-on-start` says the daemon
/// should observe and be told when to act, and once the loop reconciles on its
/// own that has to keep meaning something -- otherwise the flag delays acting
/// by one tick and no more, and the *protected first apply* it exists for
/// cannot happen: the window on `ncfg apply` is there because the first apply
/// after a boot is the one that can take the network away.
///
/// So it holds until an explicit apply arrives, and then the machine is
/// netcfgd's like any other. **Only the acting is held**; the loop goes on
/// observing, because a daemon planning against what it saw at startup answers
/// `apply` with work for a machine that has since moved.
fn start_up(state: &mut State, apply_on_start: bool, reverted: bool) -> bool {
	if apply_on_start && !reverted {
		// A network configuration daemon that starts and configures nothing is
		// not doing its job; design section 4.4 makes oneshot the alternative
		// rather than the default.
		converge(state, &mut Vec::new());
	}
	!apply_on_start
}

/// Whether the watcher should stand back and let a window cover this change.
///
/// **The reconcile runs before the requests are served**, so an operator's
/// `ncfg apply --confirm-within 60` landing in the same burst as the
/// `ConfigChanged` it accompanies was answered after `reconcile_drift` had
/// already applied the change. The window then covered nothing: measured three
/// times out of three, the only inverse a windowed apply recorded was the one
/// for arming the window itself. A commit-confirm window that covers nothing
/// is worse than none, because the operator believes they have a way back.
///
/// Two cases, and they are different questions.
///
/// A pending `Apply` carrying a window is the operator saying they want this
/// change to be revertible. Deferring costs one pass of the loop: the apply is
/// served a few lines below and does the work itself, with the window that
/// goes with it. **This half only fires when the request is already in the
/// burst**, which measurement says is the uncommon case: the request arrives
/// about eight milliseconds after the pass that reconciles, in a pass of its
/// own. Making it reliable needs the loop to wait after a config change, and
/// a settle short enough not to cost automatic convergence -- 300ms, 500ms,
/// 1s were each tried -- did not close it, while 3s did. A three-second delay
/// on every automatic reconcile is not a trade to make in passing, so what is
/// here is the half that costs nothing and the gap is written down.
///
/// An **open** window means a change is already awaiting confirmation.
/// Reconciling over it would apply something the operator has not accepted
/// yet, on top of something they may be about to reject, and the revert would
/// then undo a state nobody ever chose. `confirm::may_arm` already refuses to
/// arm a second window over the first; this is the same rule from the other
/// side.
///
/// What this deliberately does not do is hold indefinitely. An operator who
/// edits the file and applies a minute later has a reconcile in between, and
/// their window still covers nothing -- closing that needs the watcher to wait
/// for an operator on every change, which would stop an unattended machine
/// converging. That trade is not this function's to make.
fn defers_to_a_window(
	state: &State,
	requests: &[(
		Request,
		netcfgd_sys::peer::Peer,
		authorize::Origin,
		SyncSender<Response>,
	)],
) -> bool {
	if netcfgd_host::confirm::read_window(&state.paths.run).is_some() {
		return true;
	}
	a_window_is_requested(requests.iter().map(|(request, ..)| request))
}

/// Does any pending request ask for a window?
///
/// Split out from `defers_to_a_window` so it can be tested: the tuples that
/// arrive at the loop carry a `SyncSender`, and a predicate that cannot be
/// exercised without building one is a predicate nothing exercises.
fn a_window_is_requested<'a>(requests: impl Iterator<Item = &'a Request>) -> bool {
	requests.into_iter().any(|request| {
		matches!(
			request,
			Request::Apply {
				confirm: Some(seconds),
				..
			} if *seconds > 0
		)
	})
}

/// Resolve a window whose timer has fired.
///
/// **A timer resolves the window it was spawned for, and no other.**
/// `ConfirmExpired` carries no identity, so a timer outliving its own window --
/// confirmed early, or reverted by hand -- used to revert whatever window
/// happened to be open when it fired. Measured: a window confirmed at three
/// seconds left its six-second timer running, a second change armed a new
/// window at five, and at six the first timer reverted the second window two
/// seconds into its life. The log said "the window closed unconfirmed" about a
/// window nobody had had time to confirm.
///
/// Asking the window whether it has actually expired costs one clock read and
/// cannot be fooled by an extra timer: a window with time left is not one that
/// closed. A stale timer now finds nothing to do, which is what
/// `spawn_expiry_timer`'s comment always claimed happened.
fn resolve_expired_window(state: &mut State, subscribers: &mut Vec<SyncSender<Event>>) {
	let still_open = netcfgd_host::confirm::read_window(&state.paths.run);
	if still_open.is_some_and(|window| window.expired()) {
		let (_, events) = confirm::revert(state, "the window closed unconfirmed");
		for event in events {
			server::broadcast(subscribers, &event);
		}
	}
}

/// Recompile, and say whether the desired document actually moved.
///
/// **"The file was written" is not "the configuration changed"**, and the
/// confirm window turns on the difference. `Command::ConfigChanged` is sent for
/// any inotify event, so an editor writing the same bytes, or a
/// configuration-management tool rewriting the file on a timer, sets it -- and
/// a reload that fails to compile sets it while leaving the desired document
/// exactly as it was.
///
/// Either of those on a pass that is also correcting drift used to arm a window
/// over the drift correction, which 0157 says never happens. Measured with a
/// sysctl, whose drift the kernel does not announce and which is therefore
/// still outstanding when the rewrite wakes the loop: a byte-identical write
/// armed a window over netcfgd putting `forwarding` back. On expiry that
/// reverts netcfgd's own repair, the drift is found again on the next pass, and
/// the machine oscillates.
///
/// Comparing the document either side of the reload is what makes the exclusion
/// true rather than intended.
fn reload_configuration(state: &mut State, subscribers: &mut Vec<SyncSender<Event>>) -> bool {
	let before = state.desired.as_ref().map(netcfgd_host::document_hash);
	let event = state.reload();
	let moved = state.desired.as_ref().map(netcfgd_host::document_hash) != before;
	server::broadcast(subscribers, &event);
	moved
}

/// Whether this batch of requests is the operator taking their turn.
///
/// `--no-apply-on-start` holds the reconcile loop until somebody applies
/// deliberately, so that the *first* apply after a boot is the one carrying a
/// confirm window -- it is the one that can take the network away. An explicit
/// apply is what the hold was waiting for; nothing else releases it, because
/// nothing else is the operator saying "go".
fn releases_the_hold(
	requests: &[(
		Request,
		netcfgd_sys::peer::Peer,
		authorize::Origin,
		SyncSender<Response>,
	)],
) -> bool {
	requests
		.iter()
		.any(|(request, ..)| matches!(request, Request::Apply { .. }))
}

/// Give back a radio netcfgd should not be holding.
///
/// **The boot race, and the only part of it netcfgd can fix.** The guard in
/// `start_supplicant` refuses an interface another manager claims, and learns
/// that from the files `NetworkManager` writes once it has decided it owns a
/// device. netcfgd starts `Before=network-pre.target`, so it can reach that
/// guard before NM has written anything -- the radio looks free, netcfgd takes
/// it, and NM declares a moment later. Two supplicants on one radio drop the
/// association, which is the fault this whole milestone was about.
///
/// The check therefore belongs on the tick as well as at start. Once netcfgd
/// holds a backend the plan says "nothing to do" for it, so nothing was ever
/// looking again.
///
/// **netcfgd stops only its own process.** That is what keeps this inside
/// `contention`'s rule that netcfgd reports rather than acts: nothing here
/// touches another daemon, and what is given back is a radio netcfgd took in a
/// window where it could not have known better. Holding it is the thing making
/// the machine unusable, and an operator who wants netcfgd to have the radio
/// says so by handing it over -- which is what the message names.
fn release_contended(state: &mut State) {
	use netcfgd_apply::Executor as _;

	let Some(desired) = &state.desired else {
		return;
	};
	// Only interfaces netcfgd currently runs a backend on: a contended
	// interface netcfgd is not touching is the ordinary coexistence case, and
	// saying anything about it here would repeat the warning the plan already
	// carries.
	let held: Vec<(String, u32)> = desired
		.interfaces
		.iter()
		.filter(|interface| {
			state
				.observed
				.backends
				.iter()
				.any(|backend| backend.interface == interface.name && backend.running)
		})
		.filter_map(|interface| {
			state
				.observed
				.link(&interface.name)
				.map(|link| (interface.name.clone(), link.index))
		})
		.collect();
	if held.is_empty() {
		return;
	}

	let Ok(mut executor) = state.executor() else {
		eprintln!("netcfgd: cannot open a netlink socket to release a contended radio");
		return;
	};
	for contender in netcfgd_host::contention::contenders(&held) {
		for interface in &contender.interfaces {
			let kinds: Vec<netcfgd_model::BackendKind> = state
				.observed
				.backends
				.iter()
				.filter(|backend| &backend.interface == interface && backend.running)
				.map(|backend| backend.kind)
				.collect();
			for kind in kinds {
				eprintln!(
					"netcfgd: {} claims {interface}, which netcfgd is running a {kind:?} on -- \
					 two managers on one interface drop the association, so netcfgd is \
					 stopping its own and leaving the interface to {}. {}",
					contender.name,
					contender.name,
					netcfgd_host::contention::describe(&contender)
				);
				if let Err(error) = executor.execute(&netcfgd_plan::Op::BackendStop {
					kind,
					iface: interface.clone(),
				}) {
					eprintln!("netcfgd: could not stop the {kind:?} on {interface}: {error}");
				}
			}
		}
	}
}

fn converge(state: &mut State, subscribers: &mut Vec<SyncSender<Event>>) {
	let Ok(mut executor) = state.executor() else {
		eprintln!("netcfgd: cannot open a netlink socket to apply");
		return;
	};
	let (plan, journal) = state.apply(&PlanOptions::default(), &mut executor);
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));

	if let Some(failure) = journal.failure() {
		eprintln!(
			"netcfgd: {} failed: {}",
			failure.op,
			failure.error.as_deref().unwrap_or("no detail")
		);
	}
	for refusal in &plan.refusals {
		eprintln!(
			"netcfgd: refused {} on {} -- {} depends on it",
			refusal.op, refusal.interface, refusal.guard
		);
	}
	state.reobserve();

	// This configuration is now the one in effect, so it is what a future
	// commit-confirm window falls back to. Without recording it here, the
	// first `apply --confirm-within` after a boot is refused for having
	// nothing to revert to -- which is safe, and useless.
	if journal.failure().is_none() {
		if let Some(desired) = &state.desired {
			let _ = netcfgd_host::confirm::write_last_good(&state.paths.run, desired);
		}
	}

	server::broadcast(
		subscribers,
		&Event::Observed {
			summary: format!("applied {} actions", journal.done()),
		},
	);
}

/// Tell subscribers the kernel's link set moved.
///
/// **A link appearing or going away is an event even when netcfgd does nothing
/// about it.** `Event::Observed` is documented as "the kernel reported a
/// change" and was emitted only after an apply -- so a client subscribing to
/// the stream heard about the machine only when netcfgd acted on it.
///
/// That is exactly wrong for an unmanaged device, which netcfgd deliberately
/// never acts on. Deleting one produced no drift, no reconcile and no event,
/// and the `NetworkManager` shim -- which redraws on any event and has no other
/// trigger -- went on serving a device whose link was gone, reporting it as
/// `unmanaged` for ever. Measured before the fix: two events for deleting a
/// managed link, none at all for an unmanaged one.
fn announce_links(moved: bool, subscribers: &mut Vec<std::sync::mpsc::SyncSender<Event>>) {
	if !moved {
		return;
	}
	server::broadcast(
		subscribers,
		&Event::Observed {
			summary: "the links the kernel reports have changed".to_owned(),
		},
	);
}

/// Answer everything that arrived this pass.
///
/// The policy is re-read per request rather than once per pass, because a
/// reload earlier in the same pass may have changed it -- and a request
/// authorised against the configuration that was replaced a moment ago is a
/// permission check on a document nobody is running.
fn serve_requests(
	state: &mut State,
	requests: Vec<(
		Request,
		netcfgd_sys::peer::Peer,
		authorize::Origin,
		SyncSender<Response>,
	)>,
	subscribers: &mut Vec<SyncSender<Event>>,
	commands: &Sender<Command>,
) {
	for (request, peer, origin, reply) in requests {
		let policy = state
			.desired
			.as_ref()
			.map(|document| document.globals.control.clone())
			.unwrap_or_default();
		let remote = state
			.desired
			.as_ref()
			.map(|document| document.globals.remote.clone())
			.unwrap_or_default();
		let response = authorized(
			state,
			&policy,
			&remote,
			origin,
			&peer,
			&request,
			subscribers,
			commands,
		);
		// A client that hung up between asking and being answered is ordinary,
		// not an error.
		let _ = reply.send(response);
	}
}

/// Check the peer, then answer.
///
/// Split out of the loop because the loop was over its line budget and this is
/// the part that reads as one thought: what may this connection do, and given
/// that, what does it get told. The tiers are worked out whether or not the
/// request is allowed, because `hello` reports them and `hello` is the request
/// somebody with no permissions can still make.
#[allow(clippy::too_many_arguments)]
fn authorized(
	state: &mut State,
	policy: &netcfgd_model::Control,
	remote: &netcfgd_model::RemotePolicy,
	origin: authorize::Origin,
	peer: &netcfgd_sys::peer::Peer,
	request: &Request,
	subscribers: &mut Vec<SyncSender<Event>>,
	commands: &Sender<Command>,
) -> Response {
	let granted = authorize::granted(policy, remote, origin, peer);
	// One call, deliberately. There are two gates behind it -- may this caller
	// make a request of this kind, and may they send what is in it -- and
	// asking them separately here is how the second came to be missing while
	// every test of it passed.
	match authorize::permitted(policy, remote, origin, peer, request) {
		Ok(()) => answer(state, request, subscribers, Some(commands), &granted),
		Err(message) => Response::error(message),
	}
}

/// Bind the local socket, and the remote one where a policy asks for it.
///
/// Split out because `run` was over its line budget, which is the same reason
/// `authorized` is its own function. It also reads as one thought: which
/// sockets this machine offers, and why the second one is usually absent.
///
/// **0128: the remote socket exists only when a remote policy does.** A
/// machine that has never configured remote access has nothing listening for
/// it -- constraint 2 applied where the difference is a security property
/// rather than tidiness, since a socket that does not exist is one nothing can
/// reach through.
///
/// Both carry the same `Control`, and that is not an oversight: the local
/// policy is what `Origin::Local` connections are judged against, and a remote
/// connection never consults it. Passing it keeps `serve` one function rather
/// than two that must agree about how a socket is set up.
fn bind_sockets(
	socket_path: &std::path::Path,
	control: &netcfgd_model::Control,
	state: &State,
	commands: &Sender<Command>,
) -> Result<(), String> {
	server::serve(
		socket_path,
		control,
		authorize::Origin::Local,
		commands.clone(),
	)
	.map_err(|error| format!("could not bind {}: {error}", socket_path.display()))?;

	let remote = state
		.desired
		.as_ref()
		.map(|document| document.globals.remote.clone())
		.unwrap_or_default();
	if !remote.is_open() {
		return Ok(());
	}

	let remote_path = socket_path.with_file_name("remote.sock");
	server::serve(
		&remote_path,
		control,
		authorize::Origin::Remote,
		commands.clone(),
	)
	.map_err(|error| format!("could not bind {}: {error}", remote_path.display()))?;
	// Said out loud, because a listening socket that reaches the network is
	// the one thing about this daemon an operator should never discover by
	// finding the file.
	eprintln!(
		"netcfgd: remote access is open on {} -- observe {}, wifi {}, admin {}",
		remote_path.display(),
		remote.observe,
		remote.wifi,
		remote.admin
	);
	Ok(())
}

/// Watch `/dev/rfkill` so a flipped switch is noticed as it happens.
///
/// 0062 made netcfgd report a blocked radio; this is what makes the report
/// prompt. An observation runs on a netlink event or on the loop's five-second
/// backstop, and a kill switch produces neither reliably -- *blocking* a radio
/// usually takes the interface down and shows up on netlink, but *unblocking*
/// one produces nothing until something else happens, so the machine could sit
/// with a working radio and a plan still saying it was off.
///
/// It reports `KernelChanged` rather than a command of its own. What changed is
/// something an observation reads, so the answer is the one netlink already
/// gets: look again. A second command would mean a second path through the loop
/// doing the same thing.
///
/// Opening the device replays one `ADD` per existing switch, so the first few
/// wake the loop for a state it already has. That is a handful of reobservations
/// at startup and it is the honest cost of not having to ask `/sys` whether
/// anything changed while netcfgd was not running.
///
/// A machine with no radio has no `/dev/rfkill`; the thread ends and says
/// nothing, because "this laptop has no wifi" is not a warning.
fn spawn_rfkill_watcher(commands: &Sender<Command>, device: PathBuf) {
	let commands = commands.clone();
	let _ = std::thread::Builder::new()
		.name("rfkill".to_owned())
		.spawn(move || {
			let Ok(mut rfkill) = netcfgd_sys::rfkill::Rfkill::open(&device) else {
				return;
			};
			loop {
				match rfkill.next_event() {
					Ok(Some(_)) => {
						if commands.send(Command::KernelChanged).is_err() {
							return;
						}
					}
					// The device went away, or cannot be read. Either way there
					// is nothing to watch and nothing to retry against.
					Ok(None) | Err(_) => return,
				}
			}
		});
}

/// Probe for a captive portal on an interface that has just become addressed.
///
/// **Not a plan action.** A probe is not a change, so an action would run on
/// every apply and no plan would ever converge -- section 4's promise. It is
/// also not something an observation can answer: netcfgd has to *ask*, which is
/// I/O, and doing it on every netlink event would be a request to somebody
/// else's server every time a cable moved.
///
/// So it fires on a transition: the interface has an address now and did not
/// when this last looked. That is when a portal appears, and it is once per
/// joining rather than once per event -- the same record `carrier` and `lease`
/// use, for the reason 0084 gives.
///
/// Only where the operator gave a URL. No URL, no probe, on every machine that
/// did not ask (0061, 0095).
///
/// Returns what it told each interface, for the caller to record.
fn run_portal_checks(state: &State) -> Vec<(String, String)> {
	let Some(desired) = state.desired.as_ref() else {
		return Vec::new();
	};
	let mut told = Vec::new();

	for device in &desired.devices {
		let Some(url) = device
			.wifi
			.as_ref()
			.and_then(|wifi| wifi.portal_check.as_ref())
		else {
			continue;
		};
		// The addresses netcfgd can see on the device's own interface. A portal
		// hands out a perfectly ordinary lease, so "addressed" is exactly the
		// moment the machine looks configured and may not be.
		let addressed = state.observed.addresses.iter().any(|address| {
			address.interface == device.name && netcfgd_host::portal::is_routable(&address.address)
		});
		let was = State::last_told(&state.observed, &device.name, HookPhase::Portal);

		// Nothing to do while it stays as it was. The record holds "addressed"
		// or "bare" rather than the verdict, because what this fires on is the
		// transition and not what the transition turned out to mean.
		let now = if addressed { "addressed" } else { "bare" };
		if was.as_deref() == Some(now) {
			continue;
		}
		told.push((device.name.clone(), now.to_owned()));
		if !addressed {
			continue;
		}

		let verdict = netcfgd_host::portal::probe(url, 204);
		let detail = match &verdict {
			// Nothing in the way. Said to the log and to nobody else: a hook
			// that ran on every successful join would be a hook nobody keeps.
			netcfgd_host::portal::Verdict::Clear => continue,
			netcfgd_host::portal::Verdict::Portal { detail } => {
				eprintln!(
					"netcfgd: {} looks like a captive portal: {detail}",
					device.name
				);
				detail.clone()
			}
			// Something else is wrong -- no route, no resolver, nothing
			// listening. Reported and *not* called a portal: a portal is a
			// thing that replies, and saying "captive portal" about a network
			// with no route sends the operator to a login page that is not
			// there.
			netcfgd_host::portal::Verdict::Unreachable { detail } => {
				eprintln!("netcfgd: {} could not be checked: {detail}", device.name);
				continue;
			}
		};

		for interface in desired.interfaces.iter().filter(|i| i.name == device.name) {
			for hook in interface
				.hooks
				.iter()
				.filter(|hook| hook.phase == HookPhase::Portal)
			{
				let env = netcfgd_apply::hooks::HookEnv::for_interface(&device.name)
					.because(format!("a captive portal answered: {detail}"))
					.with("NCFG_URL", url.clone());
				match netcfgd_apply::hooks::run(hook, &env) {
					netcfgd_apply::hooks::Outcome::Ok => {}
					netcfgd_apply::hooks::Outcome::Vetoed(message)
					| netcfgd_apply::hooks::Outcome::Noted(message) => {
						eprintln!("netcfgd: {message}");
					}
				}
			}
		}
	}
	told
}

/// Run the `roam` hooks for an interface that has just moved.
///
/// **No de-duplication, unlike `drift`.** That one fires on a condition which
/// persists -- the machine stays drifted until something fixes it, so firing on
/// presence would run the script forever. A roam is not a condition; it is a
/// thing that happened once, and the watcher already reports only a *change* of
/// access point. Suppressing a second would mean a station that moved back and
/// forth told the script once.
///
/// Never a veto: the move has happened, and there is nothing left to stop.
fn run_roam_hooks(state: &State, interface: &str, bssid: &str) {
	let Some(desired) = state.desired.as_ref() else {
		return;
	};
	let Some(configured) = desired.interfaces.iter().find(|i| i.name == interface) else {
		return;
	};
	for hook in configured
		.hooks
		.iter()
		.filter(|hook| hook.phase == netcfgd_model::HookPhase::Roam)
	{
		let env = netcfgd_apply::hooks::HookEnv::for_interface(interface)
			.because(format!("moved to {bssid}"))
			.with("NCFG_BSSID", bssid.to_owned());
		match netcfgd_apply::hooks::run(hook, &env) {
			netcfgd_apply::hooks::Outcome::Ok => {}
			netcfgd_apply::hooks::Outcome::Vetoed(message)
			| netcfgd_apply::hooks::Outcome::Noted(message) => {
				eprintln!("netcfgd: {message}");
			}
		}
	}
}

/// Record what the `drift` phase has been told, so it is told once.
///
/// Through the same `/run` record the `carrier` and `lease` phases use, and
/// through that alone. The first version wrote it into the in-memory
/// observation as well, with a comment saying why that was necessary; breaking
/// the line changed nothing, because `reobserve` reads this record back and
/// runs before every drift check. Breaking *this* write turns one hook run into
/// seven. The comment was the kind of claim that outlives its reason, so the
/// line went rather than the claim.
fn remember_drift(state: &State, told: &[(String, String)]) {
	remember_told(state, netcfgd_model::HookPhase::Drift, told);
}

/// Record what a phase was last told about each interface.
///
/// One record per interface and phase, which is what makes "fire on the change"
/// possible for `drift` and for `portal` without either keeping state of its
/// own. Written to `/run` and nowhere else: `reobserve` reads it back and runs
/// before every check, which is the whole of why an in-memory copy was removed
/// from here rather than kept (0084).
fn remember_told(state: &State, phase: netcfgd_model::HookPhase, told: &[(String, String)]) {
	if told.is_empty() {
		return;
	}
	let _ = run_state::update_owned(&state.paths.run, |owned| {
		for (interface, value) in told {
			owned
				.hook_state
				.retain(|record| &record.interface != interface || record.phase != phase);
			owned.hook_state.push(netcfgd_model::ObservedHookState {
				interface: interface.clone(),
				phase,
				value: value.clone(),
			});
		}
	});
}

/// Put back what drifted, but only on interfaces whose policy says to.
/// Move a modem to its next SIM source when its probe says the link is dead.
///
/// [0152](../../../doc/decision/0152-a-sim-source-is-kept-until-the-probe-says-otherwise.md).
/// Only a *decided* failure counts: 0119 leaves an unprobed link at `None`,
/// and switching a SIM on no information is what that rule exists to prevent
/// -- so a modem with no `probe` block never falls back, deliberately.
///
/// Called only when a verdict moved, so a link that has been down for an hour
/// costs nothing. `advance` would return `None` on every tick after the first
/// anyway, but reaching it would still be work.
///
/// A device and an interface with the same kernel name are the same hardware,
/// which is what makes the probe's interface name a device lookup here.
fn advance_failed_sims(state: &mut State, probe_changed: bool) {
	if !probe_changed {
		return;
	}
	let Some(document) = state.desired.clone() else {
		return;
	};
	for iface in state.probes.failing() {
		if let Some(source) = state.sims.advance(&document, &iface, &state.paths.run) {
			eprintln!("netcfgd: {iface}: probe says this link is dead; trying SIM `{source}`");
		}
	}
}

/// The window a config change should arm, and what it would fall back to.
///
/// `global { confirm = N }` says every change to this machine's configuration
/// gets a safety net. Until now the only thing that read it was the planner,
/// which emitted a `commit.arm` action -- and `commit.arm` is a marker the
/// executor deliberately no-ops, because the window belongs to the daemon.
/// So the action was recorded `Done`, counted in "applied N actions", and no
/// window was ever written. An operator who wrote the key and watched an
/// apply succeed had exactly the safety net they would have had without it.
///
/// **Only a configuration change, and that is the whole design.** The two
/// exclusions are not omissions:
///
/// A **drift** reconcile is netcfgd putting back what something else changed.
/// Arming there would revert netcfgd's own correction when nobody confirmed,
/// the drift would be detected again on the next pass, and the machine would
/// oscillate -- spending half its time in the state the reconcile exists to
/// leave. Nobody is waiting to confirm a correction they did not ask for.
///
/// **Startup** is worse. `establish_first_last_good` writes an empty document
/// as the last-good before the first apply, so on a machine that has never
/// applied, a window armed at boot and left unconfirmed reverts to *nothing*
/// -- taking down every address, route and backend netcfgd had just brought
/// up, N seconds after start, with no operator present. `converge` runs from
/// `start_up` rather than from the loop, so it is exempt by construction, and
/// this comment is here to stop somebody wiring it in later.
///
/// Called after `reconcile_drift`'s early returns rather than before the apply.
/// Before was the first arrangement, on the reasoning that the decision should
/// be taken while nothing had moved -- and neither half of that held: `may_arm`'s
/// already-armed branch is unreachable from here, because `defers_to_a_window`
/// has already sent the loop away when a window is open, and nothing between the
/// plan and the arm touches `last-good.json`. What it did do was announce a
/// refusal to arm on a pass that then applied nothing at all.
fn window_for_a_config_change(state: &State, config_changed: bool) -> Option<(u32, Document)> {
	if !config_changed {
		return None;
	}
	// **Asked of the planner rather than re-derived here.** The rule has three
	// cases -- the caller's number, the caller's zero meaning "no window
	// despite the default", and the document's own -- and a second copy of it
	// beside this one is how the two would stop agreeing about, say, whether a
	// zero in the file counts. The plan cannot answer for us, because the
	// `commit.arm` it produces is a marker `state::restrict` drops on this path
	// before the executor ever sees it; the decision behind it is what is
	// wanted, so that is what is asked for.
	let desired = state.desired.as_ref()?;
	let seconds = netcfgd_plan::confirm_window(desired, &PlanOptions::default())?;
	let last_good = match confirm::may_arm(state) {
		Ok(document) => document,
		// Said out loud rather than swallowed. The request path returns the
		// refusal to whoever asked; nobody asked for this one, so an operator
		// who set the key and watched the change apply would otherwise believe
		// they had a window and have none.
		Err(error) => {
			eprintln!(
				"netcfgd: not arming a window for this change: {}",
				error.message()
			);
			return None;
		}
	};
	// **A window whose fall-back is the placeholder is not a safety net, it is
	// a scheduled outage.** `establish_first_last_good` writes an empty
	// document before the first apply so that `--confirm-within` works from
	// the very beginning, where "revert to nothing" really is the exact undo
	// of a first apply -- an operator asked, is watching, and can confirm.
	//
	// Nobody asked for this one, and the empty last-good outlives the moment
	// it was written for: `converge` only replaces it when the startup apply
	// had no failure at all, so one failed action at boot leaves it in place
	// indefinitely. An operator then changing one field would arm a window
	// whose revert removes *every* address, route and backend netcfgd has
	// installed -- a blast radius with no relation to the change, on a machine
	// with nobody present. That is the disaster the startup exclusion above
	// exists to prevent, arriving one pass later by another road.
	if last_good == Document::default() {
		eprintln!(
			"netcfgd: not arming a window for this change: the last-good \
			 configuration is empty, so reverting would undo everything \
			 netcfgd has done rather than this change"
		);
		return None;
	}
	Some((seconds, last_good))
}

fn reconcile_drift(
	state: &mut State,
	subscribers: &mut Vec<SyncSender<Event>>,
	config_changed: bool,
	commands: &Sender<Command>,
) {
	let wanted = state.reconciling_interfaces();
	if wanted.is_empty() {
		return;
	}
	// The cycles waiting to happen, taken before the plan and cleared only
	// after it ran: a plan that could not be applied leaves the note in place
	// so the next pass tries again, rather than the machine sitting for ever
	// on a source nothing ever selected.
	let cycling = state.sims.pending();
	let full = state.plan(&PlanOptions {
		cycle: cycling.clone(),
		..PlanOptions::default()
	});
	let (restricted, dropped) = state::restrict(&full, &wanted);
	if restricted.actions.is_empty() {
		return;
	}
	for note in dropped {
		eprintln!("netcfgd: not reconciled in isolation: {note}");
	}

	// **After the early returns, not before them.** Computing it earlier read
	// as defensive -- take the decision before anything moves -- and neither
	// reason held: `may_arm`'s already-armed branch is unreachable here because
	// `defers_to_a_window` has already sent the loop away when a window is
	// open, and nothing between here and the arm touches `last-good.json`. What
	// it did do is announce a refusal to arm on a pass that then applied
	// nothing at all, which is a message about a change that never happened.
	let arming = window_for_a_config_change(state, config_changed);

	let Ok(mut executor) = state.executor() else {
		eprintln!("netcfgd: cannot open a netlink socket to reconcile drift");
		return;
	};
	let journal = netcfgd_apply::apply(&restricted, &mut executor);
	state.sims.cycled(&cycling, &journal);
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));
	let _ = run_state::write_journal(&state.paths.run, &journal);
	state.reobserve();

	// Armed after the apply, like the request path, and armed even when the
	// apply failed part-way: a half-applied change is exactly what a window is
	// for, and refusing to arm one there would withhold the safety net from
	// the case that needs it most.
	if let Some((seconds, last_good)) = arming {
		if let Some(desired) = state.desired.clone() {
			state.armed = Some(confirm::undo_from(&restricted, &journal, &desired));
		}
		let event = confirm::arm(state, seconds, &last_good);
		// Without this the window never closes. `spawn_expiry_timer` is the
		// only producer of `ConfirmExpired`, and the tick does not sweep for
		// an expired window -- so an unarmed timer would leave the change
		// standing until the next daemon start noticed the window and
		// reverted it, which is the opposite of a safety net.
		spawn_expiry_timer(commands, seconds);
		server::broadcast(subscribers, &event);
	}

	// **A failed reconcile said nothing at all.** `converge` prints the action
	// that failed and the reconcile path did not, so the only trace of a
	// broken pass was a count in an event nobody is subscribed to and a file
	// under /run that has to be gone looking for.
	//
	// Measured, and it is not a hypothetical quiet: a read-only `ncfg status`
	// rewrites the hook scripts under /run, the executor correctly refuses a
	// hook whose hash has changed since the plan was made, `pre_up` fails, and
	// `link.up` and `addr.add` are skipped behind it -- leaving the interface
	// down with no address, while the daemon log held two startup lines and
	// nothing else. `plan.last.json` named the cause exactly. The daemon knew
	// and did not say.
	if let Some(failure) = journal.failure() {
		eprintln!(
			"netcfgd: reconcile stopped at {}: {}; {} done, {} not attempted",
			failure.op,
			failure.error.as_deref().unwrap_or("no detail"),
			journal.done(),
			journal.skipped()
		);
	}

	server::broadcast(
		subscribers,
		&Event::Observed {
			summary: format!("reconciled {} actions", journal.done()),
		},
	);
}

/// Everything an `apply` request does.
///
/// Split out of [`answer`] to keep that a dispatcher rather than a place where
/// one arm is longer than the other twelve together.
fn apply_request(
	state: &mut State,
	window: Option<u32>,
	allow_disruption: &[String],
	strand_credentials: &[String],
	restart_wedged: &[String],
	subscribers: &mut Vec<SyncSender<Event>>,
	timers: Option<&Sender<Command>>,
) -> Response {
	if let Some(diagnostics) = &state.diagnostics {
		return Response::error(diagnostics.clone());
	}
	// **`--confirm-within 0` is how an operator says *no* window on a machine
	// whose config sets one, and it is the only way to say it (0094).** The
	// planner is still told the zero a few lines below -- that is what
	// suppresses the document's default -- but nothing here may arm from it.
	// A zero-second window arms and expires, which is the apply undoing itself
	// a moment after it succeeded.
	//
	// Measured before this guard existed: `ncfg apply --confirm-within 0` on a
	// machine setting `confirm = 60` printed "confirm window open for 0s", and
	// four seconds later the interface had no address at all -- the flag
	// documented as the way to decline a window was the most destructive thing
	// in the command. `may_arm` is asked about `arming` too, so declining a
	// window is not refused for a window somebody else has open.
	let arming = window.filter(|seconds| *seconds > 0);
	// Checked before anything is applied, so a refusal leaves the
	// machine untouched rather than changed-but-unprotected.
	let last_good = match &arming {
		Some(_) => match confirm::may_arm(state) {
			Ok(document) => Some(document),
			Err(error) => return Response::error(error.message()),
		},
		None => None,
	};
	// Taken before the plan and cleared only after it ran, which is the order
	// `reconcile_drift` uses: a plan that could not be applied leaves the note
	// in place so the next attempt still performs the cycle.
	let cycling = state.sims.pending();
	let options = PlanOptions {
		confirm_window: window,
		revert_to: last_good.as_ref().map(netcfgd_host::document_hash),
		allow_disruption: allow_disruption.to_vec(),
		strand_credentials: strand_credentials.to_vec(),
		// 0141: a wedged backend is a loud failure by default. Only a client
		// that named an interface gets it killed and started again -- the
		// reconcile loop passes nothing here, which is what makes the default
		// hold on a machine nobody is watching.
		restart_wedged: restart_wedged.to_vec(),
		// A deliberate apply performs a SIM cycle that is waiting, the same as
		// the reconcile loop would: the operator asked netcfgd to make the
		// machine match, and a modem sitting on a source nothing selected is
		// one of the ways it does not.
		cycle: cycling.clone(),
	};
	let mut executor = match state.executor() {
		Ok(executor) => executor,
		Err(message) => return Response::error(message),
	};
	let (plan, journal) = state.apply(&options, &mut executor);
	// **Cleared here as well as in the reconcile loop, and it was not.** The
	// note that a modem is waiting for its link to be cycled is taken before
	// the plan and forgotten after the plan ran; `reconcile_drift` did both
	// and this path did only the first. So an `ncfg apply` performed the cycle
	// and left the note, and every apply after it cycled the link again --
	// taking the link down and up on a machine that had already switched SIM.
	//
	// The reconcile loop would eventually have cleared it, but only on a pass
	// that found something to reconcile: it returns before taking the notes
	// when nothing is drifting, which on a converged machine is every pass.
	state.sims.cycled(&cycling, &journal);
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));
	state.reobserve();

	match (&arming, last_good) {
		(Some(seconds), Some(document)) => {
			// What to undo if nobody confirms, taken from the plan that just
			// ran and the journal saying which of it reached the kernel. Set
			// before the window is armed, so there is no instant in which a
			// window is open with nothing recorded against it.
			if let Some(desired) = state.desired.clone() {
				state.armed = Some(confirm::undo_from(&plan, &journal, &desired));
			}
			let event = confirm::arm(state, *seconds, &document);
			if let Some(timer) = timers {
				spawn_expiry_timer(timer, *seconds);
			}
			server::broadcast(subscribers, &event);
		}
		// No window: this configuration is the one to fall back to, and
		// there is nothing outstanding to undo.
		//
		// **Unless a window is open, in which case both of those are somebody
		// else's.** A plain `ncfg apply` while a window is outstanding used to
		// clear the inverses recorded against it and overwrite the last-good
		// with the very configuration the window exists to undo -- so the
		// expiry found nothing to take back, re-planned to what was already in
		// effect, and reported a revert that had reverted nothing. The safety
		// net disappeared silently, and `state.rejected` was then set to the
		// configuration on disk, refusing every later reload of it.
		//
		// Rare before, because a window only existed if somebody had asked for
		// one; routine now that a config change arms its own. Leaving the
		// record alone is enough: the window resolves on its own terms, and
		// this apply is inside it rather than instead of it.
		_ => {
			if netcfgd_host::confirm::read_window(&state.paths.run).is_some() {
				eprintln!(
					"netcfgd: applied inside an open confirm window; the window \
					 still reverts to what it was armed against"
				);
			} else {
				state.armed = None;
				if let Some(desired) = &state.desired {
					let _ = netcfgd_host::confirm::write_last_good(&state.paths.run, desired);
				}
			}
		}
	}
	Response::Journal(Box::new(journal))
}

fn answer(
	state: &mut State,
	request: &Request,
	subscribers: &mut Vec<SyncSender<Event>>,
	timers: Option<&Sender<Command>>,
	// What the connection asking may do. Computed by the caller, which is where
	// the peer credentials are: passing them further in would put the socket's
	// business into a dispatcher that is otherwise about state.
	granted: &[netcfgd_model::Tier],
) -> Response {
	match request {
		Request::Hello => Response::Hello {
			protocol: netcfgd_proto::PROTOCOL_VERSION,
			schema: netcfgd_model::SCHEMA_VERSION,
			tiers: granted.to_vec(),
		},
		Request::Status => Response::Status(Box::new(state.observed.clone())),
		Request::Show => match &state.desired {
			Some(document) => Response::Document(Box::new(document.clone())),
			None => Response::error(
				state
					.diagnostics
					.clone()
					.unwrap_or_else(|| "no configuration".to_owned()),
			),
		},
		Request::Plan => plan_response(state),
		Request::Apply {
			confirm: window,
			allow_disruption,
			strand_credentials,
			restart_wedged,
		} => apply_request(
			state,
			*window,
			allow_disruption,
			strand_credentials,
			restart_wedged,
			subscribers,
			timers,
		),
		Request::Reload => {
			// The answer comes from the event rather than from
			// `state.diagnostics`; see `state::reload_answer` for what the two
			// disagreed about and which cases got the wrong answer.
			let event = state.reload();
			let response = state::reload_answer(&event);
			server::broadcast(subscribers, &event);
			response
		}
		// Commit-confirm is the next piece of M2; refusing by name beats
		// accepting and doing nothing, which would let a client believe it had
		// a safety net.
		Request::Confirm => {
			let (response, event) = confirm::confirm_window(state);
			if let Some(event) = event {
				server::broadcast(subscribers, &event);
			}
			response
		}
		Request::Revert => {
			let (response, events) = confirm::revert(state, "asked to");
			for event in events {
				server::broadcast(subscribers, &event);
			}
			response
		}
		Request::Explain { subject } => Response::Explanation(Box::new(netcfgd_host::explain(
			subject,
			state.desired.as_ref(),
			&state.observed,
			&run_state::read_provenance(&state.paths.run),
		))),
		// Handled entirely on the connection thread.
		Request::Monitor => Response::Ok,

		// Wireless. These reach the supplicant rather than the kernel, and
		// none of them can create a network -- the `wifi` tier joins what the
		// configuration already describes and nothing else (decision 0013).
		// The wireless verbs, split out because `answer` was over its line
		// budget and these are the group that reads as one subject.
		Request::WifiScan { .. }
		| Request::WifiStatus { .. }
		| Request::WifiConnect { .. }
		| Request::WifiDisconnect { .. }
		| Request::WifiAdd { .. }
		| Request::ApStations { .. }
		| Request::Radios
		| Request::RadioSet { .. } => answer_wifi(state, request),
		Request::ConfigPut {
			name,
			text,
			replace,
		} => put_config_request(state, name, text, *replace),
		Request::SecretPut {
			name,
			value,
			replace,
		} => put_secret_request(state, name, value, *replace),
		Request::ProfileList => list_profiles_request(state),
		Request::ProfileSet { name } => set_profile_request(state, name.as_deref()),
		Request::ProfileSave { name, replace } => save_profile_request(state, name, *replace),
		Request::SecretList => list_secrets_request(state),
		Request::ModemList => Response::Modems {
			modems: state.sims.status(state.desired.as_ref()),
		},
		Request::ProbeList => Response::Probes {
			probes: netcfgd_host::config::list_probes(&state.paths.config, &state.paths.factory),
		},
		Request::ProbePut {
			name,
			text,
			replace,
		} => put_probe_request(state, name, text, *replace),
		Request::ConfigDelete { name } => delete_config_request(state, name),
		Request::SecretDelete { name } => {
			match netcfgd_host::config::remove_secret(&state.paths.config, name) {
				Ok(()) => Response::Ok,
				Err(message) => Response::error(message),
			}
		}
	}
}

/// The wireless verbs.
///
/// Split from [`answer`] for its line budget, and they are the right group to
/// take: every one of them is about a radio, and none of them touches the
/// parts of `answer` that are about documents and plans.
fn answer_wifi(state: &mut State, request: &Request) -> Response {
	match request {
		Request::Radios => wifi::radios(state.desired.as_ref(), &state.observed),
		Request::RadioSet {
			interface,
			activate,
		} => {
			// Cloned because the write borrows `state` mutably while the check
			// reads the observation. A radio list is a handful of names.
			let observed = state.observed.clone();
			wifi::set_radio(state, &observed, interface, *activate)
		}
		Request::WifiScan { interface } => wifi::scan(state.desired.as_ref(), interface),
		Request::ApStations { interface } => {
			wifi::ap_stations(state.desired.as_ref(), &state.paths.run, interface)
		}
		Request::WifiStatus { interface } => wifi::status(state.desired.as_ref(), interface),
		Request::WifiConnect { interface, network } => wifi::connect_to(
			state.desired.as_ref(),
			&state.paths.config.join("secrets"),
			interface,
			network,
		),
		Request::WifiDisconnect { interface } => {
			wifi::disconnect(state.desired.as_ref(), interface)
		}
		Request::WifiAdd {
			ssid,
			id,
			passphrase,
			proto,
			hidden,
			metric,
			eap,
		} => add_network_request(
			state,
			&wifi::Wanted {
				ssid_hex: ssid,
				id: id.as_deref(),
				passphrase: passphrase.as_deref(),
				proto: proto.as_deref(),
				hidden: *hidden,
				metric: *metric,
				eap: eap.as_deref(),
			},
		),
		// Unreachable: the caller matches exactly the variants above. A
		// panic here would be a dispatcher bug rather than anything a client
		// can cause, so it says so rather than inventing an error a caller
		// would try to act on.
		other => unreachable!("answer_wifi was given {other:?}"),
	}
}

/// Store a credential a client sent.
///
/// **No reload, unlike its neighbour.** A secret is read when a backend needs
/// it rather than compiled into the document, so nothing about the desired
/// state has changed and recompiling would be work that looks like care.
///
/// Nothing is reported back but success: not the path, not the length, not
/// whether it replaced anything. `netcfgd-secret` keeps that rule everywhere
/// and a socket is not the place to break it.
/// Take a drop-in away, and read the configuration back.
///
/// A function rather than an arm for the reason its siblings are: `answer` has
/// a line limit, and every other writer here is already one of these.
fn delete_config_request(state: &mut State, name: &str) -> Response {
	// Taking a drop-in away is a settings change like any other.
	let folded = match take_off_profile(state, name) {
		Ok(folded) => folded,
		Err(message) => return Response::error(message),
	};
	match refold_on_failure(
		state,
		folded.as_deref(),
		netcfgd_host::config::remove_drop_in(&state.paths.config, &state.paths.factory, name)
			.map(|_| ()),
	) {
		Ok(()) => {
			state.reload();
			Response::Ok
		}
		Err(message) => Response::error(message),
	}
}

/// Put a link-detection script on disk.
///
/// **No reload**, unlike `put_config_request`. A script is not configuration:
/// nothing in the document changed, and the `probe` block naming it is a
/// different request. Reloading here would re-read a document that says the
/// same thing it did a moment ago.
///
/// The privilege check is not here, for the reason `put_config_request` gives:
/// `authorize::check_content` refuses this from anyone but local root before
/// the dispatcher sees it, and an authorization question answered in two
/// places is one where the two come to disagree.
fn put_probe_request(state: &State, name: &str, text: &str, replace: bool) -> Response {
	match netcfgd_host::config::install_probe(&state.paths.config, name, text, replace) {
		Ok(_) => Response::Ok,
		Err(message) => Response::error(message),
	}
}

fn put_secret_request(state: &State, name: &str, value: &str, replace: bool) -> Response {
	match netcfgd_host::config::install_secret(&state.paths.config, name, value, replace) {
		Ok(_) => Response::Ok,
		Err(message) => Response::error(message),
	}
}

/// Put a client's configuration on disk, then read the configuration back.
///
/// The reload is here for `add_network_request`'s reason: inotify notices the
/// file on its own, but a client that wrote configuration and was told by the
/// very next request that the machine knows nothing about it would be right to
/// call that a bug.
///
/// **What is not here is the privilege check**, and that is deliberate.
/// Whether this caller may send this content is `authorize::check_content`'s,
/// asked before the request reaches the dispatcher, because it is an
/// authorization question and answering it in two places is how the two come
/// to disagree. By the time execution is here the answer is yes.
/// A person changed a setting, so the machine comes off its profile.
///
/// [0151]'s directive: a settings write by a person puts the machine on "none
/// chosen", and the profile's drop-ins are folded into `conf.d` in the same
/// step so that what is running does not move. A write netcfgd makes for
/// itself does not come through here, which is what keeps the other half of
/// the directive true -- the selection never moves on its own.
///
/// `ncfg profile set` and `unset` are exempt by name: they write the selection
/// itself, and taking the machine off a profile in order to put it on one
/// would be a loop.
///
/// [0151]: ../../../doc/decision/0151-a-profile-is-a-directory-and-it-is-switched-by-hand.md
/// Put the profile back when the settings write it was made for did not
/// happen. A refused drop-in changed no setting, so it must not have moved the
/// selection either.
fn refold_on_failure<T>(
	state: &State,
	folded: Option<&str>,
	outcome: Result<T, String>,
) -> Result<T, String> {
	let (Err(error), Some(profile)) = (&outcome, folded) else {
		return outcome;
	};
	if let Err(undo) = netcfgd_host::config::restore_profile(&state.paths.config, profile) {
		return Err(format!(
			"{error}\n(and the `{profile}` profile could not be put back: {undo})"
		));
	}
	outcome
}

fn take_off_profile(state: &State, name: &str) -> Result<Option<String>, String> {
	if name == netcfgd_host::config::PROFILE_DROP_IN {
		return Ok(None);
	}
	match netcfgd_host::config::adopt_profile(&state.paths.config, &state.paths.factory) {
		Ok(None) => Ok(None),
		Ok(Some(profile)) => {
			eprintln!(
				"netcfgd: a setting was changed by hand, so the `{profile}` \
				 profile was folded into conf.d and no profile is chosen now"
			);
			Ok(Some(profile))
		}
		Err(error) => Err(error.to_string()),
	}
}

/// The profiles, and which one is in effect.
fn list_profiles_request(state: &State) -> Response {
	Response::Profiles {
		profiles: netcfgd_host::config::list_profiles(&state.paths.config, &state.paths.factory),
		// From the document rather than from the file, so what is reported is
		// what the loader actually chose -- a `90-profile` some other file
		// contradicts is refused by the loader, and this would otherwise
		// announce a profile that is not in effect.
		chosen: state
			.desired
			.as_ref()
			.and_then(|document| document.globals.profile.clone()),
	}
}

/// Choose a profile, or stop using one.
///
/// The write goes through the same drop-in machinery every other configuration
/// write uses, under the name netcfgd owns -- which is why a client never
/// spells that name and cannot go stale when it changes.
///
/// **A name with no directory is refused rather than written.** Writing it
/// would leave a machine whose configuration names a profile that does not
/// exist, and the fault would surface later as a profile that changes nothing,
/// which reads as netcfgd ignoring the operator. The check belongs here
/// because this is the machine that would have to read the directory: a
/// client checking its own disk would be answering about the wrong host.
/// The credentials this machine holds, by name and never by value.
///
/// A function rather than an arm for the reason its siblings are: `answer` has
/// a line limit and every other reader here is already one of these.
///
/// The document is the one the daemon compiled, so a name referenced by a
/// configuration that does not currently compile is not reported as used --
/// which is right, because it is not in force.
fn list_secrets_request(state: &State) -> Response {
	Response::Secrets {
		secrets: netcfgd_host::secrets::list(&state.paths.config, state.desired.as_ref()),
	}
}

/// Write what the machine is running into a profile, and select it.
///
/// A function rather than an arm for the reason its siblings are: `answer` has
/// a line limit and every other writer here is already one of these.
///
/// The document it saves is the one the daemon compiled, not one re-read from
/// disk: that is what "what this machine is running" means, and re-reading
/// would race an edit somebody made in the last second.
fn save_profile_request(state: &mut State, name: &str, replace: bool) -> Response {
	let Some(running) = state.desired.clone() else {
		return Response::error(
			"there is no compiled configuration to save; fix the configuration first",
		);
	};
	match netcfgd_host::config::save_profile(
		&state.paths.config,
		&state.paths.factory,
		name,
		replace,
		&running,
		"asking again with replace",
	) {
		Ok(_) => {
			// The selection moved, so what the daemon holds is now stale --
			// and `save_profile` has already proved the result compiles back
			// to what was running.
			state.reload();
			Response::Ok
		}
		Err(message) => Response::error(message),
	}
}

fn set_profile_request(state: &mut State, name: Option<&str>) -> Response {
	let drop_in = netcfgd_host::config::PROFILE_DROP_IN;

	let Some(name) = name else {
		return match netcfgd_host::config::remove_drop_in(
			&state.paths.config,
			&state.paths.factory,
			drop_in,
		) {
			Ok(_) => {
				state.reload();
				Response::Ok
			}
			Err(message) => Response::error(message),
		};
	};

	let known = netcfgd_host::config::list_profiles(&state.paths.config, &state.paths.factory);
	if !known.iter().any(|entry| entry.name == name) {
		let names: Vec<&str> = known.iter().map(|entry| entry.name.as_str()).collect();
		return Response::error(if names.is_empty() {
			format!("no profile called `{name}`, and this machine has none")
		} else {
			format!(
				"no profile called `{name}`; this machine has {}",
				names.join(", ")
			)
		});
	}

	// Replacing, because switching twice must edit one file rather than
	// leaving the previous choice behind for the loader to argue with.
	let text = format!("global {{\n\tprofile = \"{name}\"\n}}\n");
	match netcfgd_host::config::install_drop_in(
		&state.paths.config,
		&state.paths.factory,
		drop_in,
		&text,
		true,
	) {
		Ok(_) => {
			state.reload();
			Response::Ok
		}
		Err(message) => Response::error(message),
	}
}

fn put_config_request(state: &mut State, name: &str, text: &str, replace: bool) -> Response {
	let folded = match take_off_profile(state, name) {
		Ok(folded) => folded,
		Err(message) => return Response::error(message),
	};
	match refold_on_failure(
		state,
		folded.as_deref(),
		netcfgd_host::config::install_drop_in(
			&state.paths.config,
			&state.paths.factory,
			name,
			text,
			replace,
		),
	) {
		Ok(_) => {
			state.reload();
			// `Ok` and not a path. The caller named the drop-in and netcfgd
			// chose where it went, which is 0127's point -- handing the path
			// back would invite a client to keep it, and the next thing a
			// client keeps a path for is writing to it.
			Response::Ok
		}
		Err(message) => Response::error(message),
	}
}

/// Write a network into the configuration, then read the configuration back.
///
/// Separate from the dispatcher because of the reload, which is the part worth
/// explaining: inotify would notice the new file on its own, but a client that
/// added a network and was told by the very next request that there is no such
/// network would be right to call that a bug. So the document is refreshed
/// before answering.
fn add_network_request(state: &mut State, wanted: &wifi::Wanted<'_>) -> Response {
	let answer = wifi::configure_network(
		state.desired.as_ref(),
		&state.paths.config,
		&state.paths.factory,
		wanted,
	);
	if matches!(answer, Response::Ok) {
		state.reload();
	}
	answer
}

/// Wake the loop when a window closes.
///
/// A dedicated one-shot thread rather than the 5-second tick, because a
/// safety mechanism that fires up to five seconds late is one whose window is
/// not the length it says. If the window is confirmed first the thread still
/// fires and the loop finds no window to close, which costs nothing.
fn spawn_expiry_timer(commands: &Sender<Command>, seconds: u32) {
	let commands = commands.clone();
	let _ = std::thread::Builder::new()
		.name("confirm".to_owned())
		.spawn(move || {
			std::thread::sleep(std::time::Duration::from_secs(u64::from(seconds)));
			let _ = commands.send(Command::ConfirmExpired);
		});
}

/// Watch every radio's control socket for the one event an observation cannot
/// catch: a station moving to a different access point.
///
/// **Push, not poll**, and that is the whole reason this thread exists. netcfgd
/// asks a station nothing during an observation, so the alternative was a
/// `STATUS` round trip per radio on every netlink event -- work added to the
/// reconcile loop, needing its own deadline for the reason 0085's does, and
/// still able to miss a move that happened and reversed between two
/// observations. `wpa_supplicant` will simply tell us.
///
/// One thread for all radios rather than one each: they are polled with a short
/// timeout in turn, so a machine with two radios costs one thread and not two,
/// and a supplicant that goes away is reconnected on the next pass rather than
/// taking a thread with it.
///
/// A **roam** is a `CONNECTED` naming a different access point than the last one
/// this interface reported. The first one after netcfgd started is an
/// association rather than a roam -- there is nothing to have moved from, and
/// firing then would run the hook on every boot.
fn spawn_roam_watcher(commands: &Sender<Command>, ctrl_dir: PathBuf) {
	let commands = commands.clone();
	let _ = std::thread::Builder::new()
		.name("roam".to_owned())
		.spawn(move || {
			// interface -> (attached client, the access point it last named).
			let mut watching: Vec<(String, netcfgd_supplicant::Client, Option<String>)> =
				Vec::new();

			loop {
				// Anything with a control socket that is not being watched yet.
				// Read every pass, because a radio appears when netcfgd starts
				// a supplicant for it, which is after this thread exists.
				if let Ok(entries) = std::fs::read_dir(&ctrl_dir) {
					for entry in entries.flatten() {
						let Some(interface) = entry.file_name().to_str().map(ToOwned::to_owned)
						else {
							continue;
						};
						// Not every entry here is an interface. A datagram client
						// binds its own reply socket in this directory, so the
						// daemon's own in-flight connections appear beside the
						// supplicants -- and connecting to one waits out the
						// full timeout against a process that will never answer,
						// while delivering the `PING` into that client's reply
						// queue where it can be read as the answer to a command
						// it actually sent. Decision 0112.
						if netcfgd_supplicant::is_reply_socket(&interface) {
							continue;
						}
						if watching.iter().any(|(known, _, _)| *known == interface) {
							continue;
						}
						// Impatiently, for the reason every other control-socket
						// deadline in this tree exists: what is left after the
						// filter above is a real supplicant, and a wedged one
						// would otherwise cost this thread ten seconds a pass and
						// starve the radios that are working of their events.
						let Ok(client) = netcfgd_supplicant::Client::connect_within(
							&ctrl_dir,
							&interface,
							netcfgd_supplicant::IMPATIENT,
						) else {
							continue;
						};
						// Without ATTACH this connection gets replies and no
						// events, and the loop below would be a silent
						// no-op forever.
						if client.attach().is_ok() {
							watching.push((interface, client, None));
						}
					}
				}

				if watching.is_empty() {
					// Nothing to watch. Sleeping rather than spinning on an
					// empty directory, which is every machine with no radio.
					std::thread::sleep(std::time::Duration::from_millis(1000));
					continue;
				}

				let mut lost: Vec<String> = Vec::new();
				for (interface, client, last) in &mut watching {
					match client.next_event(std::time::Duration::from_millis(250)) {
						Ok(Some(event)) => {
							let Some(bssid) = event.connected_bssid() else {
								continue;
							};
							let moved = last.as_deref().is_some_and(|was| was != bssid);
							*last = Some(bssid.to_owned());
							if moved
								&& commands
									.send(Command::Roamed {
										interface: interface.clone(),
										bssid: bssid.to_owned(),
									})
									.is_err()
							{
								return;
							}
						}
						Ok(None) => {}
						// The supplicant went away. Dropped and picked up again
						// on a later pass if it comes back, which is what an
						// `ncfg apply` restarting one looks like from here.
						Err(_) => lost.push(interface.clone()),
					}
				}
				watching.retain(|(interface, _, _)| !lost.contains(interface));
			}
		});
}

fn spawn_kernel_watcher(commands: &Sender<Command>) {
	let commands = commands.clone();
	let _ = std::thread::Builder::new()
		.name("netlink".to_owned())
		.spawn(move || {
			let Ok(socket) = Netlink::open_with_groups(groups::OBSERVED) else {
				eprintln!("netcfgd: cannot watch netlink; kernel changes will be missed");
				return;
			};
			// A timeout rather than an indefinite block, so the loop keeps
			// ticking even on a system where nothing ever changes.
			let _ = socket.set_timeout(i64::from(TICK_MS / 1000));
			loop {
				match socket.wait_for_change() {
					Ok(true) => {
						if commands.send(Command::KernelChanged).is_err() {
							return;
						}
					}
					Ok(false) => {
						if commands.send(Command::Tick).is_err() {
							return;
						}
					}
					Err(error) => {
						eprintln!("netcfgd: netlink watch failed: {error}");
						return;
					}
				}
			}
		});
}

fn spawn_config_watcher(
	commands: &Sender<Command>,
	paths: &Paths,
	force_polling: bool,
) -> &'static str {
	// The writable layer only. The factory layer is part of the image -- on
	// the read-only root this exists for, it cannot change while the daemon is
	// running, and watching it would cost two more inotify descriptors on the
	// device with the fewest to spare. A factory directory that does change is
	// a development setup, and a `reload` picks it up.
	let directories = vec![paths.config.clone(), paths.config.join("conf.d")];
	let mut watcher = if force_polling {
		Watcher::polling(&directories)
	} else {
		Watcher::new(&directories)
	};
	let mechanism = watcher.mechanism().name();

	let commands = commands.clone();
	let _ = std::thread::Builder::new()
		.name("config".to_owned())
		.spawn(move || loop {
			match watcher.wait(TICK_MS) {
				Ok(true) => {
					if commands.send(Command::ConfigChanged).is_err() {
						return;
					}
				}
				Ok(false) => {}
				Err(error) => {
					eprintln!("netcfgd: config watch failed: {error}");
					return;
				}
			}
		});
	mechanism
}

#[cfg(test)]
mod tests {
	use super::*;

	fn apply(confirm: Option<u32>) -> Request {
		Request::Apply {
			confirm,
			allow_disruption: Vec::new(),
			strand_credentials: Vec::new(),
			restart_wedged: Vec::new(),
		}
	}

	/// A pending apply that asks for a window defers the watcher, and one that
	/// does not ask for anything does not.
	///
	/// The second half is the control. Without it this passes for a predicate
	/// that returns true unconditionally, which is what the first version of
	/// the live check did before a no-window run was put beside it.
	#[test]
	fn only_a_requested_window_defers_the_watcher() {
		assert!(a_window_is_requested([apply(Some(60))].iter()));
		assert!(!a_window_is_requested([apply(None)].iter()));

		// `--confirm-within 0` is "apply and do not arm anything", so it is
		// not a window and must not hold the watcher off.
		assert!(!a_window_is_requested([apply(Some(0))].iter()));

		// One among several is enough: the watcher must not reconcile just
		// because something unrelated is also queued.
		assert!(a_window_is_requested(
			[Request::Status, apply(Some(30)), apply(None)].iter()
		));
		assert!(!a_window_is_requested(
			[Request::Status, apply(None)].iter()
		));
	}
}
