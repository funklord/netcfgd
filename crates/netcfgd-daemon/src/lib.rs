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
mod server;
mod state;
mod wifi;

use netcfgd_host::state as run_state;
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
	server::serve(&socket_path, &control, commands.clone())
		.map_err(|error| format!("could not bind {}: {error}", socket_path.display()))?;
	spawn_kernel_watcher(&commands);
	spawn_roam_watcher(&commands, supplicant_ctrl_dir());
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

	if options.apply_on_start && !reverted_at_startup {
		// A network configuration daemon that starts and configures nothing is
		// not doing its job; design section 4.4 makes oneshot the alternative
		// rather than the default. `--no-apply-on-start` exists for anyone who
		// wants the daemon to observe first and be told when to act.
		converge(&mut state, &mut Vec::new());
	}

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
		let mut requests = Vec::new();
		let mut roamed: Vec<(String, String)> = Vec::new();

		for command in std::iter::once(command).chain(server::drain(&incoming)) {
			match command {
				Command::KernelChanged => kernel_changed = true,
				Command::ConfigChanged => config_changed = true,
				Command::ConfirmExpired => confirm_expired = true,
				Command::Tick => {}
				// Not collapsed the way a netlink burst is: two roams are two
				// events, and a station that moved twice moved twice.
				Command::Roamed { interface, bssid } => roamed.push((interface, bssid)),
				Command::Subscribe { events } => subscribers.push(events),
				Command::Request {
					request,
					peer,
					reply,
				} => requests.push((request, peer, reply)),
			}
		}

		if confirm_expired {
			let (_, events) = confirm::revert(&mut state, "the window closed unconfirmed");
			for event in events {
				server::broadcast(&mut subscribers, &event);
			}
		}

		// Before the reobserve below, so a `roam` script sees the machine as
		// the move left it. Nothing here re-plans: a station moving within its
		// own network changes no desired state, which is why this is a hook and
		// not drift.
		for (interface, bssid) in &roamed {
			run_roam_hooks(&state, interface, bssid);
		}

		if config_changed {
			let event = state.reload();
			server::broadcast(&mut subscribers, &event);
		}
		if kernel_changed || config_changed {
			state.reobserve();
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
			reconcile_drift(&mut state, &mut subscribers);
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
/// has happened, and docs/first-run.md says so.
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
fn converge(state: &mut State, subscribers: &mut Vec<SyncSender<Event>>) {
	let Ok(mut executor) = state.executor() else {
		eprintln!("netcfgd: cannot open a netlink socket to apply");
		return;
	};
	let (plan, journal) = state.apply(&PlanOptions::default(), &mut executor);
	let mut owned = run_state::read_owned(&state.paths.run);
	owned.absorb(&executor.effects);
	let _ = run_state::write_owned(&state.paths.run, &owned);

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

/// Answer everything that arrived this pass.
///
/// The policy is re-read per request rather than once per pass, because a
/// reload earlier in the same pass may have changed it -- and a request
/// authorised against the configuration that was replaced a moment ago is a
/// permission check on a document nobody is running.
fn serve_requests(
	state: &mut State,
	requests: Vec<(Request, netcfgd_sys::peer::Peer, SyncSender<Response>)>,
	subscribers: &mut Vec<SyncSender<Event>>,
	commands: &Sender<Command>,
) {
	for (request, peer, reply) in requests {
		let policy = state
			.desired
			.as_ref()
			.map(|document| document.globals.control.clone())
			.unwrap_or_default();
		let response = authorized(state, &policy, &peer, &request, subscribers, commands);
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
fn authorized(
	state: &mut State,
	policy: &netcfgd_model::Control,
	peer: &netcfgd_sys::peer::Peer,
	request: &Request,
	subscribers: &mut Vec<SyncSender<Event>>,
	commands: &Sender<Command>,
) -> Response {
	let granted = authorize::granted(policy, peer);
	match authorize::check(policy, peer, request) {
		Ok(()) => answer(state, request, subscribers, Some(commands), &granted),
		Err(message) => Response::error(message),
	}
}

/// Where `wpa_supplicant`'s control sockets are.
///
/// Overridable by the same variable `netcfgd-apply` reads, and for the same
/// reason: a network namespace is not a mount namespace, so a test that could
/// not move this would watch whatever the host is running.
fn supplicant_ctrl_dir() -> PathBuf {
	std::env::var_os("NCFG_WPA_CTRL_DIR").map_or_else(
		|| PathBuf::from(netcfgd_supplicant::DEFAULT_CTRL_DIR),
		PathBuf::from,
	)
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
	if told.is_empty() {
		return;
	}
	let mut owned = run_state::read_owned(&state.paths.run);
	for (interface, summary) in told {
		owned.hook_state.retain(|record| {
			&record.interface != interface || record.phase != netcfgd_model::HookPhase::Drift
		});
		owned.hook_state.push(netcfgd_model::ObservedHookState {
			interface: interface.clone(),
			phase: netcfgd_model::HookPhase::Drift,
			value: summary.clone(),
		});
	}
	let _ = run_state::write_owned(&state.paths.run, &owned);
}

/// Put back what drifted, but only on interfaces whose policy says to.
fn reconcile_drift(state: &mut State, subscribers: &mut Vec<SyncSender<Event>>) {
	let wanted = state.reconciling_interfaces();
	if wanted.is_empty() {
		return;
	}
	let full = state.plan(&PlanOptions::default());
	let (restricted, dropped) = state::restrict(&full, &wanted);
	if restricted.actions.is_empty() {
		return;
	}
	for note in dropped {
		eprintln!("netcfgd: not reconciled in isolation: {note}");
	}

	let Ok(mut executor) = state.executor() else {
		eprintln!("netcfgd: cannot open a netlink socket to reconcile drift");
		return;
	};
	let journal = netcfgd_apply::apply(&restricted, &mut executor);
	let mut owned = run_state::read_owned(&state.paths.run);
	owned.absorb(&executor.effects);
	let _ = run_state::write_owned(&state.paths.run, &owned);
	let _ = run_state::write_journal(&state.paths.run, &journal);
	state.reobserve();

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
	subscribers: &mut Vec<SyncSender<Event>>,
	timers: Option<&Sender<Command>>,
) -> Response {
	if let Some(diagnostics) = &state.diagnostics {
		return Response::error(diagnostics.clone());
	}
	// Checked before anything is applied, so a refusal leaves the
	// machine untouched rather than changed-but-unprotected.
	let last_good = match &window {
		Some(_) => match confirm::may_arm(state) {
			Ok(document) => Some(document),
			Err(error) => return Response::error(error.message()),
		},
		None => None,
	};
	let options = PlanOptions {
		confirm_window: window,
		revert_to: last_good.as_ref().map(netcfgd_host::document_hash),
		allow_disruption: allow_disruption.to_vec(),
		strand_credentials: strand_credentials.to_vec(),
	};
	let mut executor = match state.executor() {
		Ok(executor) => executor,
		Err(message) => return Response::error(message),
	};
	let (_, journal) = state.apply(&options, &mut executor);
	let mut owned = run_state::read_owned(&state.paths.run);
	owned.absorb(&executor.effects);
	let _ = run_state::write_owned(&state.paths.run, &owned);
	state.reobserve();

	match (&window, last_good) {
		(Some(seconds), Some(document)) => {
			let event = confirm::arm(state, *seconds, &document);
			if let Some(timer) = timers {
				spawn_expiry_timer(timer, *seconds);
			}
			server::broadcast(subscribers, &event);
		}
		// No window: this configuration is the one to fall back to.
		_ => {
			if let Some(desired) = &state.desired {
				let _ = netcfgd_host::confirm::write_last_good(&state.paths.run, desired);
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
		Request::Plan => {
			if let Some(diagnostics) = &state.diagnostics {
				return Response::error(diagnostics.clone());
			}
			Response::Plan(Box::new(state.plan(&PlanOptions::default())))
		}
		Request::Apply {
			confirm: window,
			allow_disruption,
			strand_credentials,
		} => apply_request(
			state,
			*window,
			allow_disruption,
			strand_credentials,
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
	}
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
						if watching.iter().any(|(known, _, _)| *known == interface) {
							continue;
						}
						let Ok(client) = netcfgd_supplicant::Client::connect(&ctrl_dir, &interface)
						else {
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
