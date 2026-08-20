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
mod state;
mod wifi;

use netcfgd_host::state as run_state;
use netcfgd_model::HookPhase;
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
					origin,
					reply,
				} => requests.push((request, peer, origin, reply)),
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

		// Whatever is due, and only a *changed* verdict counts as movement.
		// A probe that has agreed with itself for an hour should cost the
		// program it runs and nothing else -- no re-observation, no plan, no
		// event. Run before the block below so a verdict that did change goes
		// round the same path a carrier change does (0119).
		let probe_changed = state.probes.run_due(state.desired.as_ref());

		if kernel_changed || config_changed || probe_changed {
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
			// After the drift hooks and before the reconcile, for the same
			// reason: a script sees the machine as the change left it.
			remember_told(&state, HookPhase::Portal, &run_portal_checks(&state));
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
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));
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
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));
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
		// The wireless verbs, split out because `answer` was over its line
		// budget and these are the group that reads as one subject.
		Request::WifiScan { .. }
		| Request::WifiStatus { .. }
		| Request::WifiConnect { .. }
		| Request::WifiDisconnect { .. }
		| Request::WifiAdd { .. }
		| Request::ApStations { .. } => answer_wifi(state, request),
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
		Request::ConfigDelete { name } => {
			match netcfgd_host::config::remove_drop_in(
				&state.paths.config,
				&state.paths.factory,
				name,
			) {
				Ok(()) => {
					state.reload();
					Response::Ok
				}
				Err(message) => Response::error(message),
			}
		}
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
			priority,
		} => add_network_request(
			state,
			&wifi::Wanted {
				ssid_hex: ssid,
				id: id.as_deref(),
				passphrase: passphrase.as_deref(),
				proto: proto.as_deref(),
				hidden: *hidden,
				priority: *priority,
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
fn put_config_request(state: &mut State, name: &str, text: &str, replace: bool) -> Response {
	match netcfgd_host::config::install_drop_in(
		&state.paths.config,
		&state.paths.factory,
		name,
		text,
		replace,
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
