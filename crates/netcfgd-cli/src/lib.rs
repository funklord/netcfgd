#![forbid(unsafe_code)]

//! `ncfg`: read the config, see what would change, change it.
//!
//! The argument parsing is hand-written. `clap` is excellent and would be
//! several hundred kilobytes against a 400 KB nano budget, for a command set
//! this small -- section 6's size gate is the kind of constraint that has to
//! bind on the first binary or it never binds at all.

mod client;
#[cfg(feature = "tui")]
mod tui;

use netcfgd_host::{config, hooks, state};

use netcfgd_apply::{apply, KernelExecutor};
use netcfgd_model::Observed;
use netcfgd_plan::{plan, Plan, PlanOptions};
use std::process::ExitCode;

const USAGE: &str = "\
ncfg -- netcfgd command line

usage:
  ncfg plan [options]      show what would change, and change nothing
  ncfg apply [options]     make the observed state match the config
  ncfg status [options]    show what is currently observed
  ncfg show [options]      print the compiled desired-state document
  ncfg explain SUBJECT      why is it like this? SUBJECT is one of:
                             interface NAME
                             address   IFACE CIDR
                             route     IFACE DEST
  ncfg wifi SUBCOMMAND      wireless, via netcfgd. SUBCOMMAND is one of:
                             scan       [IFACE]  list access points in range
                             status     [IFACE]  what the radio is doing
                             connect ID [IFACE]  join a configured network
                             disconnect [IFACE]  leave it, keeping the config
                           IFACE may be omitted when the config describes one
                           wireless device.
  ncfg tui [options]       full-screen client: devices, wifi, plan, events
  ncfg monitor [options]   stream events until interrupted (needs netcfgd)
  ncfg confirm [options]   keep a change made under a confirm window
  ncfg revert [options]    undo it now rather than at expiry
  ncfg reset [--yes]       discard the writable config, leaving the factory
                           defaults. Prints what it would remove unless --yes

options:
  --config-dir PATH        default /etc/netcfgd, or $NCFG_CONFIG_DIR
  --factory-dir PATH       default /usr/share/netcfgd, or $NCFG_FACTORY_DIR.
                           Read before --config-dir, which overrides it
  --yes                    for `reset`: actually remove the files
  --run-dir PATH           default /run/netcfgd, or $NCFG_RUN_DIR
  --oneshot                apply once and exit; the default, there being no
                           daemon yet
  --json                   machine-readable output
  --confirm-within SECS    apply, then revert automatically unless confirmed
                           within SECS. Needs netcfgd running, since the
                           window has to outlive this command.
  --allow-disruption IFACE consent to disrupting one guarded interface;
                           repeatable, and deliberately not a blanket --force
  -h, --help               this text

exit codes:
  0  the desired state was reached, or already held
  1  an action failed, or the config did not compile
  3  a guard refused a disruptive action; nothing else failed
";

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
			eprintln!("ncfg: {message}");
			ExitCode::from(1)
		}
	}
}

pub(crate) struct Options {
	config_dir: Option<String>,
	factory_dir: Option<String>,
	yes: bool,
	run_dir: Option<String>,
	json: bool,
	confirm: Option<u32>,
	allow_disruption: Vec<String>,
}

fn run(arguments: &[String]) -> Result<ExitCode, String> {
	let Some(command) = arguments.first() else {
		print!("{USAGE}");
		return Ok(ExitCode::from(2));
	};
	if command == "-h" || command == "--help" || command == "help" {
		print!("{USAGE}");
		return Ok(ExitCode::SUCCESS);
	}

	let options = parse_options(&arguments[1..])?;

	match command.as_str() {
		"plan" => command_plan(&options),
		"apply" => command_apply(&options),
		"status" => command_status(&options),
		"show" => command_show(&options),
		"explain" => command_explain(&arguments[1..], &options),
		"monitor" => command_monitor(&options),
		"wifi" => command_wifi(&positional(&arguments[1..]), &options),
		#[cfg(feature = "tui")]
		"tui" => tui::run(&options),
		#[cfg(not(feature = "tui"))]
		"tui" => Err("this build has no TUI; it was compiled without the `tui` feature".to_owned()),
		"reset" => command_reset(&options),
		"confirm" => command_confirm(&options, &netcfgd_proto::Request::Confirm),
		"revert" => command_confirm(&options, &netcfgd_proto::Request::Revert),
		other => Err(format!("unknown command `{other}`; try `ncfg --help`")),
	}
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
	let mut options = Options {
		config_dir: None,
		factory_dir: None,
		yes: false,
		run_dir: None,
		json: false,
		confirm: None,
		allow_disruption: Vec::new(),
	};
	let mut index = 0;
	while index < arguments.len() {
		let argument = arguments[index].as_str();
		let mut take_value = |name: &str| -> Result<String, String> {
			index += 1;
			arguments
				.get(index)
				.cloned()
				.ok_or_else(|| format!("{name} needs a value"))
		};
		match argument {
			"--config-dir" => options.config_dir = Some(take_value("--config-dir")?),
			"--factory-dir" => options.factory_dir = Some(take_value("--factory-dir")?),
			"--run-dir" => options.run_dir = Some(take_value("--run-dir")?),
			"--confirm-within" => {
				let value = take_value("--confirm-within")?;
				options.confirm = Some(value.parse().map_err(|_| {
					format!("--confirm-within wants a number of seconds, not `{value}`")
				})?);
			}
			"--allow-disruption" => options
				.allow_disruption
				.push(take_value("--allow-disruption")?),
			"--json" => options.json = true,
			"--yes" => options.yes = true,
			// There is no daemon yet, so oneshot is the only mode there is.
			// Accepting the flag now means the command line does not change
			// when the daemon lands in M2.
			"--oneshot" => {}
			// Positional arguments belong to the subcommand -- `explain` takes
			// three. An unknown *option* is still an error, because a typo in
			// a flag silently ignored is how somebody thinks they passed
			// --confirm-within and did not.
			other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
			_ => {}
		}
		index += 1;
	}
	Ok(options)
}

/// Compile the config, and write the result where `cat` can reach it.
fn compile(options: &Options) -> Result<(netcfgd_model::Document, std::path::PathBuf), String> {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let run_dir = state::resolve_dir(options.run_dir.as_deref());

	let sources = config::load_layered(
		&config::resolve_factory_dir(options.factory_dir.as_deref()),
		&config_dir,
	)
	.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;
	if sources.is_empty() {
		return Err(format!(
			"no configuration found in {}",
			config_dir.display()
		));
	}

	let mut sink = hooks::RunHooks::new(&run_dir);
	let (document, provenance) = netcfgd_compile::compile_with_provenance(&sources, &mut sink)
		.map_err(|diagnostics| diagnostics.render(&sources))?;
	// Written on every compile, not only when `explain` asks, so that what is
	// in /run describes the current configuration whichever binary last ran.
	let _ = state::write_provenance(&run_dir, &provenance);

	Ok((document, run_dir))
}

/// Compile, keeping the provenance table.
fn compile_with_provenance(
	options: &Options,
) -> Result<(netcfgd_model::Document, netcfgd_compile::Provenance), String> {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let sources = config::load_layered(
		&config::resolve_factory_dir(options.factory_dir.as_deref()),
		&config_dir,
	)
	.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;
	let mut sink = hooks::RunHooks::new(&run_dir);
	let (document, provenance) = netcfgd_compile::compile_with_provenance(&sources, &mut sink)
		.map_err(|diagnostics| diagnostics.render(&sources))?;
	let _ = state::write_provenance(&run_dir, &provenance);
	Ok((document, provenance))
}

fn observe(run_dir: &std::path::Path) -> Result<Observed, String> {
	let prior = state::prior_state(run_dir);
	netcfgd_observe::current(&prior).map_err(|error| format!("could not read the kernel: {error}"))
}

fn build_plan(
	options: &Options,
) -> Result<(Plan, netcfgd_model::Document, Observed, std::path::PathBuf), String> {
	let (document, run_dir) = compile(options)?;
	let observed = observe(&run_dir)?;
	let plan_options = PlanOptions {
		confirm_window: options.confirm,
		revert_to: None,
		allow_disruption: options.allow_disruption.clone(),
	};
	let plan = plan(&document, &observed, &plan_options);
	Ok((plan, document, observed, run_dir))
}

fn command_plan(options: &Options) -> Result<ExitCode, String> {
	let (plan, document, observed, run_dir) = build_plan(options)?;

	// Even a plan writes what it decided and what it saw. Answering "why is it
	// like this?" from a file is the product, and it should not require an
	// apply first.
	let _ = state::write_desired(&run_dir, &document);
	let _ = state::write_observed(&run_dir, &observed);

	if options.json {
		println!(
			"{}",
			serde_json::to_string_pretty(&plan).map_err(|error| error.to_string())?
		);
	} else {
		print_plan(&plan);
		warn_about_contention(&document, &observed);
	}
	Ok(ExitCode::SUCCESS)
}

/// Say so if another daemon manages an interface this plan touches.
///
/// Printed after the plan rather than as a plan warning: it is not a fact
/// about the plan, which is correct either way. It is a fact about the machine
/// that makes the plan unlikely to stick.
fn warn_about_contention(document: &netcfgd_model::Document, observed: &Observed) {
	let claimed: Vec<(String, u32)> = document
		.interfaces
		.iter()
		.filter_map(|interface| {
			observed
				.link(&interface.name)
				.map(|link| (interface.name.clone(), link.index))
		})
		.collect();

	for contender in netcfgd_host::contention::contenders(&claimed) {
		println!();
		println!(
			"warning: {}",
			netcfgd_host::contention::describe(&contender)
		);
	}
}

fn command_apply(options: &Options) -> Result<ExitCode, String> {
	if let Some(seconds) = options.confirm {
		// One implementation of the safety net, in the daemon. `ncfg` could
		// fork a watchdog instead, but two implementations of the mechanism
		// that saves a machine from a bad config is two chances to get it
		// wrong, and the one that runs would depend on how it was invoked.
		let run_dir = state::resolve_dir(options.run_dir.as_deref());
		let request = netcfgd_proto::Request::Apply {
			confirm: Some(seconds),
			allow_disruption: options.allow_disruption.clone(),
		};
		return match client::ask(&client::socket_path(&run_dir), &request)? {
			client::Answer::Journal(journal) => {
				for record in &journal.records {
					println!("{:?} {}", record.outcome, record.op);
				}
				println!(
					"confirm window open for {seconds}s -- run `ncfg confirm` to keep this, \
					 or `ncfg revert` to undo it now"
				);
				Ok(ExitCode::SUCCESS)
			}
			client::Answer::Error { message } => Err(message),
			other => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	let (plan, document, observed, run_dir) = build_plan(options)?;

	let _ = state::write_desired(&run_dir, &document);
	let _ = state::write_observed(&run_dir, &observed);

	if plan.is_empty() {
		if !options.json {
			if plan.was_refused() {
				print_refusals(&plan);
			} else {
				println!("nothing to do");
			}
		}
		if plan.was_refused() {
			return Ok(ExitCode::from(3));
		}
		return Ok(ExitCode::SUCCESS);
	}

	let mut executor = KernelExecutor::new()
		.map_err(|error| format!("could not open a netlink socket: {error}"))?
		.with_context(&run_dir, &document);
	let journal = apply(&plan, &mut executor);

	// Record what happened before reporting it. A journal that exists only in
	// the terminal is no use to whoever finds the machine afterwards.
	let mut owned = state::read_owned(&run_dir);
	owned.absorb(&executor.effects);
	if let Err(error) = state::write_owned(&run_dir, &owned) {
		eprintln!("ncfg: could not record ownership: {error}");
	}
	if let Err(error) = state::write_journal(&run_dir, &journal) {
		eprintln!("ncfg: could not write the journal: {error}");
	}

	if options.json {
		println!(
			"{}",
			serde_json::to_string_pretty(&journal).map_err(|error| error.to_string())?
		);
	} else {
		for record in &journal.records {
			let mark = match record.outcome {
				netcfgd_apply::Outcome::Done => "ok  ",
				netcfgd_apply::Outcome::Failed => "FAIL",
				netcfgd_apply::Outcome::Skipped => "skip",
			};
			println!("{mark} {}", describe(&record.op, &record.reason));
			if let Some(error) = &record.error {
				println!("     {error}");
			}
		}
	}

	if !options.json && plan.was_refused() {
		print_refusals(&plan);
	}

	if let Some(failure) = journal.failure() {
		if !options.json {
			eprintln!(
				"ncfg: stopped at action {} ({}); {} done, {} not attempted",
				failure.id,
				failure.op,
				journal.done(),
				journal.skipped()
			);
			eprintln!("ncfg: re-run `ncfg apply` to resume from current state");
		}
		return Ok(ExitCode::from(1));
	}

	// A refusal means the desired state was not reached, whether or not some
	// actions ran. Exiting zero here would tell a script convergence happened
	// when the very change it asked for is the one that did not.
	if plan.was_refused() {
		return Ok(ExitCode::from(3));
	}
	Ok(ExitCode::SUCCESS)
}

/// Answer "why is it like this?" locally.
///
/// Deliberately not routed through the daemon. Design section 4.4 makes
/// daemon-optional a property rather than a fallback, and explain is exactly
/// the command somebody reaches for when things are broken -- which is when a
/// daemon is least likely to be running.
fn command_explain(arguments: &[String], options: &Options) -> Result<ExitCode, String> {
	let positional: Vec<&String> = arguments
		.iter()
		.take_while(|argument| !argument.starts_with("--"))
		.collect();

	let subject = match positional.as_slice() {
		[kind, name] if *kind == "interface" => netcfgd_proto::Subject::Interface {
			name: (*name).clone(),
		},
		[kind, interface, address] if *kind == "address" => netcfgd_proto::Subject::Address {
			interface: (*interface).clone(),
			address: (*address).clone(),
		},
		[kind, interface, destination] if *kind == "route" => netcfgd_proto::Subject::Route {
			interface: (*interface).clone(),
			destination: (*destination).clone(),
		},
		_ => {
			return Err("explain what? try `ncfg explain interface eth0`, \
				 `ncfg explain address eth0 10.0.0.1/24`, or \
				 `ncfg explain route eth0 default`"
				.to_owned())
		}
	};

	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	// Compiled fresh rather than read from /run, so the answer describes the
	// configuration as it is now and not as it was when something last wrote
	// there. A config that no longer compiles is reported as such.
	let (desired, provenance) = match compile_with_provenance(options) {
		Ok((document, provenance)) => (Some(document), provenance),
		Err(diagnostics) => {
			eprintln!("ncfg: the configuration does not compile:\n{diagnostics}");
			(None, netcfgd_compile::Provenance::default())
		}
	};
	let observed = observe(&run_dir)?;

	let explanation = netcfgd_host::explain(&subject, desired.as_ref(), &observed, &provenance);

	if options.json {
		println!(
			"{}",
			serde_json::to_string_pretty(&explanation).map_err(|error| error.to_string())?
		);
		return Ok(ExitCode::SUCCESS);
	}

	println!("{}", explanation.subject);
	for fact in &explanation.facts {
		match &fact.source {
			Some(source) => println!("  {:<9} {}   [{}]", fact.topic, fact.detail, source),
			None => println!("  {:<9} {}", fact.topic, fact.detail),
		}
	}
	Ok(ExitCode::SUCCESS)
}

/// The arguments that are not options or option values.
///
/// `explain` does its own thing with indexes; this is for the subcommands
/// added later, which need the positional arguments without caring where the
/// flags were.
fn positional(arguments: &[String]) -> Vec<String> {
	const TAKES_VALUE: &[&str] = &[
		"--config-dir",
		"--run-dir",
		"--confirm-within",
		"--allow-disruption",
	];
	let mut out = Vec::new();
	let mut skip_next = false;
	for argument in arguments {
		if skip_next {
			skip_next = false;
			continue;
		}
		if argument.starts_with('-') {
			skip_next = TAKES_VALUE.contains(&argument.as_str());
			continue;
		}
		out.push(argument.clone());
	}
	out
}

/// Which wireless interface, when the command line did not say.
///
/// Naming an interface every time is friction on the machine this is for --
/// a laptop with one radio. Where there is exactly one wireless device in the
/// config, that is the answer; where there are several, the error lists them
/// rather than picking.
fn wireless_interface(given: Option<&String>, options: &Options) -> Result<String, String> {
	if let Some(name) = given {
		return Ok(name.clone());
	}
	let (document, _) = compile(options)?;
	let radios: Vec<&str> = document
		.devices
		.iter()
		.filter(|device| device.wifi.is_some())
		.map(|device| device.name.as_str())
		.collect();
	match radios.as_slice() {
		[only] => Ok((*only).to_owned()),
		[] => Err(
			"no wireless device in the configuration. Name the interface, or add a \
			 `device` block with a `wifi` section."
				.to_owned(),
		),
		several => Err(format!(
			"the configuration has {} wireless devices ({}); name the one you mean",
			several.len(),
			several.join(", ")
		)),
	}
}

/// The wireless subcommands, all of which are the daemon's to do.
///
/// None of these compile or apply anything. They reach the supplicant through
/// netcfgd, which is what makes them available to the `wifi` tier without
/// giving that tier the ability to change configuration (decision 0013).
fn command_wifi(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err(
			"`ncfg wifi` needs a subcommand: scan, status, connect or disconnect".to_owned(),
		);
	};
	let rest = &positional[1..];
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let socket = client::socket_path(&run_dir);

	let request = match subcommand.as_str() {
		"scan" => netcfgd_proto::Request::WifiScan {
			interface: wireless_interface(rest.first(), options)?,
		},
		"status" => netcfgd_proto::Request::WifiStatus {
			interface: wireless_interface(rest.first(), options)?,
		},
		"connect" => {
			let Some(network) = rest.first() else {
				return Err(
					"`ncfg wifi connect` needs the id of a `network` block. It joins networks \
					 the configuration already describes; adding one means editing the config."
						.to_owned(),
				);
			};
			netcfgd_proto::Request::WifiConnect {
				interface: wireless_interface(rest.get(1), options)?,
				network: network.clone(),
			}
		}
		"disconnect" => netcfgd_proto::Request::WifiDisconnect {
			interface: wireless_interface(rest.first(), options)?,
		},
		other => {
			return Err(format!(
				"unknown wifi subcommand `{other}`; try scan, status, connect or disconnect"
			))
		}
	};

	match client::ask(&socket, &request)? {
		client::Answer::WifiScan(report) => {
			render_scan(&report, options.json)?;
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::WifiStatus(state) => {
			render_wifi_status(&state, options.json)?;
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Ok => {
			println!(
				"{}",
				if matches!(request, netcfgd_proto::Request::WifiConnect { .. }) {
					"joining; `ncfg wifi status` says whether it worked"
				} else {
					"disconnected"
				}
			);
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Error { message } => Err(message),
		other => Err(format!("the daemon sent {}", other.describe())),
	}
}

fn render_scan(report: &netcfgd_proto::ScanReport, json: bool) -> Result<(), String> {
	if json {
		println!(
			"{}",
			serde_json::to_string_pretty(report).map_err(|error| error.to_string())?
		);
		return Ok(());
	}
	if report.access_points.is_empty() {
		println!("no access points in range of {}", report.interface);
		return Ok(());
	}
	let mut any_unconfigured = false;
	for entry in &report.access_points {
		// A name that is not UTF-8 is shown as hex rather than mangled, and
		// marked so nobody reads the hex as the name.
		let name = entry
			.name
			.clone()
			.unwrap_or_else(|| format!("hex:{}", entry.ssid));
		let security = if entry.secured { "secured" } else { "open" };
		let configured = if let Some(id) = &entry.configured {
			format!("  [{id}]")
		} else {
			any_unconfigured = true;
			String::new()
		};
		println!(
			"{:>4} dBm  {:>5} MHz  {security:<7}  {name}{configured}",
			entry.signal, entry.frequency
		);
	}
	if any_unconfigured {
		println!();
		println!(
			"a name in brackets is a `network` block: `ncfg wifi connect ID` joins it. \
			 The rest need config written first, which needs the admin tier."
		);
	}
	Ok(())
}

fn render_wifi_status(state: &netcfgd_proto::WifiState, json: bool) -> Result<(), String> {
	if json {
		println!(
			"{}",
			serde_json::to_string_pretty(state).map_err(|error| error.to_string())?
		);
		return Ok(());
	}
	println!("{} {}", state.interface, state.state);
	if let Some(name) = state.name.as_ref().or(state.ssid.as_ref()) {
		let bssid = state
			.bssid
			.as_ref()
			.map_or_else(String::new, |bssid| format!(" ({bssid})"));
		println!("    {name}{bssid}");
	}
	match &state.network {
		Some(id) => println!("    from the `{id}` network block"),
		None if state.ssid.is_some() => println!(
			"    not from any `network` block, which should not happen: netcfgd supplies \
			 every network the supplicant knows. Worth reporting."
		),
		None => {}
	}
	Ok(())
}

/// Stream events from the daemon until interrupted.
fn command_monitor(options: &Options) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	client::stream(&client::socket_path(&run_dir), options.json)
}

/// Confirm or revert, both of which are the daemon's to do.
fn command_confirm(
	options: &Options,
	request: &netcfgd_proto::Request,
) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let response = client::ask(&client::socket_path(&run_dir), request)?;
	match response {
		client::Answer::Ok => {
			println!(
				"{}",
				if matches!(request, netcfgd_proto::Request::Confirm) {
					"confirmed; the change stands"
				} else {
					"reverted to the last-good configuration"
				}
			);
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Error { message } => Err(message),
		other => Err(format!("the daemon sent {}", other.describe())),
	}
}

/// Discard the writable config layer, leaving whatever the image shipped.
///
/// Design section 10.4's `ncfg reset`. It is a config edit, not a runtime
/// operation, so it works on files and does not go through the daemon -- which
/// is also what gates it: the config directory is root-owned, and anybody who
/// can delete these files can edit them. The daemon notices by inotify, the
/// same way it notices any other edit.
///
/// Destructive and irreversible, so it prints what it would do and stops
/// unless `--yes` is given.
fn command_reset(options: &Options) -> Result<ExitCode, String> {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());

	// Resetting into the factory directory would delete the thing being reset
	// to. Reachable by a misconfigured unit file rather than by a typo, which
	// is exactly when nobody is watching.
	if config_dir == factory_dir {
		return Err(format!(
			"the config directory and the factory directory are both {}; reset would \
			 delete the defaults it is meant to fall back to",
			config_dir.display()
		));
	}

	let doomed = config::writable_files(&config_dir).map_err(|error| error.to_string())?;
	let factory = config::writable_files(&factory_dir).map_err(|error| error.to_string())?;

	if doomed.is_empty() {
		println!("nothing to reset: {} holds no config", config_dir.display());
		return Ok(ExitCode::SUCCESS);
	}

	for path in &doomed {
		println!(
			"{} {}",
			if options.yes {
				"removed"
			} else {
				"would remove"
			},
			path.display()
		);
	}

	// The case that surprises people: no factory layer means reset does not
	// restore anything, it empties the machine's configuration. Said before it
	// happens rather than discovered by the next apply tearing everything
	// down.
	if factory.is_empty() {
		println!();
		println!(
			"note: {} holds no factory config, so this leaves netcfgd with no \
			 configuration at all. The next apply would remove every address, route \
			 and link netcfgd installed.",
			factory_dir.display()
		);
	} else {
		println!();
		println!(
			"{} file{} remain{}, from {}",
			factory.len(),
			if factory.len() == 1 { "" } else { "s" },
			if factory.len() == 1 { "s" } else { "" },
			factory_dir.display()
		);
	}

	if !options.yes {
		println!();
		println!("nothing was removed; add --yes to do it");
		return Ok(ExitCode::SUCCESS);
	}

	for path in &doomed {
		std::fs::remove_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
	}
	Ok(ExitCode::SUCCESS)
}

fn command_status(options: &Options) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let observed = observe(&run_dir)?;
	let _ = state::write_observed(&run_dir, &observed);

	if options.json {
		println!(
			"{}",
			serde_json::to_string_pretty(&observed).map_err(|error| error.to_string())?
		);
		return Ok(ExitCode::SUCCESS);
	}

	for link in &observed.links {
		let state = if link.up { "up" } else { "down" };
		let carrier = if link.carrier { "" } else { ", no carrier" };
		println!("{} {state}{carrier} mtu {}", link.name, link.mtu);
		for address in observed.addresses_on(&link.name) {
			println!("    {} [{:?}]", address.address, address.ownership);
		}
		for vlan in observed
			.bridge_vlans
			.iter()
			.filter(|vlan| vlan.index == link.index)
		{
			let flags = match (vlan.pvid, vlan.untagged) {
				(true, true) => " pvid untagged",
				(true, false) => " pvid",
				(false, true) => " untagged",
				(false, false) => "",
			};
			println!("    vlan {}{flags}", vlan.vid);
		}
		if !link.offloads.is_empty() {
			println!("    offloads {}", link.offloads.join(" "));
		}
		if let Some(kind) = &link.qdisc {
			let shaped = link.qdisc_bandwidth_bits.map_or_else(String::new, |bits| {
				let inbound = if link.qdisc_ingress { " inbound" } else { "" };
				format!(" at {bits} bit/s{inbound}")
			});
			let ours = if observed.qdisc_applied.contains(&link.name) {
				""
			} else {
				" [kernel default or set elsewhere]"
			};
			println!("    qdisc {kind}{shaped}{ours}");
		}
		if let Some(target) = &link.ingress_redirect {
			println!("    ingress redirected to {target}");
		}
		if observed.nat.contains(&link.name) {
			println!("    masquerade");
		}
		if link.forwarding == Some(true) {
			println!("    forwarding");
		}
		for route in observed.routes_on(&link.name) {
			let via = route
				.via
				.map_or_else(String::new, |gateway| format!(" via {gateway}"));
			println!(
				"    route {}{via} [{:?}]",
				route.destination, route.ownership
			);
		}
	}
	// Printed once rather than per interface: the conflict is with a table,
	// not with a device, and repeating it under every link would make one
	// problem look like several.
	if !observed.nat_conflicts.is_empty() {
		println!();
		println!(
			"note: nftables table(s) `{}` also translate source addresses. netcfgd \
			 does not touch tables it did not create, so this is a report, not \
			 something it will resolve.",
			observed.nat_conflicts.join("`, `")
		);
	}
	if !observed.address_proto_supported {
		println!();
		println!(
			"note: no address carries a protocol tag yet, so address ownership \
			 comes from recorded state and is weaker. It strengthens once netcfgd \
			 installs its first address."
		);
	}
	Ok(ExitCode::SUCCESS)
}

fn command_show(options: &Options) -> Result<ExitCode, String> {
	let (document, run_dir) = compile(options)?;
	let _ = state::write_desired(&run_dir, &document);
	println!(
		"{}",
		document
			.to_json_canonical()
			.map_err(|error| error.to_string())?
	);
	Ok(ExitCode::SUCCESS)
}

fn print_plan(plan: &Plan) {
	if plan.is_empty() {
		println!("nothing to do");
	} else {
		for action in &plan.actions {
			println!(
				"{:>3}  {}",
				action.id,
				describe(action.op.name(), &action.reason)
			);
		}
	}
	for warning in &plan.warnings {
		match &warning.interface {
			Some(interface) => println!("warning: {interface}: {}", warning.message),
			None => println!("warning: {}", warning.message),
		}
	}
	print_refusals(plan);
}

/// What a guard stopped, and the exact command that consents to it.
///
/// Printed for `plan` and `apply` alike. A refusal the operator cannot act on
/// is just a complaint, so the override is quoted verbatim rather than
/// described.
fn print_refusals(plan: &Plan) {
	for refusal in &plan.refusals {
		println!(
			"refused: {} on {} -- {} depends on it",
			refusal.op, refusal.interface, refusal.guard
		);
		println!(
			"         would have been: {}",
			describe(&refusal.op, &refusal.reason)
		);
		println!("         to allow it:     {}", refusal.override_with);
	}
}

/// One line saying what an action does and why.
fn describe(op: &str, reason: &netcfgd_plan::Reason) -> String {
	let where_ = reason
		.interface
		.as_deref()
		.map_or_else(String::new, |interface| format!(" {interface}"));
	format!(
		"{op}{where_}  {}: {} (was {})",
		reason.field, reason.desired, reason.observed
	)
}
