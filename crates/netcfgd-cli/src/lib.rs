#![forbid(unsafe_code)]

//! `ncfg`: read the config, see what would change, change it.
//!
//! The argument parsing is hand-written. `clap` is excellent and would be
//! several hundred kilobytes against a 400 KB nano budget, for a command set
//! this small -- section 6's size gate is the kind of constraint that has to
//! bind on the first binary or it never binds at all.

mod client;
mod control;
mod drop_in;
mod secret;
#[cfg(feature = "tui")]
mod tui;
mod wifi;

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
                             clients    [IFACE]  who is on the access point
                             add SSID            remember a network: writes
                                                 conf.d/wifi-ID.conf and asks
                                                 for the credential, or reads
                                                 it from standard input. See
                                                 the flags below, including
                                                 --eap for a campus or
                                                 corporate network
                             connect ID [IFACE]  join a configured network
                             disconnect [IFACE]  leave it, keeping the config
                           IFACE may be omitted when the config describes one
                           wireless device.
  ncfg control SUBCOMMAND  who may ask netcfgd for what. SUBCOMMAND is one of:
                             show                what the policy is now
                             set --observe P     change a tier; P is one of
                                 --wifi P        root, any, user:NAME or
                                 --admin P       group:NAME. Repeatable, and
                                                 what is not named is left
                                                 alone. Needs root: this is
                                                 what grants a desktop client
                                                 access in the first place
  ncfg config SUBCOMMAND   configuration netcfgd stores for you. SUBCOMMAND is:
                             put NAME [FILE]     send a drop-in; FILE or `-`
                                                 or nothing reads standard
                                                 input. The name is what
                                                 netcfgd files it under, never
                                                 a path. --replace to overwrite
                             rm NAME             take one away
                           netcfgd compiles the result before keeping it, so a
                           drop-in that would break the configuration is
                           refused with the diagnostics
  ncfg secret SUBCOMMAND   credentials the config refers to. SUBCOMMAND is:
                             set NAME            store the value of
                                                 `@secret:NAME`, asked for at
                                                 the prompt with echo off, or
                                                 read from standard input.
                                                 Written 0600; --replace to
                                                 overwrite an existing one.
                                                 Removing one is `rm`
  ncfg tui [options]       full-screen client: devices, wifi, plan, events
  ncfg monitor [options]   stream events until interrupted (needs netcfgd)
  ncfg confirm [options]   keep a change made under a confirm window
  ncfg revert [options]    undo it now rather than at expiry
  ncfg reload [options]    re-read the config directory now, and say here
                           whether it compiled. netcfgd notices an edit by
                           itself; this is for when the answer belongs in your
                           terminal rather than in the log
  ncfg reset [--yes]       discard the writable config, leaving the factory
                           defaults. Prints what it would remove unless --yes

options:
  --config-dir PATH        default /etc/netcfgd, or $NCFG_CONFIG_DIR
  --factory-dir PATH       default /usr/share/netcfgd, or $NCFG_FACTORY_DIR.
                           Read before --config-dir, which overrides it
  --yes                    for `reset`: actually remove the files
  --replace                for `secret set`: overwrite one that already exists
  --run-dir PATH           default /run/netcfgd, or $NCFG_RUN_DIR
  --oneshot                apply once and exit; the default, there being no
                           daemon yet
  --json                   machine-readable output
  --confirm-within SECS    apply, then revert automatically unless confirmed
                           within SECS. Needs netcfgd running, since the
                           window has to outlive this command. A machine whose
                           config says `global { confirm = N }` arms one
                           without this; `--confirm-within 0` is how to say no
                           window on such a machine
  --allow-disruption IFACE consent to disrupting one guarded interface;
                           repeatable, and deliberately not a blanket --force
  --strand-credentials DEV consent to unmanaging one device while leaving a
                           key on it that cannot be revoked; repeatable.
                           `on_unmanage = \"clear\"` is the durable answer
  -h, --help               this text

options for `wifi add`:
  --id LABEL               name the block this, for an SSID that is not usable
                           as a name. The SSID itself is kept exactly, as hex
  --open                   no security at all, and no passphrase asked for
  --wpa2, --wpa3           pin one generation; the default negotiates both
  --hidden                 the SSID is not broadcast, so probe for it
  --priority N             higher wins when several are in range

options for `wifi add` on an enterprise network (802.1X):
  --eap METHOD             peap, ttls, tls or pwd. What is asked for at the
                           prompt follows from it: a password for the first
                           three, the private key for tls
  --identity NAME          who you are to the authentication server, often
                           with a realm: you@example.ac.uk
  --anonymous-identity N   who you are outside the tunnel, which is all the
                           radio sees. eduroam suggests anonymous@realm
  --ca-cert PATH           the certificate the server is checked against.
                           Without it the machine will trust any server that
                           answers, and the compiler says so
  --client-cert PATH       the certificate presented, for --eap tls
  --phase2 NAME            the inner method, such as mschapv2

exit codes:
  0  the desired state was reached, or already held
  1  an action failed, or the config did not compile
  3  a guard refused a disruptive action; nothing else failed
  4  the config walks away from a credential nobody can revoke, and has not
     said whether that is meant. Nothing else failed
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

/// `Default` is for the tests, which want one field and not the other eight.
/// `parse_options` deliberately does not use it: a new option that reached the
/// struct and not the parser would then compile.
#[derive(Default)]
pub(crate) struct Options {
	config_dir: Option<String>,
	factory_dir: Option<String>,
	yes: bool,
	/// `secret set` only: overwrite a credential that is already stored.
	replace: bool,
	run_dir: Option<String>,
	json: bool,
	confirm: Option<u32>,
	allow_disruption: Vec<String>,
	strand_credentials: Vec<String>,
	/// `wifi add` only, and named for what they mean in the config file they
	/// write rather than for the flag that set them.
	wifi: wifi::Wanted,
	/// What `ncfg control set` was asked to change. What is not named here is
	/// left alone, so a tier nobody mentioned keeps whatever it had.
	control: control::Wanted,
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

	let (options, positional) = parse_options(&arguments[1..])?;

	match command.as_str() {
		"plan" => command_plan(&options),
		"apply" => command_apply(&options),
		"status" => command_status(&options),
		"show" => command_show(&options),
		"explain" => command_explain(&positional, &options),
		"monitor" => command_monitor(&options),
		"wifi" => command_wifi(&positional, &options),
		"control" => control::run(&positional, &options),
		"config" => drop_in::run(&positional, &options),
		"secret" => command_secret(&positional, &options),
		#[cfg(feature = "tui")]
		"tui" => tui::run(&options),
		#[cfg(not(feature = "tui"))]
		"tui" => Err("this build has no TUI; it was compiled without the `tui` feature".to_owned()),
		"reload" => command_reload(&options),
		"reset" => command_reset(&options),
		"confirm" => command_confirm(&options, &netcfgd_proto::Request::Confirm),
		"revert" => command_confirm(&options, &netcfgd_proto::Request::Revert),
		other => Err(format!("unknown command `{other}`; try `ncfg --help`")),
	}
}

/// The options, and the arguments that were not options.
///
/// One pass, because there used to be three -- this function, a `positional`
/// helper with its own list of which flags take a value, and `explain`'s
/// `take_while` on the first `--`. The lists had already drifted:
/// `--factory-dir` and `--strand-credentials` were missing from the helper's,
/// so `ncfg wifi --factory-dir /some/dir scan` read the directory as a
/// subcommand, and `ncfg explain --json interface eth0` found no subject at
/// all. A single walk cannot disagree with itself.
fn parse_options(arguments: &[String]) -> Result<(Options, Vec<String>), String> {
	let mut options = Options {
		config_dir: None,
		factory_dir: None,
		yes: false,
		replace: false,
		run_dir: None,
		json: false,
		confirm: None,
		allow_disruption: Vec::new(),
		strand_credentials: Vec::new(),
		wifi: wifi::Wanted::default(),
		control: control::Wanted::default(),
	};
	let mut positional = Vec::new();
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
			"--strand-credentials" => options
				.strand_credentials
				.push(take_value("--strand-credentials")?),
			"--json" => options.json = true,
			"--yes" => options.yes = true,
			"--replace" => options.replace = true,
			// The control tiers. Named here rather than parsed inside the
			// subcommand because this parser refuses a flag it does not
			// know, which is what stops a mistyped one being ignored.
			"--observe" => options.control.observe = Some(take_value("--observe")?),
			"--wifi" => options.control.wifi = Some(take_value("--wifi")?),
			"--admin" => options.control.admin = Some(take_value("--admin")?),
			"--id" => options.wifi.id = Some(take_value("--id")?),
			"--priority" => {
				let value = take_value("--priority")?;
				options.wifi.priority = Some(value.parse().map_err(|_| {
					format!("--priority wants a number, and higher wins, not `{value}`")
				})?);
			}
			"--open" => options.wifi.open = true,
			"--wpa2" => options.wifi.proto = Some("wpa2"),
			"--wpa3" => options.wifi.proto = Some("wpa3"),
			"--hidden" => options.wifi.hidden = true,
			"--eap" => {
				let value = take_value("--eap")?;
				options.wifi.eap = Some(match value.as_str() {
					"peap" => "peap",
					"ttls" => "ttls",
					"tls" => "tls",
					"pwd" => "pwd",
					// Named here as well as in the compiler, because this is
					// the one an operator sees first and "unknown wifi key" an
					// hour later is not the same sentence.
					other => {
						return Err(format!(
							"`{other}` is not an EAP method: one of peap, ttls, tls, pwd"
						))
					}
				});
			}
			"--identity" => options.wifi.identity = Some(take_value("--identity")?),
			"--anonymous-identity" => {
				options.wifi.anonymous_identity = Some(take_value("--anonymous-identity")?);
			}
			"--ca-cert" => options.wifi.ca_cert = Some(take_value("--ca-cert")?),
			"--client-cert" => options.wifi.client_cert = Some(take_value("--client-cert")?),
			"--phase2" => options.wifi.phase2 = Some(take_value("--phase2")?),
			// There is no daemon yet, so oneshot is the only mode there is.
			// Accepting the flag now means the command line does not change
			// when the daemon lands in M2.
			"--oneshot" => {}
			// Positional arguments belong to the subcommand -- `explain` takes
			// three, `wifi add` takes one. An unknown *option* is still an
			// error, because a typo in a flag silently ignored is how somebody
			// thinks they passed --confirm-within and did not.
			other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
			other => positional.push(other.to_owned()),
		}
		index += 1;
	}
	Ok((options, positional))
}

/// Compile the config, and write the result where `cat` can reach it.
///
/// **An empty config directory is not an error**, and used to be one here. It
/// is the state a fresh install is in: the package ships no configuration and
/// `debian/postinst` says so, so every `ncfg` command that compiled met a
/// fatal `no configuration found` on a machine that was working exactly as
/// designed. The daemon has always disagreed -- [`state::reload`] compiles the
/// same empty source set to the default document and serves a socket from it --
/// and so has `ncfg wifi add`, which returns `None` and writes the first file.
/// Two answers to "what does an empty directory mean" is the drift section 5
/// created `netcfgd-host` to prevent, and this was the copy that had it wrong.
///
/// What it cost was the bootstrap. `ncfg control set` is the one command that
/// opens the socket to a desktop user, it is the command `debian/postinst`
/// prints, and it reads the current policy through here -- so the only
/// documented way out of the root-only default could not run until a
/// configuration existed, on an install that deliberately ships none. A
/// zero-byte `netcfgd.conf` was the entire difference.
///
/// The diagnostic is not lost, only demoted: `plan` says the directory is
/// empty rather than refusing to answer, which keeps the case where somebody
/// pointed `--config-dir` at the wrong place from reading as "nothing to do".
fn compile(options: &Options) -> Result<(netcfgd_model::Document, std::path::PathBuf), String> {
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
	observe_against(run_dir, None)
}

/// The same, with the document to compare a running daemon's secret against.
///
/// Split rather than made optional at the call sites, because most callers have
/// no document and the one question this answers -- has the passphrase behind a
/// `@secret:` reference been edited (decision 0052) -- is only meaningful when
/// there is one.
fn observe_against(
	run_dir: &std::path::Path,
	desired: Option<&netcfgd_model::Document>,
) -> Result<Observed, String> {
	let prior = state::prior_state(run_dir);
	netcfgd_observe::current(&prior, run_dir, desired)
		.map_err(|error| format!("could not read the kernel: {error}"))
}

fn build_plan(
	options: &Options,
) -> Result<(Plan, netcfgd_model::Document, Observed, std::path::PathBuf), String> {
	let (document, run_dir) = compile(options)?;
	// With the document, because one thing the observation answers needs it:
	// whether a running access point still holds the passphrase the store has
	// (decision 0052). Every other caller of `observe` has no document and asks
	// a smaller question.
	let observed = observe_against(&run_dir, Some(&document))?;
	let plan_options = PlanOptions {
		confirm_window: options.confirm,
		revert_to: None,
		allow_disruption: options.allow_disruption.clone(),
		strand_credentials: options.strand_credentials.clone(),
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
		note_empty_config(options);
		warn_about_contention(&document, &observed);
	}
	Ok(ExitCode::SUCCESS)
}

/// Say that the configuration directory is empty, where that explains the plan.
///
/// `compile` stopped treating this as fatal, and a bare `nothing to do` is
/// ambiguous in the one case the old error was right about: somebody who
/// pointed `--config-dir` at the wrong directory gets the same two words as
/// somebody whose machine genuinely has nothing to change. So the fact is
/// still reported, as a note under an answer rather than instead of one.
///
/// Not printed for `--json`, which is read by programs, and not for `show`,
/// whose whole output is a document a parser is meant to consume.
fn note_empty_config(options: &Options) {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let Ok(sources) = config::load_layered(
		&config::resolve_factory_dir(options.factory_dir.as_deref()),
		&config_dir,
	) else {
		// Unreadable rather than empty. `compile` has already failed with the
		// real error, so this is unreachable in practice and silent by choice:
		// a second, vaguer sentence about the same directory helps nobody.
		return;
	};
	if !sources.is_empty() {
		return;
	}
	println!();
	println!(
		"there is no configuration in {}, so netcfgd manages nothing here.",
		config_dir.display()
	);
	println!("`ncfg wifi add SSID` writes the first one; docs/first-run.md has the");
	println!("wired case.");
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
			strand_credentials: options.strand_credentials.clone(),
		};
		return match client::ask(&client::socket_path(&run_dir), &request)? {
			client::Answer::Journal(journal) => {
				for record in &journal.records {
					println!("{:?} {}", record.outcome, record.op);
					// The record has carried this all along and this path dropped
					// it, so a failure over the socket said `Failed hook.run` and
					// nothing about why -- while the same failure through `ncfg
					// apply` printed the reason. Found by a live test looking for a
					// message that was already in the journal (0063).
					if let Some(error) = &record.error {
						println!("     {error}");
					}
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
			if plan.was_refused() || plan.strands_credentials() {
				print_refusals(&plan);
				print_stranded(&plan);
			} else {
				println!("nothing to do");
			}
		}
		return Ok(outcome(&plan));
	}

	let mut executor = KernelExecutor::new()
		.map_err(|error| format!("could not open a netlink socket: {error}"))?
		.with_context(&run_dir, &document, &observed);
	let journal = apply(&plan, &mut executor);

	// Record what happened before reporting it. A journal that exists only in
	// the terminal is no use to whoever finds the machine afterwards.
	if let Err(error) = state::update_owned(&run_dir, |owned| owned.absorb(&executor.effects)) {
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

	if !options.json {
		print_refusals(&plan);
		print_stranded(&plan);
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

	Ok(outcome(&plan))
}

/// The exit code for a plan that did not fail.
///
/// A refusal means the desired state was not reached, whether or not some
/// actions ran. Exiting zero there would tell a script convergence happened
/// when the very change it asked for is the one that did not.
///
/// Stranding is a separate code because it has a separate remedy. A script
/// that saw 3 and re-ran with `--allow-disruption` would be answering a
/// question nobody asked, and the state it left behind -- a key on hardware
/// walking out of the building -- is the one this exists to stop being
/// silent about. Refusal wins when both apply: it is the one where netcfgd
/// did not do something it was asked.
fn outcome(plan: &Plan) -> ExitCode {
	if plan.was_refused() {
		return ExitCode::from(3);
	}
	if plan.strands_credentials() {
		return ExitCode::from(4);
	}
	ExitCode::SUCCESS
}

/// Answer "why is it like this?" locally.
///
/// Deliberately not routed through the daemon. Design section 4.4 makes
/// daemon-optional a property rather than a fallback, and explain is exactly
/// the command somebody reaches for when things are broken -- which is when a
/// daemon is least likely to be running.
fn command_explain(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let subject = match positional {
		[kind, name] if kind == "interface" => {
			netcfgd_proto::Subject::Interface { name: name.clone() }
		}
		[kind, interface, address] if kind == "address" => netcfgd_proto::Subject::Address {
			interface: interface.clone(),
			address: address.clone(),
		},
		[kind, interface, destination] if kind == "route" => netcfgd_proto::Subject::Route {
			interface: interface.clone(),
			destination: destination.clone(),
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
/// `ncfg secret SUBCOMMAND`.
///
/// One subcommand so far, and the shape is deliberate: `set` writes a file that
/// the `file` provider reads, and there is no `get` -- the whole point of a
/// `SecretRef` is that the value travels to the backend that needs it and
/// nowhere else. Decision 0075.
///
/// Removing one is `rm`, which is the answer 0069 gave for forgetting a network
/// and is honest here for the same reason: there is nothing a command could add
/// to `rm` beyond a longer way to spell it.
fn command_secret(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err("`ncfg secret` needs a subcommand: set".to_owned());
	};
	match subcommand.as_str() {
		"set" => secret::set(&positional[1..], options),
		"get" | "show" | "print" => Err(format!(
			"there is no `ncfg secret {subcommand}`, and that is the point: a secret goes to \
			 the backend that needs it and nowhere else (project.md section 2). The file is \
			 readable by root if you must -- and if it is a WireGuard key, the kernel has it \
			 too"
		)),
		other => Err(format!(
			"unknown `ncfg secret` subcommand `{other}`; there is one: set"
		)),
	}
}

/// `ncfg wifi activate|deactivate <radio>`.
///
/// **The interface is named rather than defaulted**, unlike `scan` and
/// `status`. Those act on "the radio", which is unambiguous on a machine with
/// one. This decides *which* radio netcfgd takes on, and a machine with two is
/// exactly where that question is being asked -- defaulting would pick one of
/// them for somebody who has more than one for a reason.
///
/// # Errors
///
/// A missing name, with the command that lists them.
fn radio_request(subcommand: &str, rest: &[String]) -> Result<netcfgd_proto::Request, String> {
	let Some(interface) = rest.first() else {
		return Err(format!(
			"`ncfg wifi {subcommand}` needs the name of a radio. `ncfg wifi radios` lists them"
		));
	};
	Ok(netcfgd_proto::Request::RadioSet {
		interface: interface.clone(),
		activate: subcommand == "activate",
	})
}

fn command_wifi(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err(
			"`ncfg wifi` needs a subcommand: radios, activate, deactivate, scan, \
			 status, add, connect or disconnect"
				.to_owned(),
		);
	};
	let rest = &positional[1..];

	// Before the socket: `add` writes the configuration and needs no daemon,
	// which is the point -- a machine with no network yet is a machine where
	// nothing else is running either.
	if subcommand == "add" {
		return wifi::add(rest, options);
	}

	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let socket = client::socket_path(&run_dir);

	let request = match subcommand.as_str() {
		"radios" => netcfgd_proto::Request::Radios,
		"activate" | "deactivate" => radio_request(subcommand, rest)?,
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
		"clients" => netcfgd_proto::Request::ApStations {
			interface: wireless_interface(rest.first(), options)?,
		},
		other => {
			return Err(format!(
				"unknown wifi subcommand `{other}`; try scan, status, clients, add, connect or \
				 disconnect"
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
		client::Answer::ApStations(report) => {
			render_stations(&report, options.json)?;
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Radios { radios } => {
			render_radios(&radios, options.json)?;
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Ok => {
			println!(
				"{}",
				match &request {
					netcfgd_proto::Request::WifiConnect { .. } =>
						"joining; `ncfg wifi status` says whether it worked".to_owned(),
					netcfgd_proto::Request::RadioSet {
						interface,
						activate,
					} =>
						if *activate {
							format!(
								"netcfgd manages `{interface}` now, and will run a \
								 supplicant on it. `ncfg wifi scan {interface}` should \
								 find something"
							)
						} else {
							format!("`{interface}` is no longer netcfgd's")
						},
					_ => "disconnected".to_owned(),
				}
			);
			Ok(ExitCode::SUCCESS)
		}
		client::Answer::Error { message } => Err(message),
		other => Err(format!("the daemon sent {}", other.describe())),
	}
}

/// A duration a person reads at a glance rather than a seconds count.
fn duration(seconds: u64) -> String {
	let (hours, minutes, seconds) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
	if hours > 0 {
		format!("{hours}h{minutes:02}m")
	} else if minutes > 0 {
		format!("{minutes}m{seconds:02}s")
	} else {
		format!("{seconds}s")
	}
}

/// Bytes in the units the number is actually in.
///
/// Integer arithmetic rather than a float divide: a byte counter is a `u64`,
/// and casting one to `f64` loses precision above 2^53 -- which clippy refuses
/// and is right to. One decimal place is all this shows anyway.
fn bytes(count: u64) -> String {
	for (limit, suffix) in [(1_000_000_000_u64, "G"), (1_000_000, "M"), (1_000, "k")] {
		if count >= limit {
			let whole = count / limit;
			let tenths = (count % limit) * 10 / limit;
			return format!("{whole}.{tenths}{suffix}");
		}
	}
	format!("{count}B")
}

/// Who is on an access point.
///
/// A station hostapd could not read statistics for still appears, with dashes
/// where the numbers would be. Hiding it would be the worst way for this to be
/// wrong: the whole point is knowing who is connected, and a client that is
/// there is more important than the signal strength that is not.
fn render_stations(report: &netcfgd_proto::StationReport, json: bool) -> Result<(), String> {
	if json {
		println!(
			"{}",
			serde_json::to_string_pretty(report).map_err(|error| error.to_string())?
		);
		return Ok(());
	}
	if report.stations.is_empty() {
		println!(
			"nothing is associated with `{}` on {}",
			report.access_point, report.interface
		);
		return Ok(());
	}

	println!(
		"{} station{} on `{}` ({})",
		report.stations.len(),
		if report.stations.len() == 1 { "" } else { "s" },
		report.access_point,
		report.interface
	);
	println!();
	println!(
		"{:<17}  {:>7}  {:>9}  {:>7}  {:>8}  {:>8}",
		"ADDRESS", "SIGNAL", "CONNECTED", "IDLE", "RX", "TX"
	);

	let mut anomalies = 0;
	for station in &report.stations {
		let signal = station
			.signal
			.map_or_else(|| "--".to_owned(), |dbm| format!("{dbm} dBm"));
		let connected = station
			.connected_seconds
			.map_or_else(|| "--".to_owned(), duration);
		let idle = station
			.inactive_msec
			.map_or_else(|| "--".to_owned(), |msec| duration(msec / 1000));
		let rx = station.rx_bytes.map_or_else(|| "--".to_owned(), bytes);
		let tx = station.tx_bytes.map_or_else(|| "--".to_owned(), bytes);

		// The note says what is *surprising*, which is the opposite thing
		// under the two policies: a listed station is expected under `allow`
		// and should be impossible under `deny`.
		let note = match (report.access_control, station.listed) {
			(Some(netcfgd_model::AclPolicy::Deny), true) => {
				anomalies += 1;
				"  <- on the deny list and still connected"
			}
			(Some(netcfgd_model::AclPolicy::Allow), false) => {
				anomalies += 1;
				"  <- not on the allow list and still connected"
			}
			_ if !station.authorized => "  (associated, not authorized)",
			_ => "",
		};

		println!(
			"{:<17}  {signal:>7}  {connected:>9}  {idle:>7}  {rx:>8}  {tx:>8}{note}",
			station.address
		);
	}

	if anomalies > 0 {
		println!();
		// What this means changed with decision 0041, and saying the old thing
		// would send an operator to restart an access point that was about to
		// fix itself. hostapd still reads its file once at startup, but netcfgd
		// now converges the live list over the control socket, so an arrow is a
		// state that lasts until the next reconcile rather than until somebody
		// intervenes. `ncfg apply` is the way to stop waiting.
		println!(
			"An arrow means hostapd's live list does not match the document yet: it reads \n\
			 the file once at startup and netcfgd converges the difference over the control \n\
			 socket. `ncfg apply` does it now; if an arrow survives that, `ncfg plan` says \n\
			 why (docs/decisions/0041)."
		);
	}
	Ok(())
}

/// Whether a link with this kind and name is a radio.
///
/// The kernel's word first and the name only as a fallback: `wlan` is a fact
/// where the kernel says it, and the `wl` prefix is a convention that happens
/// to hold, in the same way `eth0` is not proof of an ethernet.
///
/// That ordering is the whole rule, and it used to be written as `kind ==
/// Some("wlan") || name.starts_with("wl")` -- an *or*, which is not a fallback.
/// The two differ only where the kernel gave a kind that is not `wlan`, and
/// that is precisely where the name is least trustworthy: `ObservedLink::kind`
/// is empty for a plain device and holds a word only for a virtual one, so a
/// non-empty kind means the kernel has already answered. A VLAN on a radio is
/// named `wlan0.10` and a bridge may be named anything, so the *or* called both
/// of them radios -- and `tui.rs` picks its radio with `.find()` over a
/// name-sorted list, where `wl-br0` sorts ahead of `wlan0` and would be shown
/// as the radio instead of the real one.
///
/// `client/`'s `ncfg_link_is_wireless()` is the identical rule in C, because
/// the GUI needs it and cannot reach this one. Two implementations of one
/// heuristic is the drift 0116 names and does not fix -- so `make conformance`
/// feeds both the same table and diffs the answers, which is the cheapest
/// honest substitute for sharing the code. What that comparison cannot do is
/// say whether the shared answer is *right*: both sides were written from each
/// other, so they are one witness. `a_kind_the_kernel_gave_wins_over_the_name`
/// is the independent one.
pub(crate) fn is_radio(kind: Option<&str>, name: &str) -> bool {
	match kind {
		Some(kind) if !kind.is_empty() => kind == "wlan",
		_ => name.starts_with("wl"),
	}
}

/// How an access point is named on a screen, for every client that draws one.
///
/// Three cases and not two, because the daemon sends three. A name that arrived
/// is the name. A name that arrived *empty* is a hidden network, which is a fact
/// worth saying rather than a blank cell. A name that did not arrive at all
/// means the SSID is not valid UTF-8 -- the daemon omits it rather than mangling
/// it -- and then the hex is the only honest name it has, so it is shown with a
/// prefix that stops anybody reading the hex as the name.
///
/// Here rather than at each call site because it was at each call site: `ncfg
/// wifi scan` said `hex:...` and nothing for hidden, the TUI said `<not text>`
/// for one and nothing for the other, and the GUI grew a third spelling. Three
/// words for one thing is the drift section 10 keeps recording, and losing the
/// hex was worse than untidy -- two unprintable SSIDs became the same row.
///
/// The C client renders the same three cases in `ncfg_connection.cpp` and must
/// keep saying the same words. Until the socket has a specification (0116) that
/// agreement is a comment in two languages, which is why it is written down in
/// both.
/// The one word a scan row uses for an access point's security.
///
/// **Three values, not two.** "secured" on a corporate network sends an
/// operator looking for a passphrase that does not exist; naming 802.1X says
/// what will be asked for. The word has to be the same in every client -- the
/// GUI, the TUI and `ncfg wifi scan` -- for the same reason
/// [`access_point_name`] exists: three places each choosing their own word is
/// how they end up disagreeing about one access point.
///
/// It is also the TUI's grouping key rather than merely its heading, so a
/// passphrase network and an enterprise one sharing an SSID stay two rows. A
/// key coarser than the word displayed would merge them under a heading that
/// then described only one.
pub(crate) fn access_point_security(secured: bool, enterprise: bool) -> &'static str {
	match (secured, enterprise) {
		(_, true) => "enterprise",
		(true, false) => "secured",
		(false, false) => "open",
	}
}

pub(crate) fn access_point_name(name: Option<&str>, ssid: &str) -> String {
	match name {
		None => format!("hex:{ssid}"),
		Some("") => "(hidden)".to_owned(),
		Some(text) => text.to_owned(),
	}
}

/// The radios, and what netcfgd is doing about each.
///
/// Three states rather than two, because the third is the one somebody is
/// stuck in: a radio nothing has activated but where a supplicant is
/// answering belongs to another manager, and netcfgd declines those rather
/// than taking them. Saying "not activated" there and nothing else would
/// invite an `activate` that changes nothing.
fn render_radios(radios: &[netcfgd_proto::Radio], json: bool) -> Result<(), String> {
	if json {
		let text = serde_json::to_string(radios)
			.map_err(|error| format!("cannot render radios as json: {error}"))?;
		println!("{text}");
		return Ok(());
	}
	if radios.is_empty() {
		println!("no radios on this machine");
		return Ok(());
	}
	for radio in radios {
		let state = match (radio.activated, radio.supplicant) {
			(true, true) => "netcfgd's",
			(true, false) => "netcfgd's, but no supplicant is answering",
			(false, true) => {
				"another manager's -- a supplicant is answering that netcfgd \
			                  did not start"
			}
			(false, false) => "not activated",
		};
		println!("{:<16} {state}", radio.interface);
	}
	if radios.iter().any(|radio| !radio.activated) {
		println!("\n`ncfg wifi activate <radio>` hands one to netcfgd.");
	}
	Ok(())
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
		let name = access_point_name(entry.name.as_deref(), &entry.ssid);
		let security = access_point_security(entry.secured, entry.enterprise);
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
	// Keyed on the ssid, which is the field that says "associated at all", and
	// rendered by the shared namer. `name.or(ssid)` printed the raw hex with
	// nothing marking it as hex whenever the SSID was not text -- the exact
	// misreading the `hex:` prefix exists to stop, in the one place a scan's
	// rendering had not reached.
	if let Some(ssid) = state.ssid.as_deref() {
		let name = access_point_name(state.name.as_deref(), ssid);
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

/// Re-read the config, and say here whether it compiled.
///
/// Not how a change takes effect -- the daemon watches the directory and
/// reloads by itself, and that stays the normal path. This is how the person
/// who made the change *finds out*. Without it the diagnostics for a config
/// that does not compile go to the daemon's log and the editor is told
/// nothing, which is the shape of every "I edited it and nothing happened".
///
/// It also answers the case where the watch is not watching what the operator
/// thinks it is: a file replaced through a bind mount, or a config directory on
/// a filesystem that does not report changes. Asking is then the only way to
/// know, and before this the protocol had a `reload` that no shipped client
/// could send.
fn command_reload(options: &Options) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let request = netcfgd_proto::Request::Reload;
	match client::ask(&client::socket_path(&run_dir), &request)? {
		client::Answer::Ok => {
			println!("reloaded; the configuration compiles");
			Ok(ExitCode::SUCCESS)
		}
		// The daemon's own diagnostics, which name a file and a line. A
		// config that does not compile leaves the last good state in effect
		// (design section 17), so this is a report and not a failed change --
		// but it exits non-zero, because the file on disk is not what is
		// running and a script must not read that as success.
		client::Answer::Error { message } => Err(message),
		other => Err(format!("the daemon sent {}", other.describe())),
	}
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

/// Observe, with the document where the config compiles.
///
/// The observation answers one question that needs it: whether a running access
/// point still holds the passphrase the store has (decision 0052). A config
/// that does not compile is not a reason to refuse to look at the kernel, so a
/// failure here leaves that one field unanswered -- which is exactly what
/// `None` says -- rather than failing the command.
fn observe_with_document(options: &Options, run_dir: &std::path::Path) -> Result<Observed, String> {
	let compiled = compile(options).ok();
	observe_against(run_dir, compiled.as_ref().map(|(document, _)| document))
}

/// The per-link lines that are neither an address nor a VLAN.
///
/// Split out when the radio line arrived and the function passed what the style
/// allows. Each of these prints only when there is something to say: a status
/// listing is read to find out why something is wrong, and a line per feature per
/// interface buries the one that matters.
fn print_link_settings(link: &netcfgd_model::ObservedLink, observed: &netcfgd_model::Observed) {
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
	// Only when it is off. A radio that works needs no line, and an operator
	// scanning this list is looking for the reason something does not work --
	// `ncfg explain interface` reports it either way.
	if let Some(rfkill) = &link.rfkill {
		if rfkill.blocked() {
			let switch = if rfkill.hard { "hardware" } else { "software" };
			println!("    radio off [{switch} block at {}]", rfkill.switch);
		}
	}
}

fn command_status(options: &Options) -> Result<ExitCode, String> {
	let run_dir = state::resolve_dir(options.run_dir.as_deref());
	let observed = observe_with_document(options, &run_dir)?;
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
		print_link_settings(link, &observed);
		// What something outside netcfgd reported, shown as reported rather than
		// as applied -- because it is not applied. netcfgd reads this file and
		// does nothing with it until an `addressing` source asks (0044, 0045,
		// `docs/interface-report.md`), and an operator who cannot see the
		// difference between "the bearer is up" and "netcfgd configured the
		// interface" would have no way to tell which half was broken.
		if let Some(report) = observed
			.reports
			.iter()
			.find(|report| report.interface == link.name)
		{
			for address in &report.addresses {
				println!("    {address} [reported, not applied]");
			}
			for gateway in &report.gateways {
				println!("    via {gateway} [reported, not applied]");
			}
			if !report.nameservers.is_empty() {
				println!(
					"    nameservers {} [reported, not applied]",
					report.nameservers.join(" ")
				);
			}
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
	print_stranded(plan);
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

/// What a plan walks away from that cannot be taken back.
///
/// Both ways out are printed, and the config one first: the flag consents for
/// one run, and the config key is the answer that is still there next time
/// somebody reads the file. Printing them the other way round would make the
/// flag look like the fix.
fn print_stranded(plan: &Plan) {
	for stranded in &plan.stranded {
		println!(
			"stranded: unmanaging {} leaves {}",
			stranded.interface, stranded.credential
		);
		println!("          it cannot be revoked: {}", stranded.irrevocable);
		println!("          to remove it:  {}", stranded.remove_with);
		println!("          to leave it:   {}", stranded.consent_with);
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

#[cfg(test)]
mod tests {
	use super::{access_point_name, is_radio, parse_options};

	fn split(arguments: &[&str]) -> (super::Options, Vec<String>) {
		let owned: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
		parse_options(&owned).expect("it parses")
	}

	/// Every command the help text offers has an arm to dispatch it.
	///
	/// `reload` drifted the other way for a whole milestone: the request was in
	/// the protocol, in `docs/schema/socket.json` and in the authorisation
	/// table, and no shipped client could send it. Nothing was red, because
	/// nothing compared the two lists.
	///
	/// This catches the half that can be caught without running commands that
	/// want a daemon: a name in the help that dispatches to `unknown command`.
	/// The other half -- a request the protocol defines and the CLI never
	/// offers -- is what the reader below the seam is for, and is why
	/// `client/tests` parses the witness rather than a fixture.
	#[test]
	fn every_command_in_the_help_text_is_dispatched() {
		let source = include_str!("lib.rs");
		let mut checked = 0;
		for line in super::USAGE.lines() {
			let Some(rest) = line.trim_start().strip_prefix("ncfg ") else {
				continue;
			};
			let name = rest.split_whitespace().next().unwrap_or_default();
			// Only the command lines. The options block wraps continuation
			// text under the same indent, and none of it starts with `ncfg `.
			if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase()) {
				continue;
			}
			assert!(
				source.contains(&format!("\"{name}\" =>")),
				"`ncfg {name}` is offered by the help text with nothing to dispatch it"
			);
			checked += 1;
		}
		assert!(
			checked > 10,
			"the help text was reformatted out from under this test: it found \
			 {checked} commands, and there are more than that"
		);
	}

	/// The regression the one-pass parse fixes. Every option that takes a value
	/// has to consume it, or the value becomes a subcommand -- and it used to,
	/// for the two options that were in this parser and not in the separate
	/// list the subcommands used.
	#[test]
	fn a_value_is_never_mistaken_for_a_subcommand() {
		// Paired with a value each option actually accepts, because two of
		// them check what they are given -- and a test that fed every flag the
		// word `value` would be asserting the parse *and* the validation, and
		// would go red for the second while claiming the first.
		for (option, value) in [
			("--config-dir", "value"),
			("--factory-dir", "value"),
			("--run-dir", "value"),
			("--allow-disruption", "value"),
			("--strand-credentials", "value"),
			("--id", "value"),
			// The enterprise flags. Every one takes a value that can look like
			// a subcommand -- an identity is a word, a phase2 name is
			// `mschapv2`, a certificate is a path -- which is exactly the shape
			// that broke `wifi add` before the parse became one pass.
			("--eap", "peap"),
			("--identity", "value"),
			("--anonymous-identity", "value"),
			("--ca-cert", "value"),
			("--client-cert", "value"),
			("--phase2", "value"),
		] {
			let (_, positional) = split(&[option, value, "scan"]);
			assert_eq!(
				positional,
				vec!["scan".to_owned()],
				"`{option} {value}` left its value behind as a positional"
			);
		}
		let (_, positional) = split(&["--confirm-within", "30", "scan"]);
		assert_eq!(positional, vec!["scan".to_owned()]);
		let (_, positional) = split(&["--priority", "30", "add", "Home"]);
		assert_eq!(positional, vec!["add".to_owned(), "Home".to_owned()]);
	}

	/// And a flag before the positionals no longer hides them, which is what
	/// `explain` did with its own `take_while`.
	#[test]
	fn a_flag_may_come_first() {
		let (options, positional) = split(&["--json", "interface", "eth0"]);
		assert!(options.json);
		assert_eq!(positional, vec!["interface".to_owned(), "eth0".to_owned()]);
	}

	#[test]
	fn a_missing_value_is_an_error_rather_than_a_default() {
		let owned = vec!["--priority".to_owned()];
		match parse_options(&owned) {
			Ok(_) => panic!("a value-taking option with no value must be refused"),
			Err(error) => assert!(error.contains("needs a value"), "{error}"),
		}
	}

	#[test]
	fn a_mistyped_flag_is_refused_rather_than_ignored() {
		let owned = vec!["--jsonn".to_owned()];
		assert!(parse_options(&owned).is_err());
	}

	/// Three cases, because the daemon sends three and every client draws
	/// them. The two that are not "a name" are the ones that were being got
	/// wrong: a hidden network drew as a blank cell in two clients, and an
	/// unprintable SSID drew as `<not text>` in the TUI -- which named the
	/// condition and threw the network away, so two of them were one row.
	#[test]
	fn an_access_point_is_named_three_ways_and_never_two() {
		assert_eq!(access_point_name(Some("home"), "686f6d65"), "home");
		assert_eq!(access_point_name(Some(""), "00"), "(hidden)");
		assert_eq!(access_point_name(None, "ff00ff"), "hex:ff00ff");
	}

	/// What the radio rule is *for*, which `make conformance` cannot say.
	///
	/// That target diffs this implementation against `client/`'s, and both were
	/// written from each other -- so they agree by construction and would agree
	/// just as loudly about a wrong answer. This is the second witness, and it
	/// asserts the ordering rather than the two easy cases: a kind the kernel
	/// gave decides on its own, and the name is consulted only where there is
	/// no kind.
	///
	/// The last two are the ones that were wrong. A VLAN on a radio inherits
	/// the radio's name, and `tui.rs` finds its radio with `.find()` over a
	/// name-sorted list, so `wl-br0` sorting ahead of `wlan0` put a bridge on
	/// the screen where the radio belonged.
	#[test]
	fn a_kind_the_kernel_gave_wins_over_the_name() {
		// No kind: a plain device, so the name convention is all there is.
		assert!(is_radio(Some(""), "wlp0s20f3"));
		assert!(is_radio(None, "wlan0"));
		assert!(!is_radio(Some(""), "eth0"));
		assert!(!is_radio(None, "wwan0"));

		// A kind the kernel gave: it answers, and the name is not consulted.
		assert!(is_radio(Some("wlan"), "enp1s0"));
		assert!(!is_radio(Some("vlan"), "wlan0.10"));
		assert!(!is_radio(Some("bridge"), "wl-br0"));
	}

	/// The hex is kept, not summarised, so two unprintable networks are two
	/// rows. This is the assertion the old TUI wording could not have passed.
	#[test]
	fn two_unprintable_networks_do_not_become_one_row() {
		assert_ne!(
			access_point_name(None, "ff00ff"),
			access_point_name(None, "ff00fe")
		);
	}

	/// The naming cases both implementations are asked to render.
	///
	/// Fixed rather than drawn from the witness, and that is the load-bearing
	/// part: the witness carries one access point and it has a text name, so
	/// the two cases that actually drifted -- hidden, and an SSID that is not
	/// text -- are in it nowhere. Drifting the C renderer back to its old
	/// spelling was *not caught* until this table existed. A gate that has
	/// never seen its subject is not a gate, and this one had not.
	const NAMING_CASES: [(bool, &str, &str); 3] = [
		(true, "home", "686f6d65"),
		(true, "", ""),
		(false, "", "ff00ff"),
	];

	/// The kind/name pairs both implementations are asked to classify.
	///
	/// Fixed rather than drawn from the witness, because the cases worth
	/// comparing are the ones no witness line contains: a kind the kernel did
	/// not give, and a name that only looks wireless. `wl-bridge` is in here
	/// deliberately -- the name fallback called a bridge a radio, which is a
	/// real false positive of a heuristic nobody had written down, and a table
	/// that hid it would be agreeing about the easy half. `wlan0.10` is the
	/// same fault in the shape somebody actually meets: a VLAN on a radio is
	/// named after the radio, so it is the false positive that arrives without
	/// anybody choosing an odd name.
	const RADIO_CASES: [(&str, &str); 7] = [
		("wlan", "wlan0"),
		("", "wlp0s20f3"),
		("bridge", "wl-bridge"),
		("vlan", "wlan0.10"),
		("", "eth0"),
		("", "wwan0"),
		("wlan", "enp1s0"),
	];

	/// What this implementation extracts from the witness, in the form the C
	/// one is asked for the same thing.
	fn rust_facts(witness: &str) -> String {
		let mut out = String::new();
		for (index, line) in witness.lines().enumerate() {
			let number = index + 1;
			let line = line.trim_end();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let Ok(response) = serde_json::from_str::<netcfgd_proto::Response>(line) else {
				continue;
			};
			match response {
				netcfgd_proto::Response::WifiScan(report) => {
					out.push_str(&format!("scan {number} interface={}\n", report.interface));
					for (i, ap) in report.access_points.iter().enumerate() {
						let display = access_point_name(ap.name.as_deref(), &ap.ssid);
						out.push_str(&format!("scan {number} ap[{i}] bssid={}\n", ap.bssid));
						out.push_str(&format!("scan {number} ap[{i}] ssid={}\n", ap.ssid));
						out.push_str(&format!(
							"scan {number} ap[{i}] named={}\n",
							i32::from(ap.name.is_some())
						));
						out.push_str(&format!("scan {number} ap[{i}] display={display}\n"));
						out.push_str(&format!(
							"scan {number} ap[{i}] configured={}\n",
							ap.configured.as_deref().unwrap_or("")
						));
						out.push_str(&format!(
							"scan {number} ap[{i}] frequency={}\n",
							ap.frequency
						));
						out.push_str(&format!("scan {number} ap[{i}] signal={}\n", ap.signal));
						out.push_str(&format!(
							"scan {number} ap[{i}] secured={}\n",
							i32::from(ap.secured)
						));
					}
				}
				netcfgd_proto::Response::WifiStatus(state) => {
					let empty = |value: &Option<String>| value.clone().unwrap_or_default();
					out.push_str(&format!("status {number} interface={}\n", state.interface));
					out.push_str(&format!("status {number} state={}\n", state.state));
					out.push_str(&format!("status {number} ssid={}\n", empty(&state.ssid)));
					out.push_str(&format!("status {number} name={}\n", empty(&state.name)));
					out.push_str(&format!("status {number} bssid={}\n", empty(&state.bssid)));
					out.push_str(&format!(
						"status {number} network={}\n",
						empty(&state.network)
					));
				}
				_ => {}
			}
		}
		for (named, name, ssid) in NAMING_CASES {
			let display = access_point_name(named.then_some(name), ssid);
			out.push_str(&format!(
				"name named={} name={name} ssid={ssid} display={display}\n",
				i32::from(named)
			));
		}
		for (kind, name) in RADIO_CASES {
			let kind_field = if kind.is_empty() { None } else { Some(kind) };
			out.push_str(&format!(
				"radio kind={kind} name={name} wireless={}\n",
				i32::from(is_radio(kind_field, name))
			));
		}
		out
	}

	/// The two client implementations agree about the same bytes.
	///
	/// This is the only check here that compares two *clients*. The schema
	/// witness pins what the daemon sends and every other gate reads it from
	/// one side; nothing asked whether the C client and this one extracted the
	/// same facts from it -- which is how one access point's name came to be
	/// spelled three ways and an unprintable SSID lost its identity in one of
	/// them.
	///
	/// Fails rather than skips when the C binary is absent. A conformance
	/// check that quietly passes because it compared nothing is the vacuous
	/// pass this project keeps finding, and it would be worse here than
	/// anywhere: the whole value is in the comparison happening.
	#[test]
	fn both_client_implementations_extract_the_same_facts() {
		let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
		let witness_path = root.join("docs/schema/socket.json");
		let binary = root.join("client/tests/client_test");

		assert!(
			binary.exists(),
			"the C client's test binary is not built, so nothing would be compared. \
			 Run `make -C client tests/client_test`, or `make conformance`, which does."
		);

		let witness = std::fs::read_to_string(&witness_path).expect("the witness is readable");
		let mine = rust_facts(&witness);
		assert!(
			mine.contains("display=") && mine.contains("radio "),
			"this implementation produced no facts, so the comparison would be vacuous"
		);

		let dump =
			std::env::temp_dir().join(format!("ncfg-conformance-{}.facts", std::process::id()));
		let status = std::process::Command::new(&binary)
			.arg("--facts")
			.arg(&dump)
			.arg(&witness_path)
			.output()
			.expect("the C client's dump runs");
		assert!(status.status.success(), "the C dump failed");

		let theirs = std::fs::read_to_string(&dump).expect("the C dump is readable");
		let _ = std::fs::remove_file(&dump);

		if mine != theirs {
			let mut report = String::from("the two clients disagree:\n");
			for difference in mine
				.lines()
				.zip(theirs.lines())
				.filter(|(a, b)| a != b)
				.take(10)
			{
				report.push_str(&format!(
					"  rust: {}\n  c:    {}\n",
					difference.0, difference.1
				));
			}
			if mine.lines().count() != theirs.lines().count() {
				report.push_str(&format!(
					"  and they produced {} and {} lines\n",
					mine.lines().count(),
					theirs.lines().count()
				));
			}
			panic!("{report}");
		}
	}
}
