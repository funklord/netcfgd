#![forbid(unsafe_code)]

//! `ncfg`: read the config, see what would change, change it.
//!
//! The argument parsing is hand-written. `clap` is excellent and would be
//! several hundred kilobytes against a 400 KB nano budget, for a command set
//! this small -- section 6's size gate is the kind of constraint that has to
//! bind on the first binary or it never binds at all.

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

options:
  --config-dir PATH        default /etc/netcfgd, or $NCFG_CONFIG_DIR
  --run-dir PATH           default /run/netcfgd, or $NCFG_RUN_DIR
  --oneshot                apply once and exit; the default, there being no
                           daemon yet
  --json                   machine-readable output
  --confirm SECONDS        arm commit-confirm for this apply
  --allow-disruption IFACE consent to disrupting one guarded interface;
                           repeatable, and deliberately not a blanket --force
  -h, --help               this text

exit codes:
  0  the desired state was reached, or already held
  1  an action failed, or the config did not compile
  3  a guard refused a disruptive action; nothing else failed
";

fn main() -> ExitCode {
	let arguments: Vec<String> = std::env::args().skip(1).collect();
	match run(&arguments) {
		Ok(code) => code,
		Err(message) => {
			eprintln!("ncfg: {message}");
			ExitCode::from(1)
		}
	}
}

struct Options {
	config_dir: Option<String>,
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
		other => Err(format!("unknown command `{other}`; try `ncfg --help`")),
	}
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
	let mut options = Options {
		config_dir: None,
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
			"--run-dir" => options.run_dir = Some(take_value("--run-dir")?),
			"--confirm" => {
				let value = take_value("--confirm")?;
				options.confirm =
					Some(value.parse().map_err(|_| {
						format!("--confirm wants a number of seconds, not `{value}`")
					})?);
			}
			"--allow-disruption" => options
				.allow_disruption
				.push(take_value("--allow-disruption")?),
			"--json" => options.json = true,
			// There is no daemon yet, so oneshot is the only mode there is.
			// Accepting the flag now means the command line does not change
			// when the daemon lands in M2.
			"--oneshot" => {}
			other => return Err(format!("unknown option `{other}`")),
		}
		index += 1;
	}
	Ok(options)
}

/// Compile the config, and write the result where `cat` can reach it.
fn compile(options: &Options) -> Result<(netcfgd_model::Document, std::path::PathBuf), String> {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let run_dir = state::resolve_dir(options.run_dir.as_deref());

	let sources = config::load(&config_dir)
		.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;
	if sources.is_empty() {
		return Err(format!(
			"no configuration found in {}",
			config_dir.display()
		));
	}

	let mut sink = hooks::RunHooks::new(&run_dir);
	let document = netcfgd_compile::compile(&sources, &mut sink)
		.map_err(|diagnostics| diagnostics.render(&sources))?;

	Ok((document, run_dir))
}

fn observe(run_dir: &std::path::Path) -> Result<Observed, String> {
	let prior = state::read_owned(run_dir).to_prior();
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
	}
	Ok(ExitCode::SUCCESS)
}

fn command_apply(options: &Options) -> Result<ExitCode, String> {
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
		.map_err(|error| format!("could not open a netlink socket: {error}"))?;
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
