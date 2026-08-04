#![forbid(unsafe_code)]

//! Running an `OpenVPN` tunnel whose configuration netcfgd does not own.
//!
//! The shape differs from every other backend here in one way that decides
//! everything else. netcfgd generates hostapd's configuration and `pppd`'s
//! options file; it generates none of `OpenVPN`'s. `openvpn --help` lists **253
//! top-level options**, against a couple of dozen expressible keys for hostapd,
//! and a `.ovpn` is something an operator is *given* rather than a rendering of
//! an intent netcfgd holds. Decision 0046 has the argument; the consequence for
//! this crate is that it never opens the file.
//!
//! What it owns is the lifecycle: start the daemon, stop the one it started,
//! and say what the daemon said when it will not run.
//!
//! ## Stopped through the management socket
//!
//! `--management <path> unix` gives `OpenVPN` a line-oriented text protocol on a
//! unix **stream** socket, and `signal SIGTERM` over it stops the daemon. That
//! is the third daemon of this shape after `wpa_supplicant` and `hostapd`, and
//! decision 0014's reason for preferring it holds unchanged: an operator's own
//! `OpenVPN` tunnels are common, and killing a process found by name would reach
//! one netcfgd did not start.
//!
//! The socket is a stream where `wpa_ctrl` is a datagram, so this is a separate
//! client rather than a reuse of [`netcfgd_supplicant`]'s.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Where the management sockets and logs live.
///
/// Under netcfgd's own `/run` rather than `/run/openvpn`, for the reason
/// [`netcfgd_hostapd::ctrl_dir`](https://docs.rs/) gives about hostapd: a
/// socket in the distribution's location would be found by that distribution's
/// tooling, which would then be managing a tunnel netcfgd owns.
#[must_use]
pub fn run_dir(run_dir: &Path) -> PathBuf {
	run_dir.join("openvpn")
}

/// The management socket for one tunnel.
#[must_use]
pub fn socket_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.sock"))
}

/// Where the daemon's startup diagnostics go.
#[must_use]
pub fn log_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.log"))
}

/// Where the daemon writes its own pid, and the only handle netcfgd has when
/// the management socket is not answering.
///
/// **The socket is not always there.** `--daemon` means the invocation returns
/// as soon as openvpn forks, and the child binds its management socket a moment
/// later -- so a stop that arrives inside that window found nothing listening,
/// reported the tunnel stopped, and left a daemon running that netcfgd would
/// never speak to again. Measured: with a three-second gap between the fork and
/// the bind, `ncfg apply` printed `ok backend.stop vpn0` and then `nothing to
/// do`, with the tunnel still up. Decision 0074.
///
/// `--writepid` is openvpn's own option for this, so the file is the daemon's
/// claim about itself rather than netcfgd's guess -- which matters because the
/// pid netcfgd could observe is the parent that exits.
#[must_use]
pub fn pid_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.pid"))
}

/// Where netcfgd records the `.ovpn` it started this tunnel from.
///
/// A hash, not a copy. The file is the operator's and netcfgd does not read it
/// for meaning (decision 0046) -- but it can notice that it changed, which is
/// the same thing a hook's `sha256` does for a script netcfgd equally does not
/// interpret (section 2.2). Decision 0053 has the argument.
#[must_use]
pub fn config_hash_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.ovpn.sha256"))
}

/// The hash of a `.ovpn`, as netcfgd records and compares it.
///
/// `None` where the file cannot be read at all, which is the honest answer:
/// "the operator's file is not there" is a different statement from "it
/// changed", and only one of them is a reason to restart a working tunnel.
#[must_use]
pub fn hash_of(config: &str) -> Option<String> {
	std::fs::read(config)
		.ok()
		.map(|bytes| netcfgd_model::hash::sha256_hex(&bytes))
}

/// The script `OpenVPN` calls to say what it negotiated.
///
/// Generated rather than installed, for the same reason a hook is materialised
/// into `/run`: a path under `/usr` would have to be packaged, would not exist
/// on a read-only root that netcfgd was unpacked onto, and would be one more
/// thing that can be out of step with the binary that wrote it.
#[must_use]
pub fn script_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.report"))
}

/// The script's text, which is the whole of netcfgd's side of `--route-up`.
///
/// Pure, so that what a tunnel is told to do can be read without running one.
///
/// `report` is the file to write and is passed in rather than derived: the
/// layout of `/run` belongs to the caller, and a second crate spelling
/// `reported` for itself is how two spellings start.
///
/// ## Why a script at all
///
/// `openvpn --help` lists 253 options and decision 0046 keeps the `.ovpn` the
/// operator's, so netcfgd cannot read what the server pushed. It can be *told*:
/// `--route-noexec` stops the daemon installing routes, and `--route-up` runs
/// this with every route in the environment. What comes back goes through
/// `docs/interface-report.md`, the same contract a modem helper writes -- which
/// is why decision 0047 took the modem's name off it.
///
/// ## What the environment holds, measured rather than assumed
///
/// Against a real `openvpn` 2.6.14 in a network namespace, with a real `tun`:
///
/// - `route_network_N`, `route_netmask_N`, `route_gateway_N` for IPv4, with the
///   netmask dotted rather than a prefix length. `route_gateway_N` is filled in
///   even for a route the config gave no gateway -- it becomes the tunnel's own
///   endpoint.
/// - `route_ipv6_network_N` already in CIDR, with `route_ipv6_gateway_N`.
/// - `foreign_option_N` for everything the server said about resolvers, as
///   `dhcp-option DNS 10.0.0.53` and the like. **2.6's newer `--dns server`
///   syntax arrives in the same list**: on anything that is not Windows,
///   `foreign_options_copy_dns` rewrites it into `dhcp-option` form, so reading
///   one spelling reads both. A locally configured `dhcp-option` lands there
///   too, which is what lets a test exercise this without a server.
/// - Both **survive `--route-noexec`**, because the environment is filled in
///   when the route list is built and the flag only skips installing it.
/// - `N` is not guaranteed contiguous: `setenv_route` skips a route that is not
///   fully defined and the counter moves on regardless, so this scans a range
///   rather than stopping at the first gap.
///
/// ## The one thing that does not survive
///
/// **`redirect-gateway` for IPv4 leaves no trace in the environment.** The
/// 0.0.0.0/1 and 128.0.0.0/1 pair it installs is added inside `add_routes`,
/// which `--route-noexec` skips entirely, and the `redirect_gateway` variable
/// is set in the same skipped branch. The IPv6 half *does* survive, because
/// those four prefixes are appended to the option list before the route list is
/// built. Measured both ways; `docs/decisions/0048` says what to do about it.
#[must_use]
pub fn report_script(iface: &str, report: &Path) -> String {
	let report = report.display();
	let mask = mask_conversion();
	let routes = route_lines();
	let servers = server_lines();
	format!(
		"#!/bin/sh\n\
		 # Written by netcfgd for {iface}. Do not edit; it is rewritten on every\n\
		 # start, and openvpn is the only thing that runs it.\n\
		 #\n\
		 # Called twice over a tunnel's life: as --route-up once the routes\n\
		 # openvpn was told not to install are known, and as --down when the\n\
		 # tunnel goes. docs/interface-report.md is the format.\n\
		 set -u\n\
		 \n\
		 target='{report}'\n\
		 tmp=\"$target.tmp\"\n\
		 dir=$(dirname \"$target\")\n\
		 mkdir -p \"$dir\" || exit 1\n\
		 \n\
		 # The tunnel is gone, so the routes are. Emptied rather than removed:\n\
		 # the contract makes an empty report mean \"nothing, deliberately\" and\n\
		 # a missing one mean \"nobody is watching\", and openvpn running its\n\
		 # down script is somebody watching.\n\
		 if [ \"${{script_type:-}}\" = down ]; then\n\
		 \t: > \"$tmp\" && mv \"$tmp\" \"$target\"\n\
		 \texit 0\n\
		 fi\n\
		 \n\
		 {mask}\n\
		 {{\n\
		 \tprintf '# %s, written by netcfgd from openvpn --route-up\\n' '{iface}'\n\
		 {routes}\
		 {servers}\
		 }} > \"$tmp\" || exit 1\n\
		 mv \"$tmp\" \"$target\"\n"
	)
}

/// The one piece of arithmetic: `255.255.255.0` becomes `24`.
///
/// openvpn hands IPv4 netmasks dotted and IPv6 prefixes already in CIDR, which
/// is its asymmetry rather than netcfgd's. A mask with a hole in it fails
/// rather than summing to a number that means something else -- the kernel
/// would refuse such a route anyway, and skipping it here leaves the line it
/// came from visible in the log.
fn mask_conversion() -> String {
	"prefix_of() {\n\
	 \ttotal=0\n\
	 \tended=\n\
	 \tfor octet in $(printf '%s' \"$1\" | tr '.' ' '); do\n\
	 \t\tcase \"$octet\" in\n\
	 \t\t255) bits=8 ;;\n\
	 \t\t254) bits=7 ;;\n\
	 \t\t252) bits=6 ;;\n\
	 \t\t248) bits=5 ;;\n\
	 \t\t240) bits=4 ;;\n\
	 \t\t224) bits=3 ;;\n\
	 \t\t192) bits=2 ;;\n\
	 \t\t128) bits=1 ;;\n\
	 \t\t0) bits=0 ;;\n\
	 \t\t*) return 1 ;;\n\
	 \t\tesac\n\
	 \t\t[ -n \"$ended\" ] && [ \"$bits\" != 0 ] && return 1\n\
	 \t\t[ \"$bits\" = 8 ] || ended=yes\n\
	 \t\ttotal=$((total + bits))\n\
	 \tdone\n\
	 \tprintf '%s' \"$total\"\n\
	 }\n"
	.to_owned()
}

/// Both families of route, out of the environment openvpn filled in.
///
/// A fixed range rather than a break on the first gap: `setenv_route` skips a
/// route it did not fully define and the counter moves on anyway, so the
/// numbering has holes in it.
fn route_lines() -> String {
	"\ti=1\n\
	 \twhile [ \"$i\" -le 256 ]; do\n\
	 \t\teval \"network=\\${route_network_$i:-}\"\n\
	 \t\teval \"netmask=\\${route_netmask_$i:-}\"\n\
	 \t\teval \"gateway=\\${route_gateway_$i:-}\"\n\
	 \t\ti=$((i + 1))\n\
	 \t\t[ -n \"$network\" ] || continue\n\
	 \t\tprefix=$(prefix_of \"$netmask\") || continue\n\
	 \t\tif [ -n \"$gateway\" ]; then\n\
	 \t\t\tprintf 'route=%s/%s via %s\\n' \"$network\" \"$prefix\" \"$gateway\"\n\
	 \t\telse\n\
	 \t\t\tprintf 'route=%s/%s\\n' \"$network\" \"$prefix\"\n\
	 \t\tfi\n\
	 \tdone\n\
	 \ti=1\n\
	 \twhile [ \"$i\" -le 256 ]; do\n\
	 \t\teval \"network=\\${route_ipv6_network_$i:-}\"\n\
	 \t\teval \"gateway=\\${route_ipv6_gateway_$i:-}\"\n\
	 \t\ti=$((i + 1))\n\
	 \t\t[ -n \"$network\" ] || continue\n\
	 \t\tif [ -n \"$gateway\" ]; then\n\
	 \t\t\tprintf 'route=%s via %s\\n' \"$network\" \"$gateway\"\n\
	 \t\telse\n\
	 \t\t\tprintf 'route=%s\\n' \"$network\"\n\
	 \t\tfi\n\
	 \tdone\n"
		.to_owned()
}

/// The nameservers, and the two things a server does not get to decide.
///
/// openvpn folds both the old `dhcp-option DNS` and 2.6's `--dns server` into
/// one `foreign_option` list on anything that is not Windows, so reading one
/// spelling reads both.
///
/// `DOMAIN` and `DOMAIN-SEARCH` are reported as **search suffixes**, which is
/// decision 0067 splitting 0049 in two: what to append to a bare name is the
/// weaker half and travels under the same gate as a nameserver, while *which
/// names go through this tunnel* is a routing domain, is the operator's to say
/// in the document, and has no report key at all. This comment said the
/// opposite for as long as 0067 had been in -- written true, left standing, and
/// with a live check beside it that had been red on every machine with openvpn
/// installed and green everywhere else, because `tunnel.sh` skips without it.
///
/// Everything else openvpn's server suggested becomes a comment: declined, and
/// visible to whoever reads the file rather than silently dropped.
fn server_lines() -> String {
	"\ti=1\n\
	 \twhile [ \"$i\" -le 256 ]; do\n\
	 \t\teval \"option=\\${foreign_option_$i:-}\"\n\
	 \t\ti=$((i + 1))\n\
	 \t\t[ -n \"$option\" ] || continue\n\
	 \t\tset -- $option\n\
	 \t\t[ \"${1:-}\" = dhcp-option ] || continue\n\
	 \t\tcase \"${2:-}\" in\n\
	 \t\tDNS|DNS6) [ -n \"${3:-}\" ] && printf 'dns=%s\\n' \"$3\" ;;\n\
	 \t\tDOMAIN|DOMAIN-SEARCH)\n\
	 \t\t\tshift 2\n\
	 \t\t\tfor suffix in \"$@\"; do\n\
	 \t\t\t\t[ -n \"$suffix\" ] && printf 'search=%s\\n' \"$suffix\"\n\
	 \t\t\tdone\n\
	 \t\t\t;;\n\
	 \t\t*) printf '# the server also said: %s\\n' \"$option\" ;;\n\
	 \t\tesac\n\
	 \tdone\n"
		.to_owned()
}

/// Where the credentials for one tunnel go, when the server wants any.
///
/// Mode 0600 and under `/run`, which is the same trade the generated hostapd
/// configuration and the `pppd` options file already make and comes with the
/// same mitigations: `/run` is tmpfs so it does not survive a reboot, and the
/// document itself still carries only a `SecretRef` (constraint 5). `OpenVPN` has
/// no indirection for a password either -- `--auth-user-pass` takes a file with
/// the username on the first line and the password on the second, and there is
/// no other way in.
#[must_use]
pub fn auth_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.auth"))
}

/// Write the credentials file, or remove it when the document carries none.
///
/// # Errors
///
/// Returns a message naming the file that could not be written.
fn write_auth(run: &Path, iface: &str, username: &str, password: &str) -> Result<PathBuf, String> {
	use std::os::unix::fs::OpenOptionsExt;

	let path = auth_path(run, iface);
	// The mode is set at open rather than afterwards. A chmod after the write
	// leaves a window in which the password is world-readable, and a mode that
	// was wrong once is a mode that was wrong.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.open(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	// Exactly two lines, which is what `--auth-user-pass` reads. A username
	// containing a newline would become a password line; nothing in the model
	// stops one, so it is stopped here.
	if username.contains('\n') || password.contains('\n') {
		return Err(format!(
			"the openvpn credentials for {iface} contain a newline, which would be read 			 as a different field"
		));
	}
	file.write_all(format!("{username}\n{password}\n").as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	Ok(path)
}

/// Write the reporting script, executable, next to the tunnel's other state.
///
/// # Errors
///
/// Returns a message naming the file that could not be written.
fn write_script(run: &Path, iface: &str, report: &Path) -> Result<PathBuf, String> {
	use std::os::unix::fs::PermissionsExt;

	let path = script_path(run, iface);
	std::fs::write(&path, report_script(iface, report))
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	// Rewritten on every start rather than written once: it carries the
	// interface name and the report path, and a tunnel renamed in the document
	// would otherwise keep reporting under the old name.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
		.map_err(|error| format!("cannot make {} executable: {error}", path.display()))?;
	Ok(path)
}

/// Find `openvpn`.
///
/// The same search as hostapd's and for the same reason: it lives in
/// `/usr/sbin`, which is not on a non-root `PATH` on Debian and several others.
///
/// `NCFG_OPENVPN` overrides it, in the same family as `NCFG_WPA_CTRL_DIR` and
/// `NCFG_RESOLV_CONF` and for the same reason: a test needs to point at
/// something that is not the real one. **This one is not a convenience.**
/// Searching `sbin` before `PATH` is right for netcfgd and means a fake cannot
/// be injected on `PATH` at all -- so `tests/live/openvpn.sh`, which fakes the
/// daemon to check the command line netcfgd builds, was silently exercising
/// the *real* openvpn on every machine that had it installed, and failing 20
/// of its 45 checks. It passed here only because this machine has no openvpn
/// (0101).
#[must_use]
pub fn binary() -> Option<PathBuf> {
	if let Some(path) = std::env::var_os("NCFG_OPENVPN") {
		let path = PathBuf::from(path);
		return path.is_file().then_some(path);
	}
	for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] {
		let path = Path::new(dir).join("openvpn");
		if path.is_file() {
			return Some(path);
		}
	}
	std::env::var_os("PATH").and_then(|paths| {
		std::env::split_paths(&paths)
			.map(|dir| dir.join("openvpn"))
			.find(|path| path.is_file())
	})
}

/// Start the tunnel described by `config`, which is a path netcfgd hands over
/// unread.
///
/// # Errors
///
/// Returns a message naming what failed: no openvpn installed, a configuration
/// file that is not there, or the daemon refusing to start -- quoting what it
/// said rather than its exit status.
pub fn start(
	run: &Path,
	iface: &str,
	config: &str,
	credentials: Option<(&str, &str)>,
	report: &Path,
) -> Result<(), String> {
	let dir = run_dir(run);
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;

	// Checked here rather than left to openvpn, only because the error is so
	// much better: netcfgd knows the path came from a document and can say so,
	// where openvpn says "Options error" against a file the operator may not
	// realise netcfgd chose.
	if !Path::new(config).is_file() {
		return Err(format!(
			"the openvpn configuration for {iface} is `{config}`, and there is no file there"
		));
	}

	let program = binary().ok_or_else(|| {
		format!("no openvpn found for {iface}; a tunnel needs the openvpn package")
	})?;

	let socket = socket_path(run, iface);
	// A socket left by a daemon that died takes the bind, and openvpn does not
	// clear it. Removing it here is safe because `stop` has already been asked
	// of anything netcfgd started.
	let _ = std::fs::remove_file(&socket);

	let log = log_path(run, iface);
	let capture = std::fs::File::create(&log)
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;
	let errors = capture
		.try_clone()
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;

	// Whatever the last tunnel negotiated is not what this one will. Removed
	// before the daemon starts rather than after it connects, because between
	// those two moments netcfgd would otherwise be installing the previous
	// tunnel's routes down the new one.
	let _ = std::fs::remove_file(report);
	let script = write_script(run, iface, report)?;

	let auth = match credentials {
		Some((username, password)) => Some(write_auth(run, iface, username, password)?),
		// No credentials in the document. Left to the `.ovpn`, which for a file
		// with inline certificates authenticates without any -- and removed if
		// an earlier configuration had some, so a password does not outlive the
		// document that asked for it.
		None => {
			let _ = std::fs::remove_file(auth_path(run, iface));
			None
		}
	};

	let mut command = Command::new(&program);
	command
		.arg("--config")
		.arg(config)
		// The interface name is netcfgd's to choose, not the file's: the
		// document says `interface vpn0`, and a `.ovpn` that named something
		// else would produce a tunnel no plan could find.
		.arg("--dev")
		.arg(iface)
		.arg("--management")
		.arg(&socket)
		.arg("unix")
		// So the apply does not block. A tunnel can take seconds to negotiate,
		// and the interface arriving later is already how a PPPoE session
		// behaves -- the planner gets there on the next reconcile.
		.arg("--daemon")
		.arg(format!("netcfgd-{iface}"))
		// So there is a handle when the management socket is not answering --
		// which is every moment between the fork this returns from and the bind
		// its child gets round to. See `pid_path` and decision 0074.
		.arg("--writepid")
		.arg(pid_path(run, iface))
		.arg("--log")
		.arg(&log)
		// The routes are netcfgd's, which is the half of a tunnel decision 0047
		// says is worth taking: a daemon installing its own default route walks
		// into the middle of netcfgd's uplink arbitration with a metric netcfgd
		// did not choose, and neither side knows the other is there.
		.arg("--route-noexec")
		// Without this openvpn runs no script at all and says so once, at
		// verb 1, in a log nobody reads -- the routes would simply never be
		// reported and nothing would fail. It is the default in 2.6, checked in
		// `run_command.c`: `script_security_level` starts at `SSEC_BUILT_IN`.
		.arg("--script-security")
		.arg("2")
		.arg("--route-up")
		.arg(&script)
		// The same script, told apart by `script_type`. `--down` rather than
		// `--route-pre-down`, which openvpn only runs when a route list exists
		// -- a tunnel that pushed nothing would then leave its report behind.
		.arg("--down")
		.arg(&script)
		.stdout(capture)
		.stderr(errors);
	if let Some(auth) = &auth {
		// The path, never the values. A password on a command line is readable
		// by every process on the machine through /proc.
		command.arg("--auth-user-pass").arg(auth);
	}
	let status = command
		.status()
		.map_err(|error| format!("could not run {}: {error}", program.display()))?;

	// What the tunnel was started from, so that an edited `.ovpn` is something
	// the next reconcile can notice. Written after the daemon took it, because
	// a hash of a file openvpn refused is a record of nothing.
	if status.success() {
		if let Some(hash) = hash_of(config) {
			let _ = std::fs::write(config_hash_path(run, iface), hash);
		}
	}

	if !status.success() {
		return Err(format!(
			"openvpn would not start on {iface}: {}. Its output is in {}",
			complaints(&log, 2).unwrap_or_else(|| format!("it exited with {status}")),
			log.display()
		));
	}
	Ok(())
}

/// Stop the tunnel on one interface.
///
/// # Errors
///
/// Returns a message if the daemon is listening and will not stop. Nothing
/// listening is the state this was asked to produce, so that is success.
pub fn stop(run: &Path, iface: &str, report: &Path) -> Result<(), String> {
	// Before the signal, and outside the "is anything listening" question. A
	// report is a claim that routes exist, and the tunnel they belong to is
	// going either way -- a daemon that already died is exactly the case where
	// nobody comes back to tidy up, which is the lesson a stopped access
	// point's passphrase paid for.
	//
	// The daemon's own `--down` script may still write an empty report after
	// this, because openvpn runs it when it gets round to exiting. That is a
	// race with no wrong outcome: gone and empty both mean no routes, and the
	// contract gives them both that meaning deliberately.
	let _ = std::fs::remove_file(report);
	// And the record of which `.ovpn` this was started from, which describes a
	// tunnel that is no longer running.
	let _ = std::fs::remove_file(config_hash_path(run, iface));
	// The script itself stays. It is regenerated on every start, it does
	// nothing unless openvpn runs it, and removing it here would pull it out
	// from under the `--down` call that has not happened yet -- which openvpn
	// would report as a failed script in a log an operator then has to explain.

	let socket = socket_path(run, iface);
	let Ok(mut client) = Management::connect(&socket) else {
		// Nothing is listening, which used to end the matter -- and did so
		// wrongly for a daemon that had forked and not yet bound. So the pid it
		// was told to write is asked next, and only a daemon that is neither
		// reachable nor running counts as already stopped. Decision 0074.
		return stop_by_pid(run, iface);
	};
	client
		.command("signal SIGTERM")
		.map_err(|error| format!("could not stop the openvpn tunnel on {iface}: {error}"))?;
	let _ = std::fs::remove_file(pid_path(run, iface));
	// The daemon removes its own socket on the way out, but only if it got far
	// enough to install the handler. Left behind, it would take the bind on the
	// next start.
	let _ = std::fs::remove_file(&socket);
	// And the credentials, which have nothing left to authenticate. `/run` is
	// tmpfs so they would go at the next reboot regardless, but a password
	// sitting beside a tunnel that is not running is one nobody is watching.
	let _ = std::fs::remove_file(auth_path(run, iface));
	Ok(())
}

/// Stop a daemon that is not answering its socket, by the pid it wrote.
///
/// The pid is checked against `/proc/<pid>/cmdline` before anything is
/// signalled, and against **this interface's own socket path** rather than the
/// interface name alone: `vpn0` is a short string that a wholly unrelated
/// command line could contain, where the socket path is unique to this tunnel
/// on this machine. That is the same reasoning `pppd_pid` and the `DHCP`
/// clients use, one notch stricter because the argument here is a path netcfgd
/// chose.
///
/// A pid file naming nothing, or naming something that is not this tunnel, is
/// removed and reported as stopped -- which is the state the caller asked for
/// and is what "stopping one that is already stopped is not an error" means.
fn stop_by_pid(run: &Path, iface: &str) -> Result<(), String> {
	let path = pid_path(run, iface);
	let socket = socket_path(run, iface);
	let Some(pid) = netcfgd_sys::process::pid_of(&path, &socket.to_string_lossy()) else {
		// No file, no number, no such process, or a process that is not this
		// tunnel -- all of which mean there is nothing here to stop.
		let _ = std::fs::remove_file(&path);
		return Ok(());
	};
	netcfgd_sys::process::terminate(pid).map_err(|error| {
		format!("could not stop the openvpn tunnel on {iface} (pid {pid}): {error}")
	})?;
	let _ = std::fs::remove_file(&path);
	let _ = std::fs::remove_file(auth_path(run, iface));
	Ok(())
}

/// A connection to one tunnel's management socket.
pub struct Management {
	stream: UnixStream,
}

impl Management {
	/// How long to wait for the daemon to answer.
	///
	/// Short, and for the reason `netcfgd_hostapd::acl::read`'s is: this runs
	/// where an apply is waiting, and the daemon is answering from memory. A
	/// tunnel that has wedged should not hold the executor.
	const TIMEOUT: Duration = Duration::from_secs(2);

	/// Open the management socket.
	///
	/// # Errors
	///
	/// Returns an error when nothing is listening, which is the ordinary case
	/// for a tunnel that is not running.
	pub fn connect(path: &Path) -> std::io::Result<Self> {
		let stream = UnixStream::connect(path)?;
		stream.set_read_timeout(Some(Self::TIMEOUT))?;
		stream.set_write_timeout(Some(Self::TIMEOUT))?;
		Ok(Self { stream })
	}

	/// Send one command and read until the daemon answers it.
	///
	/// `OpenVPN` greets a new client with `>INFO:` before it is asked anything,
	/// and emits further `>`-prefixed notifications whenever it likes,
	/// interleaved with replies. Reading the first line as the answer is the
	/// classic bug in a management client and produces a stop that silently did
	/// nothing -- the same failure `netcfgd_supplicant`'s client documents for
	/// `wpa_ctrl` events, arrived at independently because both protocols made
	/// the same choice.
	///
	/// Skipping them needs no test for `>`: reading until a line *is* an answer
	/// passes over anything that is not one, and a `>` branch on top would be a
	/// guard clause no input could make fire. The guarantee is pinned by
	/// `tests/live/openvpn.sh`, whose fake sends the greeting first, rather
	/// than by a line of code that looks like it is doing the work.
	///
	/// # Errors
	///
	/// Returns an error on a socket failure, a timeout, or an `ERROR:` reply.
	pub fn command(&mut self, command: &str) -> std::io::Result<String> {
		writeln!(self.stream, "{command}")?;
		self.stream.flush()?;

		let reader = BufReader::new(self.stream.try_clone()?);
		for line in reader.lines() {
			let line = line?;
			let line = line.trim_end();
			if let Some(rest) = line.strip_prefix("SUCCESS: ") {
				return Ok(rest.to_owned());
			}
			if let Some(rest) = line.strip_prefix("ERROR: ") {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					format!("openvpn refused `{command}`: {rest}"),
				));
			}
		}
		Err(std::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			format!("no answer to `{command}`"),
		))
	}
}

/// The lines of a log that say what went wrong, for an error message.
///
/// The same problem and the same answer as hostapd's: a daemon that fails
/// announces the reason and then narrates its shutdown, so the tail is the
/// wrong lines. `OpenVPN`'s own vocabulary for the two failures that matter is
/// `Options error:` for a configuration it will not take and `Cannot` or
/// `Could not` for a file or a socket it cannot have.
fn complaints(path: &Path, count: usize) -> Option<String> {
	let text = std::fs::read_to_string(path).ok()?;
	let lines: Vec<&str> = text
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty())
		.collect();
	if lines.is_empty() {
		return None;
	}
	let telling: Vec<&str> = lines
		.iter()
		.filter(|line| {
			let lowered = line.to_lowercase();
			["options error", "error:", "cannot", "could not", "fatal"]
				.iter()
				.any(|marker| lowered.contains(marker))
		})
		.take(count)
		.copied()
		.collect();
	let chosen = if telling.is_empty() {
		lines[lines.len().saturating_sub(count)..].to_vec()
	} else {
		telling
	};
	Some(chosen.join("; ").trim_end_matches('.').to_owned())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The generated script has to be a shell script.
	///
	/// It is written into `/run` and run by openvpn rather than by anything in
	/// this repository, so `make shell` cannot see it: that gate reads
	/// `helpers/` and `tests/live/`, and a syntax error here would first be
	/// noticed as a tunnel that reports nothing. `sh -n` costs a fork.
	#[test]
	fn the_script_parses() {
		let script = report_script("vpn0", Path::new("/run/netcfgd/reported/vpn0"));
		let dir = netcfgd_testdir::TestDir::new("script");
		let path = dir.join("report.sh");
		std::fs::write(&path, &script).expect("write");

		let status = Command::new("sh")
			.arg("-n")
			.arg(&path)
			.status()
			.expect("run sh -n");
		assert!(
			status.success(),
			"the generated script does not parse:\n{script}"
		);
	}

	/// It converts what openvpn actually hands it.
	///
	/// The environment here is copied from a real `openvpn` 2.6.14 run under
	/// `--route-noexec`: a dotted netmask, a gateway openvpn filled in for a
	/// route that named none, an explicit gateway on the second, and an IPv6
	/// route already in CIDR. Running the script is the only way to check the
	/// mask conversion without a tunnel.
	#[test]
	fn it_writes_what_openvpn_put_in_its_environment() {
		let dir = netcfgd_testdir::TestDir::new("report");
		let report = dir.join("vpn0");
		let path = dir.join("report.sh");
		std::fs::write(&path, report_script("vpn0", &report)).expect("write");

		let status = Command::new("sh")
			.arg(&path)
			.env("script_type", "route-up")
			// Both spellings of a nameserver, and the two the server does not
			// get to decide -- copied from a real openvpn's environment.
			.env("foreign_option_1", "dhcp-option DNS 10.0.0.53")
			.env("foreign_option_2", "dhcp-option DNS6 fd00::53")
			.env("foreign_option_3", "dhcp-option DOMAIN corp.example")
			.env(
				"foreign_option_4",
				"dhcp-option DOMAIN-SEARCH sub.corp.example",
			)
			// Something the contract has no key for at all, so the comment path
			// still has a subject: without one, deleting it would leave every
			// assertion here passing.
			.env("foreign_option_5", "dhcp-option WINS 10.0.0.7")
			.env("route_network_1", "10.9.0.0")
			.env("route_netmask_1", "255.255.255.0")
			.env("route_gateway_1", "10.8.0.2")
			.env("route_network_2", "10.10.0.0")
			.env("route_netmask_2", "255.255.0.0")
			.env("route_gateway_2", "192.168.99.1")
			// A mask with a hole in it, which the kernel would refuse and which
			// is better dropped here where the rest of the report survives.
			.env("route_network_3", "10.11.0.0")
			.env("route_netmask_3", "255.0.255.0")
			.env("route_gateway_3", "10.8.0.2")
			.env("route_ipv6_network_1", "fd77::/32")
			.env("route_ipv6_gateway_1", "fd00::2")
			.status()
			.expect("run the script");
		assert!(status.success());

		let written = std::fs::read_to_string(&report).expect("a report");
		let routes: Vec<&str> = written
			.lines()
			.filter(|line| line.starts_with("route="))
			.collect();
		assert_eq!(
			routes,
			[
				"route=10.9.0.0/24 via 10.8.0.2",
				"route=10.10.0.0/16 via 192.168.99.1",
				"route=fd77::/32 via fd00::2"
			],
			"got:\n{written}"
		);

		// Both families of nameserver, and both spellings of a search suffix --
		// which is what `DOMAIN` and `DOMAIN-SEARCH` are on the wire (0067). A
		// *routing* domain is still refused and still has no key: 0049 stands, and
		// the assertion below says so.
		let servers: Vec<&str> = written
			.lines()
			.filter(|line| line.starts_with("dns="))
			.collect();
		assert_eq!(
			servers,
			["dns=10.0.0.53", "dns=fd00::53"],
			"got:\n{written}"
		);
		let suffixes: Vec<&str> = written
			.lines()
			.filter(|line| line.starts_with("search="))
			.collect();
		assert_eq!(
			suffixes,
			["search=corp.example", "search=sub.corp.example"],
			"got:\n{written}"
		);
		assert!(
			!written.contains("domain="),
			"a pushed domain is not a key this contract has:\n{written}"
		);
		// And what the contract has no key for at all is still visible as a
		// comment, which netcfgd's reader drops and a person reading the file does
		// not.
		assert!(
			written.contains("# the server also said: dhcp-option WINS 10.0.0.7"),
			"what was declined should still be visible:\n{written}"
		);
	}

	/// The tunnel going down empties the report rather than removing it, which
	/// is the difference the contract draws between "nothing, deliberately" and
	/// "nobody is watching".
	#[test]
	fn the_down_call_empties_it() {
		let dir = netcfgd_testdir::TestDir::new("down");
		let report = dir.join("vpn0");
		std::fs::write(&report, "route=10.0.0.0/8 via 10.8.0.1\n").expect("a stale report");
		let path = dir.join("report.sh");
		std::fs::write(&path, report_script("vpn0", &report)).expect("write");

		let status = Command::new("sh")
			.arg(&path)
			.env("script_type", "down")
			.status()
			.expect("run the script");
		assert!(status.success());

		let written = std::fs::read_to_string(&report).expect("a report");
		assert_eq!(
			written, "",
			"a down call leaves an empty report, not a gone one"
		);
	}
}
