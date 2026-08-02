#![forbid(unsafe_code)]

//! Router advertisement, which netcfgd configures and does not send.
//!
//! Design section 1.5 keeps netcfgd off the wire: it does not speak DHCP, it
//! does not speak EAP, and it does not send router advertisements either. What
//! it does is decide *what* should be advertised and hand that to a daemon --
//! the same split decision 0026 made for hostapd, and for the same reason. An
//! RA is a packet a host on the LAN acts on without asking, and a program that
//! composes those is a program with a parser and a timer loop facing a network,
//! which is exactly the surface this project is arranged to avoid.
//!
//! ## Which daemon, and what each is told
//!
//! `radvd` here. `odhcpd` is the `OpenWrt` one and is not implemented in this
//! build -- it is refused by name rather than silently substituted, because the
//! two take entirely different configuration and a document that names one and
//! gets the other is a document that stopped describing the system.
//!
//! ## Where the prefix comes from
//!
//! Never from this crate. `RaPolicy::prefixes` is a list of [`PrefixRef`], and
//! decision 0009 makes that an indirection the *document* resolves: a router
//! advertising the /64 it carved out of an ISP's delegation is advertising
//! something no config file could have contained. The caller resolves the
//! references and passes the prefixes it derived, so this renders values and
//! looks nothing up.
//!
//! [`PrefixRef`]: netcfgd_model::PrefixRef

use netcfgd_model::interface::{RaBackend, RaPolicy};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the generated configuration and the pid file live.
///
/// Under netcfgd's own `/run` rather than `/etc/radvd.conf`, for the reason
/// hostapd's is: a file in the distribution's location would be found by that
/// distribution's tooling, which would then be managing an advertisement
/// netcfgd owns.
#[must_use]
pub fn run_dir(run: &Path) -> PathBuf {
	run.join("radvd")
}

/// The configuration for one advertising interface.
#[must_use]
pub fn config_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.conf"))
}

/// Where radvd records its own pid.
///
/// radvd has no control socket, so this is how the one netcfgd started is
/// stopped -- the same shape `pppd` forced, and with the same discipline: the
/// pid is checked against `/proc/<pid>/cmdline` before anything is signalled.
#[must_use]
pub fn pid_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.pid"))
}

/// Where the daemon's startup diagnostics go.
#[must_use]
pub fn log_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.log"))
}

/// The configuration radvd reads, from a policy and the prefixes it names.
///
/// Pure, so what is advertised can be checked without sending anything -- and
/// `radvd --configtest` will parse this same text, which is the check that
/// matters most (`tests/live/advertise.sh`).
///
/// `AdvSendAdvert on` is the whole point of the file and is not a knob: an
/// interface netcfgd was told to advertise on is one it advertises on. What the
/// document does control is the two flags that send hosts to a `DHCPv6` server
/// (`managed`, `other_config`), the lifetime, and whether the nameservers the
/// LAN's own DNS scope carries go out as `RDNSS`.
///
/// A prefix is advertised `AdvOnLink on; AdvAutonomous on;` -- the combination
/// that makes a host both treat it as local and configure an address from it,
/// which is the only combination that makes a delegated prefix useful to the
/// hosts behind the router. Anything narrower would be a knob nobody asked for.
#[must_use]
pub fn render(iface: &str, policy: &RaPolicy, prefixes: &[String], servers: &[String]) -> String {
	let mut out = format!(
		"# Written by netcfgd for {iface}. Do not edit; it is rewritten on apply.\n\
		 interface {iface}\n\
		 {{\n\
		 \tAdvSendAdvert on;\n\
		 \tAdvManagedFlag {managed};\n\
		 \tAdvOtherConfigFlag {other};\n",
		managed = on_off(policy.managed),
		other = on_off(policy.other_config),
	);
	if let Some(lifetime) = policy.lifetime {
		// The router's own lifetime as a default gateway. Zero is meaningful
		// and is how a host is told this router is not one -- so it is passed
		// through rather than treated as "unset".
		out.push_str(&format!("\tAdvDefaultLifetime {lifetime};\n"));
	}
	for prefix in prefixes {
		out.push_str(&format!(
			"\tprefix {prefix}\n\
			 \t{{\n\
			 \t\tAdvOnLink on;\n\
			 \t\tAdvAutonomous on;\n\
			 \t}};\n"
		));
	}
	if policy.dns && !servers.is_empty() {
		out.push_str(&format!("\tRDNSS {} {{ }};\n", servers.join(" ")));
	}
	out.push_str("};\n");
	out
}

fn on_off(value: bool) -> &'static str {
	if value {
		"on"
	} else {
		"off"
	}
}

/// Find `radvd`.
///
/// The same search as hostapd's and for the same reason: it lives in
/// `/usr/sbin`, which is not on a non-root `PATH` on Debian and several others.
#[must_use]
pub fn binary() -> Option<PathBuf> {
	for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] {
		let path = Path::new(dir).join("radvd");
		if path.is_file() {
			return Some(path);
		}
	}
	std::env::var_os("PATH").and_then(|paths| {
		std::env::split_paths(&paths)
			.map(|dir| dir.join("radvd"))
			.find(|path| path.is_file())
	})
}

/// Start advertising on one interface.
///
/// # Errors
///
/// Returns a message naming what failed: a backend this build does not
/// implement, no radvd installed, a policy with no prefix to advertise, or
/// radvd refusing the configuration -- quoting what it said.
pub fn start(
	run: &Path,
	iface: &str,
	policy: &RaPolicy,
	prefixes: &[String],
	servers: &[String],
) -> Result<(), String> {
	match policy.backend {
		RaBackend::Auto | RaBackend::Radvd => {}
		RaBackend::Odhcpd => {
			return Err(format!(
				"`{iface}` asks for the odhcpd backend, which this build does not \
				 implement. odhcpd takes entirely different configuration from radvd, \
				 so netcfgd will not quietly hand it radvd's -- name `radvd`, or leave \
				 the backend unset and netcfgd will use whichever is installed"
			))
		}
		RaBackend::Exec(ref command) => {
			return Err(format!(
				"`{iface}` asks for `{command}` to advertise, which this build does not \
				 implement"
			))
		}
	}

	// A policy with nothing to advertise would produce a file radvd accepts and
	// an advertisement that configures nobody -- an RA with no prefix still
	// makes the router a default gateway, which is a thing to ask for
	// deliberately rather than to arrive at by a reference that resolved to
	// nothing. The usual cause is a delegation that has not come back yet.
	if prefixes.is_empty() {
		return Err(format!(
			"`{iface}` advertises no prefix: every reference in its `advertise` block \
			 resolved to nothing, which usually means the delegation it names has not \
			 arrived. Nothing is advertised until one has"
		));
	}

	let dir = run_dir(run);
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
	let path = config_path(run, iface);
	std::fs::write(&path, render(iface, policy, prefixes, servers))
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;

	let program = binary().ok_or_else(|| {
		format!("no radvd found for {iface}; advertising needs the radvd package")
	})?;

	let log = log_path(run, iface);
	let capture = std::fs::File::create(&log)
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;
	let errors = capture
		.try_clone()
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;

	let status = Command::new(&program)
		.arg("--config")
		.arg(&path)
		.arg("--pidfile")
		.arg(pid_path(run, iface))
		// Its own file rather than syslog, so the reason an advertisement did
		// not start is readable after the fact on a machine with no syslog at
		// all -- which is the embedded case this project is built for.
		.arg("--logmethod")
		.arg("stderr")
		.stdout(capture)
		.stderr(errors)
		.status()
		.map_err(|error| format!("could not run {}: {error}", program.display()))?;

	if !status.success() {
		return Err(format!(
			"radvd would not start on {iface}: {}. Its output is in {}",
			complaints(&log, 2).unwrap_or_else(|| format!("it exited with {status}")),
			log.display()
		));
	}
	Ok(())
}

/// Rewrite the configuration and tell a running radvd to re-read it.
///
/// radvd handles `SIGHUP` by calling `reload_config`, which re-reads the file
/// it was started with -- checked in radvd 2.20's own `radvd.c` rather than
/// taken from the manual page, which does not mention it. So a changed prefix
/// costs nothing on the wire: the daemon keeps running, nothing is
/// deauthenticated, and the next advertisement carries the new block. That is
/// the opposite of an access point, where the same question means a restart
/// (decision 0026), and it is worth knowing which of the two a backend is.
///
/// Rewriting before signalling is the order that matters: radvd reads the file
/// when it is told to, so a signal sent first would reload the old contents.
///
/// # Errors
///
/// Returns a message naming what failed. A daemon that is not running is *not*
/// success here: `start` is what a stopped daemon needs, and quietly doing
/// nothing would leave the document and the wire disagreeing with nothing to
/// say so.
pub fn reload(
	run: &Path,
	iface: &str,
	policy: &RaPolicy,
	prefixes: &[String],
	servers: &[String],
) -> Result<(), String> {
	if prefixes.is_empty() {
		return Err(format!(
			"`{iface}` would advertise no prefix after the change, which is not \
			 something to reload into -- stop advertising instead"
		));
	}
	let Some(pid) = running_pid(run, iface) else {
		return Err(format!(
			"no radvd of netcfgd's is running on {iface} to reload; it has to be \
			 started rather than reloaded"
		));
	};
	let path = config_path(run, iface);
	std::fs::write(&path, render(iface, policy, prefixes, servers))
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	netcfgd_sys::process::hangup(pid)
		.map_err(|error| format!("could not tell radvd on {iface} to re-read: {error}"))
}

/// Stop advertising on one interface.
///
/// radvd has no control socket, so this is the `pppd` shape: read the pid file
/// radvd wrote for this interface, check `/proc/<pid>/cmdline` names the
/// configuration netcfgd generated, and only then signal it. An operator's own
/// radvd cannot match that, which is a stronger claim than "not by name".
///
/// # Errors
///
/// Returns a message if the process is there and will not stop. Nothing running
/// is the state this was asked to produce, so that is success.
pub fn stop(run: &Path, iface: &str) -> Result<(), String> {
	let Some(pid) = running_pid(run, iface) else {
		return Ok(());
	};
	netcfgd_sys::process::terminate(pid)
		.map_err(|error| format!("could not stop radvd on {iface} (pid {pid}): {error}"))?;
	// The generated configuration stays: it is rewritten on every start, it
	// says what was last advertised, and unlike hostapd's it holds no secret.
	let _ = std::fs::remove_file(pid_path(run, iface));
	Ok(())
}

/// Whether netcfgd's own radvd is running on this interface, and its pid.
#[must_use]
pub fn running_pid(run: &Path, iface: &str) -> Option<i32> {
	let text = std::fs::read_to_string(pid_path(run, iface)).ok()?;
	let pid: i32 = text.trim().lines().next()?.parse().ok()?;
	let config = config_path(run, iface);
	let config = config.to_string_lossy().into_owned();
	// NUL-separated, so the path is a whole argument and cannot match by
	// accident. A pid file outlives the process it names and pids are recycled,
	// which is the whole reason this check exists.
	let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
	cmdline
		.split(|byte| *byte == 0)
		.any(|argument| argument == config.as_bytes())
		.then_some(pid)
}

/// The lines of a log that say what went wrong, for an error message.
///
/// The same problem and the same answer as hostapd's and `OpenVPN`'s: a daemon
/// that fails announces the reason and then narrates its shutdown, so the tail
/// is the wrong lines.
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
			["error", "syntax", "cannot", "could not", "fatal", "exiting"]
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

	fn plain() -> RaPolicy {
		RaPolicy {
			backend: RaBackend::Auto,
			prefixes: Vec::new(),
			managed: false,
			other_config: false,
			dns: true,
			lifetime: None,
		}
	}

	#[test]
	fn a_prefix_is_advertised_on_link_and_autonomous() {
		let text = render("lan0", &plain(), &["2001:db8:1234::/64".to_owned()], &[]);
		assert!(text.contains("interface lan0"), "got:\n{text}");
		assert!(text.contains("AdvSendAdvert on;"), "got:\n{text}");
		assert!(text.contains("prefix 2001:db8:1234::/64"), "got:\n{text}");
		// Both, or a host treats the prefix as local and never configures an
		// address from it -- which is the whole point on a delegated prefix.
		assert!(text.contains("AdvOnLink on;"), "got:\n{text}");
		assert!(text.contains("AdvAutonomous on;"), "got:\n{text}");
	}

	#[test]
	fn the_two_flags_that_send_hosts_to_a_server_are_the_documents() {
		let mut policy = plain();
		policy.managed = true;
		policy.other_config = true;
		let text = render("lan0", &policy, &["2001:db8::/64".to_owned()], &[]);
		assert!(text.contains("AdvManagedFlag on;"), "got:\n{text}");
		assert!(text.contains("AdvOtherConfigFlag on;"), "got:\n{text}");

		let text = render("lan0", &plain(), &["2001:db8::/64".to_owned()], &[]);
		assert!(text.contains("AdvManagedFlag off;"), "got:\n{text}");
		assert!(text.contains("AdvOtherConfigFlag off;"), "got:\n{text}");
	}

	#[test]
	fn nameservers_go_out_only_where_the_document_says_so() {
		let servers = ["2001:db8:1234::1".to_owned()];
		let text = render("lan0", &plain(), &["2001:db8::/64".to_owned()], &servers);
		assert!(text.contains("RDNSS 2001:db8:1234::1 { };"), "got:\n{text}");

		let mut quiet = plain();
		quiet.dns = false;
		let text = render("lan0", &quiet, &["2001:db8::/64".to_owned()], &servers);
		assert!(!text.contains("RDNSS"), "got:\n{text}");
	}

	/// Zero is a lifetime and means "I am not a default gateway", so it is
	/// passed through rather than read as "unset".
	#[test]
	fn a_zero_lifetime_is_a_value_and_not_an_absence() {
		let mut policy = plain();
		policy.lifetime = Some(0);
		let text = render("lan0", &policy, &["2001:db8::/64".to_owned()], &[]);
		assert!(text.contains("AdvDefaultLifetime 0;"), "got:\n{text}");

		let text = render("lan0", &plain(), &["2001:db8::/64".to_owned()], &[]);
		assert!(!text.contains("AdvDefaultLifetime"), "got:\n{text}");
	}

	/// A backend this build does not implement is named rather than
	/// substituted. odhcpd takes entirely different configuration, and handing
	/// it radvd's would be a document that stopped describing the system.
	#[test]
	fn an_unimplemented_backend_is_refused_by_name() {
		let mut policy = plain();
		policy.backend = RaBackend::Odhcpd;
		let error = start(
			Path::new("/nonexistent"),
			"lan0",
			&policy,
			&["2001:db8::/64".to_owned()],
			&[],
		)
		.expect_err("odhcpd is not implemented");
		assert!(error.contains("odhcpd"), "got {error}");
	}

	/// And a policy whose references all resolved to nothing advertises
	/// nothing, rather than advertising a router with no prefix.
	#[test]
	fn nothing_to_advertise_is_refused_before_anything_starts() {
		let error = start(Path::new("/nonexistent"), "lan0", &plain(), &[], &[])
			.expect_err("no prefix is not something to advertise");
		assert!(error.contains("advertises no prefix"), "got {error}");
	}
}
