//! The properties a secret store has to have, as tests.

use netcfgd_model::{SecretProvider, SecretRef};
use netcfgd_secret::{Error, Resolver, Secret};
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
fn write_secret(dir: &std::path::Path, name: &str, body: &str, mode: u32) -> PathBuf {
	use std::os::unix::fs::PermissionsExt;
	let path = dir.join(name);
	fs::write(&path, body).expect("write");
	fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
	path
}

fn scratch(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("ncfg-secret-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).expect("scratch");
	dir
}

fn reference(name: &str, provider: SecretProvider) -> SecretRef {
	SecretRef {
		provider,
		name: name.to_owned(),
	}
}

#[test]
fn a_file_secret_resolves() {
	let dir = scratch("read");
	write_secret(&dir, "wifi-psk", "hunter2\n", 0o600);

	let resolver = Resolver::with_secrets_dir(&dir);
	let secret = resolver
		.resolve(&reference("wifi-psk", SecretProvider::File))
		.expect("resolves");
	assert_eq!(secret.expose(), "hunter2");

	let _ = fs::remove_dir_all(&dir);
}

/// One trailing newline is what an editor or `echo` leaves behind, and a
/// passphrase that silently carries it fails to associate with no indication
/// why. Anything past the first is the operator's business.
#[test]
fn exactly_one_trailing_newline_is_stripped() {
	let dir = scratch("newline");
	write_secret(&dir, "one", "value\n", 0o600);
	write_secret(&dir, "two", "value\n\n", 0o600);
	write_secret(&dir, "none", "value", 0o600);

	let resolver = Resolver::with_secrets_dir(&dir);
	let get = |name: &str| {
		resolver
			.resolve(&reference(name, SecretProvider::File))
			.expect("resolves")
			.expose()
			.to_owned()
	};
	assert_eq!(get("one"), "value");
	assert_eq!(get("two"), "value\n");
	assert_eq!(get("none"), "value");

	let _ = fs::remove_dir_all(&dir);
}

/// Design section 3.3 specifies mode 0600. Enforcing it is the difference
/// between a rule and a suggestion: a secret anybody can read is already
/// disclosed, and using it anyway tells the operator everything is fine.
#[cfg(unix)]
#[test]
fn a_world_readable_secret_is_refused() {
	let dir = scratch("mode");
	write_secret(&dir, "leaky", "hunter2\n", 0o644);

	let resolver = Resolver::with_secrets_dir(&dir);
	match resolver.resolve(&reference("leaky", SecretProvider::File)) {
		Err(Error::Exposed { mode, .. }) => assert_eq!(mode, 0o644),
		other => panic!("a world-readable secret must be refused, got {other:?}"),
	}

	let _ = fs::remove_dir_all(&dir);
}

/// Group-readable counts too. A secrets directory shared with a group is the
/// usual way this goes wrong, and it is not more acceptable than world.
#[cfg(unix)]
#[test]
fn a_group_readable_secret_is_refused() {
	let dir = scratch("group");
	write_secret(&dir, "shared", "hunter2\n", 0o640);

	let resolver = Resolver::with_secrets_dir(&dir);
	assert!(matches!(
		resolver.resolve(&reference("shared", SecretProvider::File)),
		Err(Error::Exposed { .. })
	));

	let _ = fs::remove_dir_all(&dir);
}

/// The refusal has to be actionable without being dangerous: it names the
/// path and the mode, and says the value should be considered disclosed
/// rather than just telling somebody to chmod and carry on.
#[cfg(unix)]
#[test]
fn the_refusal_explains_the_consequence_not_just_the_fix() {
	let dir = scratch("message");
	write_secret(&dir, "leaky", "hunter2\n", 0o644);

	let resolver = Resolver::with_secrets_dir(&dir);
	let error = resolver
		.resolve(&reference("leaky", SecretProvider::File))
		.expect_err("refused");
	let message = error.to_string();

	assert!(message.contains("0644"), "got: {message}");
	assert!(message.contains("chmod 600"), "got: {message}");
	assert!(message.contains("disclosed"), "got: {message}");
	assert!(
		!message.contains("hunter2"),
		"a diagnostic must never quote the secret: {message}"
	);

	let _ = fs::remove_dir_all(&dir);
}

/// A name that escapes the directory would let a config read any file on the
/// machine as root. Names are a flat namespace on purpose.
#[test]
fn a_name_cannot_escape_the_secrets_directory() {
	let dir = scratch("escape");
	let resolver = Resolver::with_secrets_dir(&dir);

	for name in ["../../etc/shadow", "sub/dir", "..", ""] {
		assert!(
			resolver
				.resolve(&reference(name, SecretProvider::File))
				.is_err(),
			"`{name}` must not resolve"
		);
	}

	let _ = fs::remove_dir_all(&dir);
}

/// A missing secret says where it looked, which is the question the operator
/// has next.
#[test]
fn a_missing_secret_says_where_it_looked() {
	let dir = scratch("missing");
	let resolver = Resolver::with_secrets_dir(&dir);

	match resolver.resolve(&reference("absent", SecretProvider::File)) {
		Err(Error::NotFound { where_, .. }) => {
			assert!(where_.contains("ncfg-secret-missing"), "got: {where_}");
		}
		other => panic!("expected NotFound, got {other:?}"),
	}

	let _ = fs::remove_dir_all(&dir);
}

/// The type refuses to print itself. Anything holding a passphrase ends up
/// inside a derived Debug, an error, or a panic message eventually, and the
/// one place to stop that is here.
#[test]
fn a_secret_does_not_print_itself() {
	let secret = Secret::new("hunter2".to_owned());

	let debug = format!("{secret:?}");
	let display = format!("{secret}");
	for rendered in [&debug, &display] {
		assert!(
			!rendered.contains("hunter2"),
			"a secret leaked through formatting: {rendered}"
		);
	}
	assert!(debug.contains("redacted"));
	assert_eq!(secret.len(), 7, "the length is safe to say and useful");
}

/// An empty passphrase is a common misconfiguration that fails deep inside a
/// supplicant with an unhelpful message, so the length being visible matters.
#[test]
fn an_empty_secret_is_resolvable_and_visibly_empty() {
	let dir = scratch("empty");
	write_secret(&dir, "blank", "\n", 0o600);

	let resolver = Resolver::with_secrets_dir(&dir);
	let secret = resolver
		.resolve(&reference("blank", SecretProvider::File))
		.expect("resolves");
	assert!(secret.is_empty());

	let _ = fs::remove_dir_all(&dir);
}

/// The exec provider runs the command directly, not through a shell -- a
/// shell would make the config a place where a secret name becomes arbitrary
/// code with word splitting and globbing attached.
#[test]
fn an_exec_secret_runs_the_command_without_a_shell() {
	let resolver = Resolver::default();
	let secret = resolver
		.resolve(&reference("printf hunter2", SecretProvider::Exec))
		.expect("resolves");
	assert_eq!(secret.expose(), "hunter2");

	// Shell metacharacters are arguments, not syntax.
	let literal = resolver
		.resolve(&reference("printf a;b", SecretProvider::Exec))
		.expect("resolves");
	assert_eq!(literal.expose(), "a;b");
}

/// A failing helper's stderr is not quoted back, because a secret helper that
/// fails often prints the thing it failed to deliver.
#[test]
fn a_failing_exec_secret_does_not_quote_its_output() {
	let resolver = Resolver::default();
	let error = resolver
		.resolve(&reference("false", SecretProvider::Exec))
		.expect_err("fails");
	let message = error.to_string();
	assert!(message.contains("exited with"), "got: {message}");
}

/// Providers that are not implemented say which milestone, rather than
/// failing in a way that looks like the secret is missing.
#[test]
fn an_unimplemented_provider_names_its_milestone() {
	let resolver = Resolver::default();
	for provider in [SecretProvider::Keyring, SecretProvider::Pass] {
		let error = resolver
			.resolve(&reference("anything", provider))
			.expect_err("unsupported");
		assert!(matches!(error, Error::Unsupported { .. }));
		assert!(error.to_string().contains("M3"));
	}
}
