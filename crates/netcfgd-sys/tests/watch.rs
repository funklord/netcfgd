//! The config watcher, both mechanisms, against a real directory.
//!
//! The event parser is exercised with synthetic bytes; the watcher itself is
//! not, because a watch that silently reports nothing looks exactly like a
//! quiet directory and only a real filesystem can tell the difference.

use netcfgd_sys::inotify::{mask, Event, Events, EVENT_HDR_LEN};
use netcfgd_sys::watch::Mechanism;
use netcfgd_sys::Watcher;
use std::fs;
use std::path::PathBuf;

/// Build one `struct inotify_event` with a trailing name.
fn encode(wd: i32, mask: u32, name: Option<&str>) -> Vec<u8> {
	let mut out = Vec::new();
	out.extend_from_slice(&wd.to_ne_bytes());
	out.extend_from_slice(&mask.to_ne_bytes());
	out.extend_from_slice(&0_u32.to_ne_bytes()); // cookie
	match name {
		Some(text) => {
			// The kernel NUL-pads the name to an alignment boundary, so the
			// length is not the string length. Reproducing that is the point.
			let mut bytes = text.as_bytes().to_vec();
			bytes.push(0);
			while bytes.len() % 4 != 0 {
				bytes.push(0);
			}
			out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_ne_bytes());
			out.extend_from_slice(&bytes);
		}
		None => out.extend_from_slice(&0_u32.to_ne_bytes()),
	}
	out
}

#[test]
fn an_event_decodes_with_its_padded_name() {
	let raw = encode(3, mask::CLOSE_WRITE, Some("10-lan.conf"));
	let events: Vec<Event> = Events::new(&raw).collect();
	assert_eq!(events.len(), 1);
	assert_eq!(events[0].wd, 3);
	assert_eq!(events[0].name.as_deref(), Some("10-lan.conf"));
	assert!(!events[0].overflowed());
}

#[test]
fn several_events_in_one_read_are_all_seen() {
	let mut raw = encode(1, mask::CREATE, Some("a.conf"));
	raw.extend_from_slice(&encode(1, mask::DELETE, Some("bb.conf")));
	raw.extend_from_slice(&encode(1, mask::MODIFY, None));

	let names: Vec<Option<String>> = Events::new(&raw).map(|event| event.name).collect();
	assert_eq!(
		names,
		[Some("a.conf".to_owned()), Some("bb.conf".to_owned()), None]
	);
}

/// A queue overflow means events were lost. Treated as a change, for the same
/// reason netlink's ENOBUFS is: a watcher that re-reads everything cannot tell
/// the difference, and refusing to look would stop the watch exactly when the
/// most was happening.
#[test]
fn an_overflow_is_visible_to_the_caller() {
	let raw = encode(-1, mask::Q_OVERFLOW, None);
	let events: Vec<Event> = Events::new(&raw).collect();
	assert!(events[0].overflowed());
}

/// The same termination hazard as the netlink iterators: a length running past
/// the buffer must end iteration rather than index out of bounds.
#[test]
fn an_overlong_name_length_terminates_rather_than_panicking() {
	let mut raw = encode(1, mask::CREATE, None);
	raw[12..16].copy_from_slice(&9999_u32.to_ne_bytes());
	assert_eq!(Events::new(&raw).count(), 0);
}

#[test]
fn a_truncated_event_is_refused() {
	let raw = encode(1, mask::CREATE, Some("x.conf"));
	for cut in 0..EVENT_HDR_LEN {
		assert_eq!(Events::new(&raw[..cut]).count(), 0);
	}
}

#[test]
fn adversarial_event_bytes_never_panic() {
	for seed in [
		vec![],
		vec![0xff; 16],
		vec![0xff; 64],
		vec![0x00; 15],
		(0..=255_u8).collect::<Vec<u8>>(),
	] {
		assert!(Events::new(&seed).take(10_000).count() < 10_000);
	}
}

fn scratch(name: &str) -> PathBuf {
	let base = std::env::temp_dir().join(format!("ncfg-watch-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&base);
	fs::create_dir_all(&base).expect("scratch directory");
	base
}

/// Every behavioural assertion runs against both mechanisms, because a
/// fallback that is only reached when something else has gone wrong is a
/// fallback nobody has ever watched work.
fn both_mechanisms(name: &str) -> Vec<(PathBuf, Watcher)> {
	vec![
		{
			let dir = scratch(&format!("{name}-inotify"));
			let watcher = Watcher::new(&[dir.clone()]);
			(dir, watcher)
		},
		{
			let dir = scratch(&format!("{name}-polling"));
			let watcher = Watcher::polling(&[dir.clone()]);
			(dir, watcher)
		},
	]
}

/// The property that matters: writing a file wakes the watcher, whichever
/// mechanism it got.
#[test]
fn writing_a_config_file_is_observed() {
	for (dir, mut watcher) in both_mechanisms("write") {
		assert!(
			!watcher.wait(50).expect("watch works"),
			"quiet to begin with"
		);
		fs::write(
			dir.join("10-lan.conf"),
			"interface eth0 { config = \"dhcp\" }\n",
		)
		.expect("write succeeds");
		assert!(
			watcher.wait(1500).expect("watch works"),
			"a new config file must wake a {} watcher",
			watcher.mechanism().name()
		);
		let _ = fs::remove_dir_all(&dir);
	}
}

/// Deleting a drop-in is a change too. An implementation that fingerprints
/// only the files it can see would miss this one entirely.
#[test]
fn deleting_a_config_file_is_observed() {
	for (dir, _) in both_mechanisms("delete") {
		let file = dir.join("20-extra.conf");
		fs::write(&file, "hostname = \"x\"\n").expect("write succeeds");

		// Built after the file exists, so its absence is the change.
		let inotify = dir.to_string_lossy().contains("inotify");
		let mut watcher = if inotify {
			Watcher::new(&[dir.clone()])
		} else {
			Watcher::polling(&[dir.clone()])
		};
		assert!(!watcher.wait(50).expect("watch works"));

		fs::remove_file(&file).expect("remove succeeds");
		assert!(
			watcher.wait(1500).expect("watch works"),
			"a deleted config file must wake a {} watcher",
			watcher.mechanism().name()
		);
		let _ = fs::remove_dir_all(&dir);
	}
}

/// Editing an existing file is the common case, and the one a naive
/// fingerprint misses: a directory's own mtime changes when a file is created
/// or deleted inside it, but not when an existing file's contents change. The
/// create and delete tests above therefore pass even without looking at the
/// children, which is how this gap stayed open until the fingerprint was
/// deliberately broken and nothing failed.
#[test]
fn modifying_an_existing_config_file_is_observed() {
	for (dir, _) in both_mechanisms("modify") {
		let file = dir.join("netcfgd.conf");
		fs::write(&file, "hostname = \"first\"\n").expect("write succeeds");

		let inotify = dir.to_string_lossy().contains("inotify");
		let mut watcher = if inotify {
			Watcher::new(&[dir.clone()])
		} else {
			Watcher::polling(&[dir.clone()])
		};
		assert!(
			!watcher.wait(50).expect("watch works"),
			"quiet to begin with"
		);

		// Same path, same directory, different contents.
		fs::write(&file, "hostname = \"second\"\n").expect("rewrite succeeds");
		assert!(
			watcher.wait(1500).expect("watch works"),
			"an edited config file must wake a {} watcher",
			watcher.mechanism().name()
		);
		let _ = fs::remove_dir_all(&dir);
	}
}

/// A directory that does not exist yet is still watched, because `conf.d/` is
/// created the first time somebody writes a drop-in and that is exactly the
/// moment the daemon needs to notice.
#[test]
fn a_directory_appearing_later_is_observed() {
	let base = scratch("appear");
	let missing = base.join("conf.d");

	let mut watcher = Watcher::new(&[missing.clone()]);
	// With no directory to watch there is no inotify descriptor, so this is
	// necessarily the polling path -- which is the point of having one.
	assert_eq!(watcher.mechanism(), Mechanism::Polling);
	assert!(!watcher.wait(50).expect("watch works"));

	fs::create_dir_all(&missing).expect("create succeeds");
	assert!(
		watcher.wait(1500).expect("watch works"),
		"a directory appearing must wake the watcher"
	);

	let _ = fs::remove_dir_all(&base);
}

/// inotify is preferred where the system allows it. Asserted rather than
/// assumed, because falling back silently would make the fallback the only
/// path anyone ever exercises.
#[test]
fn inotify_is_used_where_it_is_available() {
	let dir = scratch("mechanism");
	let watcher = Watcher::new(&[dir.clone()]);
	assert_eq!(
		watcher.mechanism(),
		Mechanism::Inotify,
		"expected inotify on an ordinary Linux filesystem"
	);
	let _ = fs::remove_dir_all(&dir);
}
