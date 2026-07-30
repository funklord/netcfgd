//! Link ncursesw, but only when the TUI is built.
//!
//! `ncursesw` rather than `ncurses`: the wide-character build is what makes an
//! SSID that is not ASCII occupy the columns it actually occupies. `tinfo` is
//! named separately because a split build has the terminfo routines there, and
//! linking it when it is already inside ncursesw is harmless.

fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	if std::env::var_os("CARGO_FEATURE_TUI").is_some() {
		println!("cargo:rustc-link-lib=ncursesw");
		println!("cargo:rustc-link-lib=tinfo");
	}
}
