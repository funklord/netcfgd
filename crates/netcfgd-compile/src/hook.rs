//! Materialising hook bodies, which is the one thing the compiler cannot do
//! itself.

use netcfgd_model::{HookPhase, HookRef};

/// Turns a hook body into a file on disk and reports back where it went.
///
/// The compiler is pure and opens no files, but section 2.2 requires the
/// document to carry `{phase, path, sha256}` rather than shell. Those two
/// facts meet here: the caller supplies the materialiser, the compiler stays a
/// function, and the fixture tests use a fake that writes nothing.
pub trait HookSink {
	/// Write `body` somewhere and return a reference to it.
	///
	/// # Errors
	///
	/// Returns a message to be reported at the hook's position.
	fn materialise(&mut self, phase: HookPhase, owner: &str, body: &str)
		-> Result<HookRef, String>;
}

/// A sink that refuses every hook.
///
/// The default for a caller that has nowhere to put them -- `ncfg plan` on a
/// read-only root, for instance. Refusing loudly beats silently dropping the
/// hooks and producing a document that describes a system nobody asked for.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl HookSink for NoHooks {
	fn materialise(
		&mut self,
		_phase: HookPhase,
		_owner: &str,
		_body: &str,
	) -> Result<HookRef, String> {
		Err("this caller cannot materialise hooks".to_owned())
	}
}
