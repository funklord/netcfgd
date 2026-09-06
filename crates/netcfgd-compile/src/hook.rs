//! Naming hook bodies, so that the compiler can refer to them without
//! writing them.

use netcfgd_model::{HookPhase, HookRef};

/// Turns a hook body into a reference, and keeps the body for later.
///
/// **This used to write the file, and that made the compiler impure.** Section
/// 2.2 requires the document to carry `{phase, path, sha256}` rather than
/// shell, and both of those are computable from the body and a naming rule --
/// no filesystem needed. Writing them was folded in because the sink was there,
/// and it cost more than it looks:
///
/// - **Five of the six CLI paths that compile are read-only** -- `plan`,
///   `show`, `explain` and two helpers -- and every one of them wrote hook
///   scripts under `/run` as a side effect of being asked what *would* happen.
///   `ncfg plan`'s own help says "change nothing".
/// - **A compile that failed had already written some of them**, because the
///   writes happened as the hooks were reached rather than after the document
///   was known to be good.
/// - **A pure compiler can be run somewhere with no privileges.** That is what
///   this is for next, and it could not be while compilation touched `/run`.
///
/// So an implementation of this records; a caller that wants the files on disk
/// asks for them afterwards, and says so where it does. See
/// `netcfgd_host::hooks::PendingHooks`.
pub trait HookSink {
	/// Name `body`, keep it, and return the reference the document carries.
	///
	/// **No I/O.** An implementation that writes here puts the side effect
	/// back where the document says there is none.
	///
	/// # Errors
	///
	/// Returns a message to be reported at the hook's position.
	fn record(&mut self, phase: HookPhase, owner: &str, body: &str) -> Result<HookRef, String>;
}

/// A sink that refuses every hook.
///
/// The default for a caller that has nowhere to put them -- `ncfg plan` on a
/// read-only root, for instance. Refusing loudly beats silently dropping the
/// hooks and producing a document that describes a system nobody asked for.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl HookSink for NoHooks {
	fn record(&mut self, _phase: HookPhase, _owner: &str, _body: &str) -> Result<HookRef, String> {
		Err("this caller cannot accept hooks".to_owned())
	}
}
