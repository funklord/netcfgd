#![forbid(unsafe_code)]

//! Everything netcfgd does to the filesystem.
//!
//! Reading `/etc/netcfgd`, writing `/run/netcfgd`, and materialising hook
//! bodies. Split out of the CLI when the daemon turned out to need all three:
//! two copies of "which files are the config, and in what order" is how the
//! CLI and the daemon end up disagreeing about what the config says, which is
//! the worst kind of bug this project could have.
//!
//! The pure crates -- model, compile, plan -- deliberately touch none of this.
//! That is what keeps them testable from fixtures, and it is why this crate
//! exists rather than the I/O being pushed down into them.

pub mod config;
pub mod confirm;
/// Finding out whether something else is already managing an interface.
///
/// **Moved down to `netcfgd-apply` and re-exported here**, because the executor
/// has to consult it before starting a supplicant and cannot depend on this
/// crate -- `netcfgd-host` depends on `netcfgd-apply`, so the arrow only goes
/// one way. The re-export keeps every existing caller spelled as it was.
pub use netcfgd_apply::contention;
pub mod explain;
pub mod hooks;
pub mod portal;
pub mod state;
pub mod wifi_profile;

pub use config::load;
pub use confirm::{document_hash, Window};
pub use explain::explain;
pub use hooks::RunHooks;
pub use state::{OwnedState, DEFAULT_RUN_DIR};
