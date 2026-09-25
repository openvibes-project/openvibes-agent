#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SQLite-backed scanner state and durable delivery queue.
//!
//! All writes are restricted to agent-owned state paths prepared by
//! [`prepare_state_dir`]. SQLite is bundled, so
//! every platform runs the same reviewed SQLite version.

mod db;
mod identity;
mod install;
mod paths;
mod queue;
mod rules;

use openvibes_core::ComponentDescriptor;

pub use db::StorageError;
pub use identity::{IdentityStore, StoredIdentity};
pub use install::install_id;
pub use paths::{check_output_dir, open_input_file, prepare_state_dir};
pub use queue::{DeliveryError, SqliteQueue};
pub use rules::{RuleStore, StoredRuleBundle};

/// Returns the storage component descriptor.
#[must_use]
pub const fn descriptor() -> ComponentDescriptor {
    ComponentDescriptor::new("storage")
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    #[test]
    fn descriptor_is_stable() {
        assert_eq!(descriptor().name(), "storage");
    }
}
