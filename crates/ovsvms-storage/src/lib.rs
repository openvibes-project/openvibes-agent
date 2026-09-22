#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SQLite-backed scanner state and durable delivery queue.
//!
//! All writes are restricted to agent-owned state paths. The concrete SQLite
//! implementation will follow an accepted queue schema and storage ADR.

use ovsvms_core::ComponentDescriptor;

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
