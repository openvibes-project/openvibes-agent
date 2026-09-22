#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Read-only, platform-specific host collectors.
//!
//! Collectors may observe host state but must never modify it or invoke an
//! external process. Platform implementations will be added after the fact
//! schema and collector contract are accepted.

use openvibes_core::ComponentDescriptor;

/// Returns the collectors component descriptor.
#[must_use]
pub const fn descriptor() -> ComponentDescriptor {
    ComponentDescriptor::new("collectors")
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    #[test]
    fn descriptor_is_stable() {
        assert_eq!(descriptor().name(), "collectors");
    }
}
