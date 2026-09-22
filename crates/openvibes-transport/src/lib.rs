#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Enrollment, mTLS identity lifecycle, and OpenVIBES Platform communication.
//!
//! Network behavior is bounded by explicit timeouts, payload limits, retry
//! limits, and redirect policy. No transport implementation exists yet.

use openvibes_core::ComponentDescriptor;

/// Returns the transport component descriptor.
#[must_use]
pub const fn descriptor() -> ComponentDescriptor {
    ComponentDescriptor::new("transport")
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    #[test]
    fn descriptor_is_stable() {
        assert_eq!(descriptor().name(), "transport");
    }
}
