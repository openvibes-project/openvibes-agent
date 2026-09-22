#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Enrollment, mTLS identity, and OpenVIBES Platform communication.
//!
//! Every request uses TLS 1.3 with pinned server roots, no redirects, bounded
//! timeouts, and bounded response sizes. The client never touches disk:
//! persisting the host key and issued chain is the composition root's job.

mod client;
mod identity;

use openvibes_core::ComponentDescriptor;

pub use client::{DEFAULT_PLATFORM_PORT, PlatformClient, TransportConfig, TransportError};
pub use identity::{ClientIdentity, HostKey};

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
