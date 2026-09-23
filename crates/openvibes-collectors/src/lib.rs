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

/// The host name the OS reports, or `None` if it is unavailable or not UTF-8.
/// A label for operators only; it is spoofable and never authenticates.
#[must_use]
pub fn hostname() -> Option<String> {
    #[cfg(unix)]
    let name = rustix::system::uname().nodename().to_str().ok()?.to_owned();
    // ponytail: the environment variable Windows sets for every process;
    // switch to GetComputerNameExW if a service ever runs without it.
    #[cfg(not(unix))]
    let name = std::env::var("COMPUTERNAME").ok()?;
    Some(name).filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    #[test]
    fn descriptor_is_stable() {
        assert_eq!(descriptor().name(), "collectors");
    }

    #[test]
    fn hostname_is_reported() {
        assert!(super::hostname().is_some_and(|name| !name.is_empty()));
    }
}
