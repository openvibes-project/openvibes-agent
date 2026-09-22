#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Ed25519 rule-envelope verification and bounded declarative CEL evaluation.
//!
//! This crate receives immutable facts. It must not receive filesystem,
//! operating-system, SQLite, environment, clock, or network capabilities.

use ovsvms_core::ComponentDescriptor;

mod evaluation;
mod loader;
mod parsing;
mod subset;

pub use evaluation::{
    EvaluationClock, EvaluationError, EvaluationReport, Evaluator, RuleOutcome, RuleResult,
};

pub use loader::{
    AcceptedVersion, LoadContext, LoadError, RuleLoader, TrustedRuleKey, VerifiedRuleSet,
    signing_preimage,
};

/// Returns the rules component descriptor.
#[must_use]
pub const fn descriptor() -> ComponentDescriptor {
    ComponentDescriptor::new("rules")
}

#[cfg(test)]
mod tests {
    use super::descriptor;

    #[test]
    fn descriptor_is_stable() {
        assert_eq!(descriptor().name(), "rules");
    }
}
