use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, RuleSet, SignedRuleEnvelope, Validate,
};
use sha2::{Digest, Sha256};

use crate::parsing;

/// Fixed, non-sensitive failure categories. Parser diagnostics never echo inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    /// A configured parser limit is zero or above the supported safety ceiling.
    InvalidLimits,
    /// A serialized document exceeds the configured byte limit.
    DocumentTooLarge,
    /// The outer JSON envelope is malformed or exceeds a parser budget.
    InvalidEnvelope,
    /// Envelope fields violate the versioned contract.
    InvalidMetadata,
    /// A trusted key is invalid, weak, or duplicated in its rule-set scope.
    InvalidTrustKey,
    /// No trusted key is authorized for this issuer and rule set.
    UntrustedIssuer,
    /// The requested rule-set identity does not match the signed identity.
    WrongRuleSet,
    /// The supplied clock or accepted-version state is invalid for this load.
    InvalidContext,
    /// The supplied digest does not match the exact payload bytes.
    DigestMismatch,
    /// The Ed25519 signature is malformed or fails strict verification.
    InvalidSignature,
    /// The authenticated bundle was created after the supplied current time.
    NotYetValid,
    /// The authenticated bundle has reached its expiration time.
    Expired,
    /// The bundle version is lower than the last accepted version.
    Rollback,
    /// The same version was previously accepted with different signed content.
    VersionConflict,
    /// The authenticated payload is malformed or exceeds a parser budget.
    InvalidPayload,
    /// The decoded rule set violates its versioned semantic contract.
    InvalidRules,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLimits => "invalid rule loader resource limits",
            Self::DocumentTooLarge => "rule document exceeds byte limit",
            Self::InvalidEnvelope => "invalid or over-budget JSON envelope",
            Self::InvalidMetadata => "invalid rule envelope metadata",
            Self::InvalidTrustKey => "invalid or duplicate trusted rule key",
            Self::UntrustedIssuer => "issuer is not trusted for this rule set",
            Self::WrongRuleSet => "unexpected rule-set identity",
            Self::InvalidContext => "invalid clock or accepted-version context",
            Self::DigestMismatch => "rule payload digest mismatch",
            Self::InvalidSignature => "invalid rule envelope signature",
            Self::NotYetValid => "rule bundle is not yet valid",
            Self::Expired => "rule bundle has expired",
            Self::Rollback => "rule bundle version rollback rejected",
            Self::VersionConflict => "rule bundle version content conflict",
            Self::InvalidPayload => "invalid or over-budget rule payload",
            Self::InvalidRules => "invalid rule-set contract",
        };
        f.write_str(message)
    }
}

impl std::error::Error for LoadError {}

/// A provisioned Ed25519 key authorized for exactly one rule set.
#[derive(Clone, Debug)]
pub struct TrustedRuleKey {
    rule_set_id: Identifier,
    issuer_key_id: Identifier,
    key: VerifyingKey,
}

impl TrustedRuleKey {
    /// Creates a scoped trust entry from a compressed 32-byte Ed25519 public key.
    /// This must be supplied by trusted configuration, never by the incoming bundle.
    pub fn new(
        rule_set_id: Identifier,
        issuer_key_id: Identifier,
        public_key: [u8; 32],
    ) -> Result<Self, LoadError> {
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| LoadError::InvalidTrustKey)?;
        if key.is_weak() {
            return Err(LoadError::InvalidTrustKey);
        }
        Ok(Self {
            rule_set_id,
            issuer_key_id,
            key,
        })
    }
}

/// Last accepted version and SHA-256 of its complete signing preimage.
///
/// The composition root must persist this together with the accepted bundle,
/// serialize concurrent acceptance, and restore it before subsequent loads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedVersion {
    rule_set_id: Identifier,
    version: u64,
    preimage_sha256: [u8; 32],
}

impl AcceptedVersion {
    /// Restores a record from trusted, integrity-protected agent-owned state.
    pub fn restore(
        rule_set_id: Identifier,
        version: u64,
        preimage_sha256: [u8; 32],
    ) -> Result<Self, LoadError> {
        if version == 0 {
            return Err(LoadError::InvalidContext);
        }
        Ok(Self {
            rule_set_id,
            version,
            preimage_sha256,
        })
    }

    /// Rule set whose rollback floor this record represents.
    #[must_use]
    pub fn rule_set_id(&self) -> &Identifier {
        &self.rule_set_id
    }

    /// Last accepted monotonically increasing bundle version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Digest identifying the signed content, including all envelope metadata.
    #[must_use]
    pub const fn preimage_sha256(&self) -> &[u8; 32] {
        &self.preimage_sha256
    }
}

/// Trusted context supplied explicitly; the loader never reads clocks or disk.
pub struct LoadContext<'a> {
    /// Rule-set identity the caller intends to load.
    pub expected_rule_set_id: &'a Identifier,
    /// Trusted current time in non-negative Unix milliseconds.
    pub now_unix_ms: i64,
    /// Last accepted state; `None` is only for first enrollment of a rule set.
    pub last_accepted: Option<&'a AcceptedVersion>,
}

/// Authenticated and structurally valid rules, immutable outside this crate.
///
/// Only [`RuleLoader`] creates this type. CEL compilation/evaluation is a later
/// stage; these expressions have not yet been type-checked or evaluated.
/// Callers must recheck expiry before use after a long-running scan or cache wait.
///
/// ```compile_fail
/// let verified: openvibes_rules::VerifiedRuleSet = Default::default();
/// ```
#[derive(Debug)]
pub struct VerifiedRuleSet {
    rules: RuleSet,
    accepted: AcceptedVersion,
    issuer_key_id: Identifier,
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

impl VerifiedRuleSet {
    /// Inclusive start of the authenticated validity interval.
    #[must_use]
    pub const fn created_at_unix_ms(&self) -> i64 {
        self.created_at_unix_ms
    }
    /// Read-only access to authenticated rule contracts.
    #[must_use]
    pub const fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Candidate acceptance record to persist atomically with this bundle.
    #[must_use]
    pub const fn accepted_version(&self) -> &AcceptedVersion {
        &self.accepted
    }

    /// Trusted issuer used to authenticate this bundle.
    #[must_use]
    pub const fn issuer_key_id(&self) -> &Identifier {
        &self.issuer_key_id
    }

    /// Exclusive end of the bundle's validity interval.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }
}

/// Verifies bounded JSON envelopes carrying either JSON or YAML rule payloads.
pub struct RuleLoader {
    keys: Vec<TrustedRuleKey>,
    limits: ResourceLimits,
}

impl RuleLoader {
    /// Constructs a loader with trusted, explicitly scoped keys and parser limits.
    /// Limits may tighten the version 1 defaults but may not raise them.
    pub fn new(keys: Vec<TrustedRuleKey>, limits: ResourceLimits) -> Result<Self, LoadError> {
        parsing::validate_limits(limits)?;
        if keys.len() > limits.list_items {
            return Err(LoadError::InvalidTrustKey);
        }
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].iter().any(|prior| {
                prior.rule_set_id == key.rule_set_id && prior.issuer_key_id == key.issuer_key_id
            }) {
                return Err(LoadError::InvalidTrustKey);
            }
        }
        Ok(Self { keys, limits })
    }

    /// Loads an untrusted JSON envelope; payload parsing happens only after
    /// digest/signature verification and time/version policy checks succeed.
    /// No state is written and no partially validated rules escape on failure.
    pub fn load_json(
        &self,
        bytes: &[u8],
        context: LoadContext<'_>,
    ) -> Result<VerifiedRuleSet, LoadError> {
        let envelope = parsing::envelope(bytes, self.limits)?;
        envelope
            .validate(self.limits)
            .map_err(|_| LoadError::InvalidMetadata)?;
        if &envelope.rule_set_id != context.expected_rule_set_id {
            return Err(LoadError::WrongRuleSet);
        }
        if context.now_unix_ms < 0
            || context
                .last_accepted
                .is_some_and(|last| last.rule_set_id != envelope.rule_set_id)
        {
            return Err(LoadError::InvalidContext);
        }
        let key = self
            .keys
            .iter()
            .find(|key| {
                key.issuer_key_id == envelope.issuer_key_id
                    && key.rule_set_id == envelope.rule_set_id
            })
            .ok_or(LoadError::UntrustedIssuer)?;
        let preimage = signing_preimage(&envelope, self.limits)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&envelope.signature_base64url)
            .map_err(|_| LoadError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| LoadError::InvalidSignature)?;
        key.key
            .verify_strict(&preimage, &signature)
            .map_err(|_| LoadError::InvalidSignature)?;
        if envelope.created_at_unix_ms > context.now_unix_ms {
            return Err(LoadError::NotYetValid);
        }
        if envelope.expires_at_unix_ms <= context.now_unix_ms {
            return Err(LoadError::Expired);
        }
        let preimage_sha256: [u8; 32] = Sha256::digest(&preimage).into();
        if let Some(last) = context.last_accepted {
            if envelope.rule_set_version < last.version {
                return Err(LoadError::Rollback);
            }
            if envelope.rule_set_version == last.version && preimage_sha256 != last.preimage_sha256
            {
                return Err(LoadError::VersionConflict);
            }
        }
        let rules = parsing::rules(&envelope.payload, envelope.payload_encoding, self.limits)?;
        rules
            .validate(self.limits)
            .map_err(|_| LoadError::InvalidRules)?;
        Ok(VerifiedRuleSet {
            rules,
            accepted: AcceptedVersion {
                rule_set_id: envelope.rule_set_id,
                version: envelope.rule_set_version,
                preimage_sha256,
            },
            issuer_key_id: envelope.issuer_key_id,
            created_at_unix_ms: envelope.created_at_unix_ms,
            expires_at_unix_ms: envelope.expires_at_unix_ms,
        })
    }
}

/// Builds the exact domain-separated version 1 signing bytes.
///
/// Validates unsigned metadata and the SHA-256 payload digest, but ignores the
/// signature field. This helper neither signs nor establishes authenticity.
pub fn signing_preimage(
    envelope: &SignedRuleEnvelope,
    limits: ResourceLimits,
) -> Result<Vec<u8>, LoadError> {
    parsing::validate_limits(limits)?;
    envelope
        .validate_unsigned(limits)
        .map_err(|_| LoadError::InvalidMetadata)?;
    let digest: [u8; 32] = Sha256::digest(envelope.payload.as_bytes()).into();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex != envelope.payload_sha256_hex {
        return Err(LoadError::DigestMismatch);
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"OPENVIBES-RULE-ENVELOPE-V1\0");
    output.extend_from_slice(&envelope.schema_version.value().to_be_bytes());
    push_string(&mut output, envelope.rule_set_id.as_str())?;
    output.extend_from_slice(&envelope.rule_set_version.to_be_bytes());
    push_string(&mut output, envelope.issuer_key_id.as_str())?;
    output.extend_from_slice(&envelope.created_at_unix_ms.to_be_bytes());
    output.extend_from_slice(&envelope.expires_at_unix_ms.to_be_bytes());
    output.push(match envelope.payload_encoding {
        PayloadEncoding::Json => 1,
        PayloadEncoding::Yaml => 2,
    });
    let length = u64::try_from(envelope.payload.len()).map_err(|_| LoadError::InvalidMetadata)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(envelope.payload.as_bytes());
    output.extend_from_slice(&digest);
    Ok(output)
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), LoadError> {
    let length = u32::try_from(value.len()).map_err(|_| LoadError::InvalidMetadata)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}
