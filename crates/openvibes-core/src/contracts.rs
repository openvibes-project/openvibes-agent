use std::{collections::HashSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::ResourceLimits;

/// Schema version supported by the initial scanner contracts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SchemaVersion(u16);

impl SchemaVersion {
    /// Schema version implemented by this scanner.
    pub const V1: Self = Self(1);

    /// Returns the numeric schema version.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Identifier shared by scanner wire contracts.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    /// Creates and validates an identifier using version 1 limits.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_identifier("identifier", &value, ResourceLimits::V1)?;
        Ok(Self(value))
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Supported typed values exposed to CEL rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FactValue {
    /// Boolean fact.
    Boolean(bool),
    /// Signed integer fact.
    Integer(i64),
    /// UTF-8 string fact.
    String(String),
    /// Bounded list of UTF-8 strings.
    StringList(Vec<String>),
}

/// One canonical host fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Fact {
    /// Stable, namespaced fact key.
    pub key: Identifier,
    /// Collector that produced the fact.
    pub source: Identifier,
    /// Typed fact value.
    pub value: FactValue,
}

/// Facts produced by one scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactSet {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Unique scan identifier.
    pub scan_id: Identifier,
    /// Collection time as milliseconds since the Unix epoch.
    pub collected_at_unix_ms: i64,
    /// Immutable facts collected during the scan.
    pub facts: Vec<Fact>,
    /// Structured errors from collectors that could not fully complete.
    pub errors: Vec<CollectorError>,
}

/// Stable categories for collector failures.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorErrorCode {
    /// The current identity lacks required read access.
    PermissionDenied,
    /// The requested source does not exist.
    NotFound,
    /// The operation exceeded its deadline.
    TimedOut,
    /// Input from the host was malformed or unsupported.
    InvalidData,
    /// This collector is unavailable on the current platform.
    Unsupported,
    /// A bounded internal failure not covered by another category.
    Internal,
}

/// Structured failure from a collector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollectorError {
    /// Collector that reported the error.
    pub collector: Identifier,
    /// Stable machine-readable error category.
    pub code: CollectorErrorCode,
    /// Bounded human-readable diagnostic without secrets.
    pub message: String,
    /// Whether a later scan may reasonably retry the operation.
    pub retryable: bool,
}

/// Finding severity selected by a rule author.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational observation.
    Info,
    /// Low-impact condition.
    Low,
    /// Medium-impact condition.
    Medium,
    /// High-impact condition.
    High,
    /// Critical condition requiring urgent attention.
    Critical,
}

/// Confidence percentage from 0 through 100.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Confidence(u8);

impl Confidence {
    /// Creates a confidence percentage.
    pub fn new(value: u8) -> Result<Self, ValidationError> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(ValidationError::new(
                "confidence",
                "must be between 0 and 100",
            ))
        }
    }

    /// Returns the percentage value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// One declarative CEL rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rule {
    /// Stable rule identifier.
    pub id: Identifier,
    /// Monotonically increasing version of this rule.
    pub version: u64,
    /// Human-readable rule title.
    pub title: String,
    /// Severity emitted when the expression evaluates to true.
    pub severity: Severity,
    /// Confidence emitted when the expression evaluates to true.
    pub confidence: Confidence,
    /// Expression in the approved CEL subset.
    pub expression: String,
    /// Finding message emitted when the rule matches.
    pub finding_message: String,
}

/// Versioned collection of declarative rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleSet {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Rules evaluated as one authenticated set.
    pub rules: Vec<Rule>,
}

/// Serialization used by a signed rule payload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    /// JSON encoded UTF-8 payload.
    Json,
    /// YAML encoded UTF-8 payload.
    Yaml,
}

/// Authenticated envelope carrying an exact rule payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRuleEnvelope {
    /// Envelope schema version.
    pub schema_version: SchemaVersion,
    /// Stable rule-set identifier.
    pub rule_set_id: Identifier,
    /// Monotonically increasing rule-set version.
    pub rule_set_version: u64,
    /// Identifier of the trusted Ed25519 verification key.
    pub issuer_key_id: Identifier,
    /// Creation time as milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Expiration time as milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
    /// Serialization of the exact UTF-8 payload.
    pub payload_encoding: PayloadEncoding,
    /// Exact UTF-8 payload. It is verified before it is parsed.
    pub payload: String,
    /// Lowercase hexadecimal SHA-256 digest of `payload` bytes.
    pub payload_sha256_hex: String,
    /// Base64url-without-padding Ed25519 signature over the versioned preimage.
    pub signature_base64url: String,
}

/// Finding produced by one matching rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Finding {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Stable, idempotent finding identifier.
    pub finding_id: Identifier,
    /// Scan that produced this finding.
    pub scan_id: Identifier,
    /// Rule that produced this finding.
    pub rule_id: Identifier,
    /// Version of the matching rule.
    pub rule_version: u64,
    /// Finding observation time as milliseconds since the Unix epoch.
    pub observed_at_unix_ms: i64,
    /// Finding severity.
    pub severity: Severity,
    /// Finding confidence.
    pub confidence: Confidence,
    /// Bounded human-readable finding message.
    pub message: String,
    /// Fact keys supporting the finding.
    pub evidence: Vec<Identifier>,
}

/// Scanner health and capability report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Heartbeat {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Enrolled scanner identity.
    pub agent_id: Identifier,
    /// Scanner software version.
    pub scanner_version: String,
    /// Observation time as milliseconds since the Unix epoch.
    pub observed_at_unix_ms: i64,
    /// Stable capability identifiers.
    pub capabilities: Vec<Identifier>,
}

/// Enrollment token that redacts itself from debug output.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EnrollmentToken(String);

impl EnrollmentToken {
    /// Creates an enrollment token.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() || value.len() > ResourceLimits::V1.string_bytes {
            return Err(ValidationError::new(
                "enrollment_token",
                "must be non-empty and within the string limit",
            ));
        }
        Ok(Self(value))
    }

    /// Exposes the token for the explicit purpose of enrollment serialization.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EnrollmentToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentToken([REDACTED])")
    }
}

/// Initial token-authenticated enrollment request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnrollmentRequest {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Single-use, short-lived bootstrap token.
    pub token: EnrollmentToken,
    /// Base64-encoded DER SubjectPublicKeyInfo for the host-bound key.
    pub public_key_spki_base64: String,
}

/// Identity material returned after successful enrollment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnrollmentResponse {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Assigned scanner identity.
    pub agent_id: Identifier,
    /// PEM certificate chain, leaf first.
    pub certificate_chain_pem: Vec<String>,
    /// Client certificate expiration as milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
}

/// Platform acknowledgement for idempotently delivered findings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryAcknowledgement {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Accepted finding identifiers.
    pub accepted_finding_ids: Vec<Identifier>,
    /// Server observation time as milliseconds since the Unix epoch.
    pub acknowledged_at_unix_ms: i64,
}

/// Validation behavior shared by version 1 contracts.
pub trait Validate {
    /// Validates the contract against explicit resource limits.
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError>;
}

/// Rejects a serialized document before a parser allocates from its contents.
pub fn validate_document_size(
    document: &[u8],
    limits: ResourceLimits,
) -> Result<(), ValidationError> {
    if document.len() > limits.document_bytes {
        Err(ValidationError::new(
            "document",
            "exceeds the serialized document byte limit",
        ))
    } else {
        Ok(())
    }
}

impl Validate for FactSet {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("collected_at_unix_ms", self.collected_at_unix_ms)?;
        if self.facts.len() > limits.facts_per_scan {
            return Err(ValidationError::new("facts", "contains too many facts"));
        }
        validate_list_length("errors", self.errors.len(), limits)?;
        let mut fact_keys = HashSet::with_capacity(self.facts.len());
        for fact in &self.facts {
            if !fact_keys.insert(&fact.key) {
                return Err(ValidationError::new(
                    "facts.key",
                    "contains a duplicate fact key",
                ));
            }
            validate_fact(fact, limits)?;
        }
        for error in &self.errors {
            validate_string("errors.message", &error.message, limits)?;
        }
        Ok(())
    }
}

impl Validate for RuleSet {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        if self.rules.is_empty() || self.rules.len() > limits.rules_per_set {
            return Err(ValidationError::new(
                "rules",
                "must contain a bounded, non-empty rule list",
            ));
        }
        let mut rule_ids = HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            validate_identifier("rules.id", rule.id.as_str(), limits)?;
            if !rule_ids.insert(&rule.id) {
                return Err(ValidationError::new(
                    "rules.id",
                    "contains a duplicate rule identifier",
                ));
            }
            if rule.version == 0 {
                return Err(ValidationError::new("rules.version", "must be positive"));
            }
            validate_string("rules.title", &rule.title, limits)?;
            validate_string("rules.finding_message", &rule.finding_message, limits)?;
            if rule.expression.is_empty() || rule.expression.len() > limits.expression_bytes {
                return Err(ValidationError::new(
                    "rules.expression",
                    "must be non-empty and within the expression limit",
                ));
            }
        }
        Ok(())
    }
}

impl SignedRuleEnvelope {
    /// Checks signed fields before signing; does not verify authenticity.
    pub fn validate_unsigned(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_identifier("rule_set_id", self.rule_set_id.as_str(), limits)?;
        validate_identifier("issuer_key_id", self.issuer_key_id.as_str(), limits)?;
        if self.rule_set_version == 0 {
            return Err(ValidationError::new("rule_set_version", "must be positive"));
        }
        if self.created_at_unix_ms < 0 || self.expires_at_unix_ms <= self.created_at_unix_ms {
            return Err(ValidationError::new(
                "expires_at_unix_ms",
                "must be later than created_at_unix_ms",
            ));
        }
        if self.payload.is_empty() || self.payload.len() > limits.document_bytes {
            return Err(ValidationError::new(
                "payload",
                "must be non-empty and within the document limit",
            ));
        }
        if self.payload_sha256_hex.len() != 64
            || !self
                .payload_sha256_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::new(
                "payload_sha256_hex",
                "must be 64 lowercase hexadecimal characters",
            ));
        }
        Ok(())
    }
}

impl Validate for SignedRuleEnvelope {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        self.validate_unsigned(limits)?;
        if self.signature_base64url.len() != 86
            || !self
                .signature_base64url
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ValidationError::new(
                "signature_base64url",
                "must encode a 64-byte Ed25519 signature as unpadded base64url",
            ));
        }
        Ok(())
    }
}

impl Validate for Finding {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("observed_at_unix_ms", self.observed_at_unix_ms)?;
        validate_string("message", &self.message, limits)?;
        if self.evidence.len() > limits.evidence_per_finding {
            return Err(ValidationError::new(
                "evidence",
                "contains too many evidence references",
            ));
        }
        Ok(())
    }
}

impl Validate for Heartbeat {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("observed_at_unix_ms", self.observed_at_unix_ms)?;
        validate_string("scanner_version", &self.scanner_version, limits)?;
        validate_list_length("capabilities", self.capabilities.len(), limits)
    }
}

impl Validate for EnrollmentRequest {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_string(
            "public_key_spki_base64",
            &self.public_key_spki_base64,
            limits,
        )
    }
}

impl Validate for EnrollmentResponse {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("expires_at_unix_ms", self.expires_at_unix_ms)?;
        validate_list_length(
            "certificate_chain_pem",
            self.certificate_chain_pem.len(),
            limits,
        )?;
        if self.certificate_chain_pem.is_empty() {
            return Err(ValidationError::new(
                "certificate_chain_pem",
                "must contain at least the leaf certificate",
            ));
        }
        for certificate in &self.certificate_chain_pem {
            validate_string("certificate_chain_pem", certificate, limits)?;
        }
        Ok(())
    }
}

impl Validate for DeliveryAcknowledgement {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("acknowledged_at_unix_ms", self.acknowledged_at_unix_ms)?;
        if self.accepted_finding_ids.len() > limits.delivery_batch_items {
            return Err(ValidationError::new(
                "accepted_finding_ids",
                "contains more identifiers than one delivery batch",
            ));
        }
        Ok(())
    }
}

/// Describes why a wire contract failed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    field: &'static str,
    message: &'static str,
}

impl ValidationError {
    const fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }

    /// Returns the invalid field path.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the validation failure description.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

fn validate_version(version: SchemaVersion) -> Result<(), ValidationError> {
    if version == SchemaVersion::V1 {
        Ok(())
    } else {
        Err(ValidationError::new(
            "schema_version",
            "unsupported schema version",
        ))
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    limits: ResourceLimits,
) -> Result<(), ValidationError> {
    let valid_characters = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if value.is_empty() || value.len() > limits.identifier_bytes || !valid_characters {
        Err(ValidationError::new(
            field,
            "must use 1-128 ASCII letters, digits, dots, underscores, colons, or hyphens",
        ))
    } else {
        Ok(())
    }
}

fn validate_string(
    field: &'static str,
    value: &str,
    limits: ResourceLimits,
) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > limits.string_bytes {
        Err(ValidationError::new(
            field,
            "must be non-empty and within the string limit",
        ))
    } else {
        Ok(())
    }
}

fn validate_unix_ms(field: &'static str, value: i64) -> Result<(), ValidationError> {
    if value < 0 {
        Err(ValidationError::new(
            field,
            "must be a non-negative Unix timestamp in milliseconds",
        ))
    } else {
        Ok(())
    }
}

fn validate_fact(fact: &Fact, limits: ResourceLimits) -> Result<(), ValidationError> {
    match &fact.value {
        FactValue::String(value) => validate_string("facts.value", value, limits),
        FactValue::StringList(values) => {
            validate_list_length("facts.value", values.len(), limits)?;
            for value in values {
                validate_string("facts.value", value, limits)?;
            }
            Ok(())
        }
        FactValue::Boolean(_) | FactValue::Integer(_) => Ok(()),
    }
}

fn validate_list_length(
    field: &'static str,
    length: usize,
    limits: ResourceLimits,
) -> Result<(), ValidationError> {
    if length > limits.list_items {
        Err(ValidationError::new(field, "contains too many items"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Confidence, EnrollmentToken, Identifier, Rule, RuleSet, SchemaVersion, Severity,
        SignedRuleEnvelope, Validate,
    };
    use crate::ResourceLimits;

    fn valid_rule_set() -> RuleSet {
        RuleSet {
            schema_version: SchemaVersion::V1,
            rules: vec![Rule {
                id: Identifier::new("process.ssh.running").expect("valid identifier"),
                version: 1,
                title: "SSH server is running".to_owned(),
                severity: Severity::Medium,
                confidence: Confidence::new(100).expect("valid confidence"),
                expression: "'sshd' in facts['process.names']".to_owned(),
                finding_message: "An SSH server process was observed".to_owned(),
            }],
        }
    }

    #[test]
    fn identifiers_reject_path_and_whitespace_characters() {
        assert!(Identifier::new("../../etc/passwd").is_err());
        assert!(Identifier::new("contains spaces").is_err());
    }

    #[test]
    fn confidence_is_bounded() {
        assert!(Confidence::new(100).is_ok());
        assert!(Confidence::new(101).is_err());
        assert!(serde_json::from_str::<Confidence>("101").is_err());
    }

    #[test]
    fn enrollment_token_debug_output_is_redacted() {
        let token = EnrollmentToken::new("secret-value").expect("valid token");

        assert!(!format!("{token:?}").contains(token.expose_secret()));
        assert!(serde_json::from_str::<EnrollmentToken>("\"\"").is_err());
    }

    #[test]
    fn rule_set_requires_rules() {
        let mut rule_set = valid_rule_set();
        rule_set.rules.clear();

        assert!(rule_set.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn envelope_rejects_invalid_digest_and_time_window() {
        let envelope = SignedRuleEnvelope {
            schema_version: SchemaVersion::V1,
            rule_set_id: Identifier::new("baseline.linux").expect("valid identifier"),
            rule_set_version: 1,
            issuer_key_id: Identifier::new("openvibes.rules.2026").expect("valid identifier"),
            created_at_unix_ms: 10,
            expires_at_unix_ms: 9,
            payload_encoding: super::PayloadEncoding::Json,
            payload: "{}".to_owned(),
            payload_sha256_hex: "invalid".to_owned(),
            signature_base64url: "signature".to_owned(),
        };

        assert!(envelope.validate(ResourceLimits::V1).is_err());
    }
}
