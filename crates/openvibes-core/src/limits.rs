/// Central resource limits for untrusted documents and scanner operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    /// Maximum serialized input document size.
    pub document_bytes: usize,
    /// Maximum structural nesting depth accepted by document parsers.
    pub document_nesting_depth: usize,
    /// Maximum parsed values plus mapping keys in a rule document.
    pub document_nodes: usize,
    /// Maximum UTF-8 bytes in a general string field.
    pub string_bytes: usize,
    /// Maximum UTF-8 bytes in an identifier.
    pub identifier_bytes: usize,
    /// Maximum number of facts in one scan result.
    pub facts_per_scan: usize,
    /// Maximum number of rules in one rule set.
    pub rules_per_set: usize,
    /// Maximum YAML alias events replayed during parsing.
    pub yaml_alias_replay_events: usize,
    /// Maximum nested YAML alias replay depth.
    pub yaml_alias_replay_depth: usize,
    /// Maximum expansion count for one YAML anchor.
    pub yaml_alias_expansions_per_anchor: usize,
    /// Maximum UTF-8 bytes in one CEL expression.
    pub expression_bytes: usize,
    /// Maximum evidence references attached to one finding.
    pub evidence_per_finding: usize,
    /// Maximum items in any general-purpose contract list.
    pub list_items: usize,
    /// Maximum CEL operations for one rule evaluation.
    pub evaluation_operations: u64,
    /// Maximum CEL expression depth.
    pub expression_depth: usize,
    /// Maximum CEL syntax tokens and AST nodes per expression.
    pub expression_nodes: usize,
    /// Maximum logical fact input bytes (keys, values, sources and diagnostics).
    pub fact_input_bytes: usize,
    /// Maximum wall-clock time for one rule evaluation.
    pub evaluation_milliseconds: u64,
    /// Maximum duration of one complete scan.
    pub scan_seconds: u64,
    /// Maximum local SQLite queue size.
    pub queue_bytes: u64,
    /// Maximum queued finding retention.
    pub retention_days: u32,
    /// Maximum findings in one delivery batch.
    pub delivery_batch_items: usize,
    /// Initial retry delay after a failed delivery.
    pub retry_initial_seconds: u64,
    /// Maximum retry delay after repeated delivery failures.
    pub retry_max_seconds: u64,
}

impl ResourceLimits {
    /// Initial limits for schema version 1.
    pub const V1: Self = Self {
        document_bytes: 1_048_576,
        document_nesting_depth: 32,
        document_nodes: 20_000,
        string_bytes: 4_096,
        identifier_bytes: 128,
        facts_per_scan: 10_000,
        rules_per_set: 512,
        yaml_alias_replay_events: 10_000,
        yaml_alias_replay_depth: 16,
        yaml_alias_expansions_per_anchor: 64,
        expression_bytes: 16_384,
        evidence_per_finding: 128,
        list_items: 1_024,
        evaluation_operations: 50_000,
        expression_depth: 32,
        expression_nodes: 256,
        fact_input_bytes: 16_777_216,
        evaluation_milliseconds: 100,
        scan_seconds: 300,
        queue_bytes: 268_435_456,
        retention_days: 30,
        delivery_batch_items: 500,
        retry_initial_seconds: 15,
        retry_max_seconds: 3_600,
    };
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::V1
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceLimits;

    #[test]
    fn retry_window_is_ordered() {
        let limits = ResourceLimits::V1;

        assert!(limits.retry_initial_seconds < limits.retry_max_seconds);
    }
}
