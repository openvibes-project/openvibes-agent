use std::fmt;

use ovsvms_core::{PayloadEncoding, ResourceLimits, RuleSet, SignedRuleEnvelope};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::LoadError;

pub(crate) fn validate_limits(limits: ResourceLimits) -> Result<(), LoadError> {
    let defaults = ResourceLimits::V1;
    for (actual, ceiling) in [
        (limits.document_bytes, defaults.document_bytes),
        (
            limits.document_nesting_depth,
            defaults.document_nesting_depth,
        ),
        (limits.document_nodes, defaults.document_nodes),
        (limits.string_bytes, defaults.string_bytes),
        (limits.identifier_bytes, defaults.identifier_bytes),
        (limits.expression_bytes, defaults.expression_bytes),
        (limits.rules_per_set, defaults.rules_per_set),
        (limits.list_items, defaults.list_items),
    ] {
        if actual == 0 || actual > ceiling {
            return Err(LoadError::InvalidLimits);
        }
    }
    for (actual, ceiling) in [
        (
            limits.yaml_alias_replay_events,
            defaults.yaml_alias_replay_events,
        ),
        (
            limits.yaml_alias_replay_depth,
            defaults.yaml_alias_replay_depth,
        ),
        (
            limits.yaml_alias_expansions_per_anchor,
            defaults.yaml_alias_expansions_per_anchor,
        ),
    ] {
        // Zero is useful for disabling alias expansion entirely.
        if actual > ceiling {
            return Err(LoadError::InvalidLimits);
        }
    }
    Ok(())
}

pub(crate) fn envelope(
    bytes: &[u8],
    limits: ResourceLimits,
) -> Result<SignedRuleEnvelope, LoadError> {
    let value =
        parse(bytes, PayloadEncoding::Json, limits, Position::Envelope).map_err(|error| {
            if error == LoadError::DocumentTooLarge {
                error
            } else {
                LoadError::InvalidEnvelope
            }
        })?;
    serde_json::from_value(value).map_err(|_| LoadError::InvalidEnvelope)
}

pub(crate) fn rules(
    payload: &str,
    encoding: PayloadEncoding,
    limits: ResourceLimits,
) -> Result<RuleSet, LoadError> {
    let value = parse(payload.as_bytes(), encoding, limits, Position::RuleSet)?;
    serde_json::from_value(value).map_err(|_| LoadError::InvalidRules)
}

#[derive(Clone, Copy)]
enum Position {
    Envelope,
    RuleSet,
    Rules,
    Rule,
    Other,
}

struct Budget {
    limits: ResourceLimits,
    nodes: usize,
    scalar_bytes: usize,
}

impl Budget {
    fn node<E: de::Error>(&mut self) -> Result<(), E> {
        self.nodes = self
            .nodes
            .checked_sub(1)
            .ok_or_else(|| E::custom("node budget"))?;
        Ok(())
    }

    fn string<E: de::Error>(&mut self, value: &str, maximum: usize) -> Result<(), E> {
        if value.len() > maximum {
            return Err(E::custom("string budget"));
        }
        self.scalar_bytes = self
            .scalar_bytes
            .checked_sub(value.len())
            .ok_or_else(|| E::custom("scalar byte budget"))?;
        Ok(())
    }
}

// This visitor traverses even unknown fields and rejects duplicate keys before
// conversion to contracts. Never use Value::deserialize or IgnoredAny here:
// either would bypass the shared depth, scalar, item and node budgets.
struct Node<'a> {
    budget: &'a mut Budget,
    depth: usize,
    position: Position,
    string_limit: usize,
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.budget.node::<D::Error>()?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded document value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        self.budget.string::<E>(value, self.string_limit)?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        self.budget.string::<E>(&value, self.string_limit)?;
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= self.budget.limits.document_nesting_depth {
            return Err(de::Error::custom("depth budget"));
        }
        let maximum = if matches!(self.position, Position::Rules) {
            self.budget
                .limits
                .rules_per_set
                .min(self.budget.limits.list_items)
        } else {
            self.budget.limits.list_items
        };
        let position = if matches!(self.position, Position::Rules) {
            Position::Rule
        } else {
            Position::Other
        };
        let mut values = Vec::new();
        loop {
            let string_limit = self.budget.limits.string_bytes;
            let next = seq.next_element_seed(Node {
                budget: self.budget,
                depth: self.depth + 1,
                position,
                string_limit,
            })?;
            let Some(value) = next else { break };
            if values.len() == maximum {
                return Err(de::Error::custom("list budget"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= self.budget.limits.document_nesting_depth {
            return Err(de::Error::custom("depth budget"));
        }
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.budget.node::<A::Error>()?;
            self.budget
                .string::<A::Error>(&key, self.budget.limits.string_bytes)?;
            if values.len() >= self.budget.limits.list_items || values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key or mapping budget"));
            }
            let position = match (self.position, key.as_str()) {
                (Position::RuleSet, "rules") => Position::Rules,
                _ => Position::Other,
            };
            let string_limit = match (self.position, key.as_str()) {
                (Position::Envelope, "payload") => self.budget.limits.document_bytes,
                (Position::Rule, "expression") => self.budget.limits.expression_bytes,
                _ => self.budget.limits.string_bytes,
            };
            let value = map.next_value_seed(Node {
                budget: self.budget,
                depth: self.depth + 1,
                position,
                string_limit,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn parse(
    bytes: &[u8],
    encoding: PayloadEncoding,
    limits: ResourceLimits,
    position: Position,
) -> Result<Value, LoadError> {
    if bytes.len() > limits.document_bytes {
        return Err(LoadError::DocumentTooLarge);
    }
    let mut budget = Budget {
        limits,
        nodes: limits.document_nodes,
        scalar_bytes: limits.document_bytes,
    };
    let node = Node {
        budget: &mut budget,
        depth: 0,
        position,
        string_limit: limits.string_bytes,
    };
    match encoding {
        PayloadEncoding::Json => {
            let mut deserializer = serde_json::Deserializer::from_slice(bytes);
            let value = node
                .deserialize(&mut deserializer)
                .map_err(|_| LoadError::InvalidPayload)?;
            deserializer.end().map_err(|_| LoadError::InvalidPayload)?;
            Ok(value)
        }
        PayloadEncoding::Yaml => {
            let input = std::str::from_utf8(bytes).map_err(|_| LoadError::InvalidPayload)?;
            let yaml_budget = serde_saphyr::budget! {
                max_depth: limits.document_nesting_depth,
                flow_nesting_limit: limits.document_nesting_depth,
                max_documents: 1,
                max_nodes: limits.document_nodes,
                max_events: limits.document_nodes * 2 + 4,
                max_total_scalar_bytes: limits.document_bytes,
                max_total_comment_bytes: limits.document_bytes,
                max_aliases: limits.yaml_alias_replay_events,
                max_anchors: limits.list_items,
                max_recorded_anchor_events: limits.document_nodes,
                max_recorded_anchor_bytes: limits.document_bytes,
                max_inclusion_depth: 0,
                max_merge_keys: 0,
            };
            // The high-level YAML API tolerates malformed trailing content after
            // an explicit document end. Scan the entire stream first to reject it.
            if serde_saphyr::budget::parse_yaml(
                input,
                yaml_budget.clone().expect("budget macro returns Some"),
            )
            .map_err(|_| LoadError::InvalidPayload)?
            {
                return Err(LoadError::InvalidPayload);
            }
            let options = serde_saphyr::options! {
                budget: yaml_budget,
                duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
                merge_keys: serde_saphyr::MergeKeyPolicy::Error,
                strict_booleans: true,
                reject_unsupported_tags: true,
                with_snippet: false,
                emit_comments: false,
                alias_limits: serde_saphyr::alias_limits! {
                    max_total_replayed_events: limits.yaml_alias_replay_events,
                    max_replay_stack_depth: limits.yaml_alias_replay_depth,
                    max_alias_expansions_per_anchor: limits.yaml_alias_expansions_per_anchor,
                },
            };
            serde_saphyr::with_deserializer_from_str_with_options(input, options, |de| {
                node.deserialize(de)
            })
            .map_err(|_| LoadError::InvalidPayload)
        }
    }
}
