# openvibes-rules

## Purpose

Verifies offline-signed rule envelopes and evaluates their rules, written in
an approved CEL subset, against collected facts. It has no filesystem,
operating-system, database, clock, or network access: time and state are
passed in.

## Interfaces

- **`RuleLoader::load_json(bytes, LoadContext)`:** verifies a
  `SignedRuleEnvelope` before its payload is parsed. That covers the
  per-rule-set Ed25519 `TrustedRuleKey`, the domain-separated signing
  preimage (`signing_preimage`), the digest, expiry, and the rollback floor
  against the caller's `AcceptedVersion`. It returns a `VerifiedRuleSet`,
  which only the loader can construct.
- **`Evaluator::evaluate`:** runs every rule of a verified set against a
  `FactSet` and returns a `RuleOutcome` per rule: `Match` (a `Finding`),
  `NoMatch`, `Unavailable`, or `Failed`. One rule's failure never discards
  the others.

## Configuration

None. Trusted keys come from the agent configuration (`[[rule_sets]]`).

## Failure behaviour

- **Loading:** fails with a fixed `LoadError`, for example `Rollback`, an
  untrusted issuer, an expired envelope, or a bad signature. Parsers run
  under node, depth, byte, and list budgets.
- **Evaluation:** every step charges an operation and wall-clock budget. A
  byte allowlist runs before the CEL parser.

## Test

```sh
cargo test --locked -p openvibes-rules    # the security regression suite
```
