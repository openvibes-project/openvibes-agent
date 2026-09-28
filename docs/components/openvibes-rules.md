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
  `NoMatch`, `Unavailable`, or `Failed`. Every finding names its rule set
  (`rule_set_id`), taken from the verified bundle. One rule's failure never discards
  the others.
  `process_event` rules are skipped here.
- **CEL subset v2 (P14):** `s.startsWith('lit')`, `s.endsWith('lit')` and
  `s.contains('lit')` on a string, with one plain string literal of at most
  256 bytes; each call costs one operation per started 64 bytes of the
  receiver. Any other method, the global form, `size`, raw or bytes
  literals and non-literal indexes are refused. Allowed in both rule kinds.
- **`compile_event_rules(bundle, limits)`:** parses and type-checks every
  `process_event` rule of a verified bundle once, against the closed
  `event` key table (`EVENT_KEYS`, the contract's), and computes its
  worst-case cost from the key bounds; a rule over the operation limit, with
  an unknown key, or using `facts` is listed in `refused` and never runs.
- **`CompiledEventRules::evaluate(bundle, event, clock)`:** runs the
  accepted rules on one `ProcessEvent` (values checked by `set` against the
  key table), skipping rules whose `programs` name neither `process.exe` nor
  `process.name`; each `EventOutcome` says matched, unavailable, or failed.

## Configuration

None. Trusted keys come from the agent configuration (`[[rule_sets]]`).

## Failure behaviour

- **Loading:** fails with a fixed `LoadError`, for example `Rollback`, an
  untrusted issuer, an expired envelope, or a bad signature. Parsers run
  under node, depth, byte, and list budgets.
- **Evaluation:** every step charges an operation and wall-clock budget. A
  byte allowlist runs before the CEL parser.
- **Process rules:** refused at compile, with the error, rather than at run
  time; an accepted rule cannot exceed its budget on in-bound values (the
  compile-time bound counts every branch). A run-time failure is reported
  and never becomes an alarm.

## Test

```sh
cargo test --locked -p openvibes-rules    # the security regression suite
cargo test --locked -p openvibes-rules --test event   # process rules, protocol vectors
```
