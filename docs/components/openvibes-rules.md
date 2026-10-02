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
  which only the loader can construct. The loader also checks every rule
  statically (`check_rule`, exported with the exact error): a process rule
  must compile against the `event` keys within its worst-case budget, and a
  snapshot rule must parse within the subset with valid method calls. A
  bundle with any rule that fails is refused as `InvalidRules`, so
  `rules sign`, `rules publish` and rules-check, which load what they
  sign, can never produce one. Fact types and missing facts are still
  decided per rule at scan time.
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
  key table), skipping rules whose `programs` name none of `process.exe`,
  its basename, or `process.name` (so a 15-byte `comm` never hides a
  rule); each `EventOutcome` says matched, unavailable, or failed. The
  agent cuts `exe`, `name` and `cwd` to 4 KiB (on a character boundary)
  before `set`, which refuses larger values. `process.euid` is the
  effective uid beside the real `process.uid`.
- **`CompiledEventRules::restrict()`:** holds the rules to a restricted
  set's limits (contract P14 "Restricted rule sets", board #108). A rule
  without `programs`, or with more than `RESTRICTED_RULE_PROGRAMS` (8)
  distinct entries (a repeat counts once),
  moves to `refused` with `Restricted`; every rule does when together they
  name more than `RESTRICTED_SET_PROGRAMS` (32) distinct entries. The
  caller decides which sets are restricted (the agent, from its own
  configuration). **`names(event)`** says whether any rule's prefilter
  lets the event through, so a caller can skip building inputs for it.
- **`CompiledEventRules::evaluate_within(bundle, event, clock, &mut budget)`:**
  the same, drawing every rule's operations from one per-start `budget`
  shared across rule sets (contract P14, board #105; the agent starts it
  at 50,000).
  - Each rule may use at most what's left (and never more than its own
    limit), and what it used is taken off.
  - When a rule runs out of the shared budget, the remaining rules aren't
    run, and it returns `true` (cut). A cut rule has no outcome, so it's
    neither a failure nor unavailable.
  - `evaluate` is this with no shared budget.

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
