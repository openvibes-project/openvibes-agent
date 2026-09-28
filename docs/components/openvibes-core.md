# openvibes-core

## Purpose

`openvibes-core` owns the versioned agent/platform Rust contract types,
resource limits, validation, and shared identifiers. It has no filesystem,
operating-system, database, or network access.

## Interfaces

- `Heartbeat`: authenticated agent contact report. Its optional `hostname` is
  the bounded OS-reported operator label defined by the protocol; it is
  spoofable and never identity or authorisation.
- Enrollment, renewal, finding, acknowledgement, rule-bundle, export, and
  inventory contract types.
- `Finding.rule_set_id`: the rule set whose verified bundle produced the
  finding (rule IDs are unique only within a set). Optional on the wire for
  earlier senders; the agent always sets it.
- `Validate` and `ResourceLimits::V1` for bounded validation before data is
  trusted.
- Inventory changes (protocol P11):
  - `InventoryChanges` (`base_sha256`, `sha256`, `os`, `running_kernel`,
    `added`, `removed`; at most 50,000 packages together);
  - `inventory_fingerprint(os, running_kernel, packages)`: the contract's
    fingerprint, SHA-256 over the compact JSON
    `[[os.id, os.version_id], running_kernel|null, [record, …]]`, each record
    a `NormalizedPackage` (`[manager, name, epoch, version, release, arch,
    source, source_version]`, epoch 0 and release/arch `""` when absent,
    `vendor` left out), deduplicated and sorted by its JSON text. The agent
    and the platform both use it, and it matches the protocol's test vectors;
  - `inventory_changes(base, current)`: `(added, removed)` by normalised
    record (an update is one of each);
  - `hex` and `digest_from_hex` (64 lowercase hex digits only).
- `Heartbeat.health` (P12): the optional `Health` report (`QueueHealth`,
  `ScanHealth` with each collector's `CollectorOutcome`, `RuleSetHealth` with
  an optional `BundleRefusal`, `storage_errors`, `clock_jump_s`). `Validate`
  enforces at most 16 collectors (`HEALTH_MAX_COLLECTORS`), 64 rule sets and
  16 rejection reasons; an invalid report makes the heartbeat invalid.
- `PlatformErrorCode::InventoryResync`: a 409 from the changes endpoint;
  the agent sends the full inventory.
- Finding changes (P13): `FindingChanges` (`started`, `changed`, `ended`
  as `EndedMatch`, `transient` as `TransientMatch`, `replace`, digests),
  `match_digest` (checked against `protocol/vectors/match-digest.json`) and
  `materially_differs` (rule version, severity, message, evidence as a set).
  `Validate` requires `rule_set_id`, refuses a rule listed twice, more than
  `MAX_CHANGE_ENTRIES` (500) entries or `MAX_TRANSIENT` (100) transients,
  and a `replace` with `changed` or `ended`. `MAX_MATCHES` (500) bounds an
  agent's set. `PlatformErrorCode::FindingsResync` (409), `Heartbeat.
  match_sha256` and `Health.matches_truncated`.

The authoritative wire definition is the pinned `protocol/` submodule. Rust
types must accept every valid fixture and reject every invalid fixture.

## Configuration

None. Callers pass resource limits and time values explicitly.

## Failure behaviour

Validation returns a fixed `ValidationError` category without echoing secrets
or untrusted document contents. An optional hostname is refused when present
but empty or outside the V1 string bound; absence is valid.

## Test

```sh
cargo test --locked -p openvibes-core --test protocol_fixtures
```
