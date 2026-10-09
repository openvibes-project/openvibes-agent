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

- ATT&CK mapping (protocol P18): `Rule.attack`, 1 to 16 distinct
  `AttackRef { tactic, technique }` pairs (`TA0002`, `T1059.004`).
  Metadata for people: kept on a round trip (the platform stores drafts as
  `Rule`), omitted when absent, never evaluated. Agents before P18 ignore
  it as an unknown field.

- Threat alarms (protocol P14):
  - `Rule.kind` (`RuleKind::Snapshot`, the default, or `ProcessEvent`) and
    `Rule.programs` (process rules only, 1 to 64 exe paths or basenames).
    Both are omitted when serialized at their defaults, so rules signed
    before P14 keep their exact bytes and signatures;
  - `AlarmBatch`, `Alarm`, `AlarmProcess` for `POST /v1/alarms`, with the
    limits as constants: 100 alarms and 256 KiB per batch, 64 KiB per
    alarm, 256 arguments and 4096 bytes joined per process, 5 ancestors.
    `Validate` also checks what the schema cannot: `last_seen` not before
    `first_seen`, the joined-argument bound, and the serialized sizes;
  - `mask_args(exe, args)`: replaces secrets with `***` as the contract
    lists them (the basename of `exe` gates `-p`; `sh -c` scripts are masked
    word by word), always returning as many arguments;
    `cap_args(args)`: whole arguments up to 4096 bytes joined, the first
    cut on a character boundary if alone too long, nothing appended. Both
    follow `protocol/vectors/alarm-masking.json`.

- Detection explanations (protocol P17): `Detection` records the authenticated
  rule bundle preimage hash, observation time, evaluated inputs, and bounded
  expression trace. Inputs carry a status (`present`, `missing`, or
  `summarized`) and optionally a value; values may be masked. Validation
  rejects duplicate input keys, invalid hashes, excess entries/steps, and
  serialized explanations over 8 KiB. Findings and alarms can omit this field
  for older senders.

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
cargo test --locked -p openvibes-core alarm_mask   # the masking vectors
```
