# Initial Scanner Implementation Plan

## Goal

Deliver a thin, testable vertical slice that accepts authenticated declarative
rules, evaluates them against controlled facts, durably queues a finding, and
hands it to a mock transport. Add real host collection and platform networking
only after those contracts are stable.

## Milestone 0: Foundation

- [x] Establish the capability-separated Cargo workspace.
- [x] Enforce `unsafe_code = "forbid"` in workspace policy and every crate.
- [x] Pin the current stable Rust toolchain used by the scaffold.
- [x] Record accepted architecture decisions.
- [x] Select and pin CI actions and security-tool versions.
- [x] Activate `.github/workflows/ci.yml` (license policy and target builds
  follow with Milestone 6).

Exit criteria: an offline checkout formats, lints, tests, and documents without
warnings.

## Milestone 1: Contracts and Limits

Define versioned, serialization-independent Rust types and example JSON/YAML
documents for:

- [x] Collected facts and collector errors
- [x] Signed rule envelopes and CEL rule metadata
- [x] Findings, severity, confidence, and stable identifiers
- [x] Heartbeats and scanner capabilities
- [x] Enrollment and delivery acknowledgements

At the same time, choose concrete maximum sizes, nesting depth, evaluation
budget, scan deadline, queue limit, retention period, and retry policy.

- [x] Record conservative version 1 resource limits.
- [x] Add equivalent JSON and YAML rule-set fixtures.
- [x] Reject incompatible versions and oversized documents in tests.
- [ ] Review the concrete limits against representative endpoint inventories.
- [x] Add JSON Schema documents for platform-side validation and SDK generation
  (in `openvibes-protocol/schemas/v1`).

Exit criteria: schema fixtures round-trip, reject unknown incompatible versions,
and fail safely at every declared limit.

## Milestone 2: In-Memory Vertical Slice

- [x] Implement a deterministic synthetic collector for tests.
- [x] Evaluate a minimal approved CEL subset against immutable facts.
- [x] Verify Ed25519 rule envelopes before parsing the rule payload.
- [x] Enforce scoped trust keys, expiry, and rollback against supplied state.
- [x] Return an immutable verified rule-set type from bounded JSON/YAML loading.
- [x] Test tampering, bad signatures, rollback, expiry, duplicate fields, parser
  budgets, and malformed YAML after an explicit document end marker.
- [x] Produce findings through an in-memory queue and mock transport.
- [x] Test exhausted evaluation budgets and partial collection failure.

Exit criteria: one end-to-end test proves that only an authenticated rule can
turn a collected fact into a deliverable finding.

## Milestone 3: Durable SQLite Queue

- [x] Select a maintained SQLite binding and decide bundled versus system SQLite.
- [x] Create the queue schema, migrations, bounded retention, acknowledgements,
  and retry scheduling.
- [x] Create state paths securely on Linux and macOS.
- [ ] Restrict the Windows state directory ACL (installer, Milestone 6).
- [x] Test restart recovery, corruption detection, queue-full behavior, and replay.
- [x] Test recovery from a process killed mid-transaction.
- [x] Persist accepted rule bundles and their version/preimage-digest records
  atomically. Restore them before loading updates or cached bundles, and
  serialize concurrent acceptance to preserve the rollback floor.

Exit criteria: findings survive restart and acknowledged records are not sent
again.

## Milestone 4: Enrollment and Transport

- [x] Select the HTTP and TLS stack (ADR-0005).
- [x] Implement single-use token enrollment against a mock platform endpoint.
- [x] Store the issued host identity in the private state directory.
- [ ] Evaluate OS key stores (TPM, Keychain, DPAPI) for the host key.
- [x] Configure `rustls`, server verification, mTLS, timeouts, payload limits,
  and disabled redirects.
- [x] Add delivery retry jitter.
- [x] Implement certificate renewal with key rotation and revocation recovery.
- [x] Schedule renewal, delivery, and heartbeats in the agent service loop
  (`openvibes-agent <config.toml>`, one tick per minute).

Exit criteria: a local integration environment can enroll, reconnect using
mTLS, deliver an idempotent finding, and recover from a revoked identity.

## Milestone 4b: Local-Only Route

Paired with protocol milestone P3 in `openvibes-protocol/PLAN.md`.

- [x] Run standalone when no platform is configured, with no network use.
- [x] Agree the export file format in the protocol repository
  (`FindingExport`: unsigned, random `install_id`, export consumes).
- [x] Add an `export` command writing queued findings in that format
  (`openvibes-agent export <config.toml> <dir>`).

Exit criteria: an agent with no platform configured never opens a network
connection, keeps its findings across restarts, and exports them to a file
that validates against the protocol schema.

## Milestone 5: First Native Collector

- [x] Choose one low-risk fact family with useful cross-platform semantics
  (running processes: `process.names`, `process.count`).
- [x] Document required privileges for every OS implementation
  (`crates/openvibes-collectors/src/processes.rs`).
- [x] Implement without shells or external processes (Linux: `/proc` via std;
  Windows and macOS: reviewed `sysinfo`, its `kill*` methods banned).
- [x] Use fixtures and native CI tests for malformed, missing, and denied
  inputs (Linux fixtures; live and canonicalisation tests on Ubuntu,
  Windows, and macOS CI).

Exit criteria: the collector emits the same canonical fact semantics on Linux,
Windows, and macOS or explicitly reports an unsupported field.

## Milestone 6: Service Packaging and Hardening

- Add Linux service, Windows service, and macOS launchd packaging.
- Apply per-platform service identity and sandbox restrictions.
- Add installation, upgrade, rollback, and uninstall tests.
- Produce signed artifacts, checksums, SBOMs, and provenance.

Exit criteria: release candidates install and run under restricted identities on
the documented support matrix.

## Immediate Next Slice

Select a CEL implementation that can enforce the approved subset and operation,
depth, memory, and wall-time budgets. Accept only `VerifiedRuleSet` as evaluator
input, bind immutable typed facts as a flat map, and test a synthetic
`process.names` fact against the authenticated example rule. Missing facts or
evaluation errors must remain distinguishable from a successful non-match.
