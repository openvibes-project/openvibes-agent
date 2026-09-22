# ADR-0001: Use a Capability-Separated Rust Workspace

## Status

Accepted

## Context

The scanner processes untrusted host data and rules while potentially holding
privileged read access, local state access, and an mTLS identity. A monolithic
crate would make it easy for rule or collection code to acquire unrelated
capabilities. Microservices would add deployment and IPC complexity without a
demonstrated need.

## Decision

Use one process assembled from a modular Rust workspace:

- `openvibes-core` owns capability-neutral domain types and contracts.
- `openvibes-collectors` owns host observation.
- `openvibes-rules` owns rule verification and evaluation.
- `openvibes-storage` owns agent state and SQLite.
- `openvibes-transport` owns enrollment and platform communication.
- `openvibes-agent` is the composition root.

Component crates depend on `openvibes-core`, not on one another. The agent crate is
the only place that wires concrete components together.

## Rationale

Crate boundaries make unwanted capabilities and dependency direction visible
to reviewers while preserving a simple single-service deployment.

## Trade-offs

- More manifests and public interfaces than a single crate.
- Some types may need to move as contracts mature.
- The separation does not itself provide process isolation.

## Revisit Trigger

Reconsider process isolation if a collector demonstrably requires privileges
that cannot be safely dropped before parsing, evaluation, storage, and egress.
