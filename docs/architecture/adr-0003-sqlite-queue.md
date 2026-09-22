# ADR-0003: Use SQLite for Agent-Owned Durable State

## Status

Accepted

## Context

Findings must survive restarts and intermittent network failures. The queue
needs bounded retention, atomic updates, acknowledgement tracking, replay-safe
identifiers, and corruption handling.

## Decision

Use SQLite within a dedicated agent-owned state directory. Initially rely on
operating-system file permissions and storage protection rather than
application-level encryption.

## Rationale

SQLite supplies proven transactions and crash recovery and avoids designing a
custom journal format. A single local writer does not require a separate
database service.

## Trade-offs

- The selected Rust binding and bundled/native SQLite strategy require review.
- SQLite files may retain deleted content until maintenance occurs.
- OS storage protection does not protect data from an already privileged local
  attacker.

## Revisit Trigger

Require application-level encryption if finding data is reclassified or the
threat model must protect it from privileged offline access.
