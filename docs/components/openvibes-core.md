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
