# ADR-0004: Use Token Bootstrap, mTLS Identity, and Rolling OS Support

## Status

Accepted

## Context

An unattended scanner needs a host identity without shipping reusable shared
credentials. The project must also set realistic cross-platform expectations
without promising indefinite compatibility with obsolete operating systems.

## Decision

Exchange a single-use, short-lived enrollment token for a host-bound mTLS
identity. Renew and rotate that identity automatically and support explicit
revocation. Build with stable Rust and support vendor-supported Windows and
macOS releases plus mainstream, actively supported Linux distributions. Record
the exact tested matrix for every release.

## Rationale

Token bootstrap limits initial credential exposure while mTLS provides ongoing
mutual authentication. A rolling support policy keeps security fixes available
and lets CI evolve with hosted runner availability.

## Trade-offs

- Enrollment requires time, replay, and token-consumption safeguards.
- Secure private-key storage differs by operating system.
- Not every supported OS release can run in hosted CI for every change.

## Revisit Trigger

Revisit identity storage when hardware-backed keys or enterprise device
identity integrations become product requirements.
