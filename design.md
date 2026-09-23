# OpenVIBES Agent Architecture

## 1. Purpose and Scope

The OpenVIBES Agent is a cross-platform Rust service that audits endpoint state,
evaluates versioned security rules, and reports findings to the OpenVIBES Platform.
It is an observation component: remediation and host-management actions are out
of scope.

A platform connection is optional. Without one the agent runs local-only: it
never uses the network, keeps findings in its own state, and exports them to a
file on request in the protocol's format, so they can later be imported by the
platform's ingest service (for example from air-gapped hosts).

Supported operating systems are vendor-supported Windows and macOS releases and
mainstream, actively supported Linux distributions. The project builds with the
current stable Rust toolchain. Exact tested versions are recorded in the release
support matrix rather than treated as an indefinite compatibility promise.

## 2. Security and Trust Boundaries

```text
Untrusted host data          Authenticated rule bundle
        |                              |
        v                              v
+------------------+          +---------------------+
| Native collectors|          | Verify + parse rules|
+--------+---------+          +----------+----------+
         | immutable facts               |
         +---------------+---------------+
                         v
              +----------------------+
              | Bounded rule evaluator|
              +----------+-----------+
                         | findings
                         v
              +----------------------+
              | Agent-owned queue    |
              +----------+-----------+
                         | authenticated HTTPS
                         v
                  OpenVIBES Platform
```

Inputs from the host, rule distribution channel, local queue, and network are
all untrusted until validated. The evaluator receives immutable facts rather
than direct filesystem, process, registry, or network capabilities.

## 3. Components

### 3.1 Service Runtime

The runtime owns scheduling, cancellation, configuration, lifecycle, and health
reporting. Every scan has a deadline and can return partial results. A failed
collector or rule must not crash the service or discard unrelated results.

The scanner should run with the least privilege needed on each operating
system. Collector privileges must be documented individually. The design must
prefer a restricted service identity, privilege dropping, or isolation of a
minimal privileged collection component over running the entire process as
`root` or `SYSTEM`.

### 3.2 Native Collectors

Collectors read operating-system state using Rust standard-library facilities
or native Rust bindings. They must not invoke shells or external programs.
Initial collector categories are:

- Processes and listening ports
- Installed packages
- Selected configuration files and operating-system settings

Each collector implements a narrow read-only interface and returns immutable,
typed facts plus structured errors. Every collector defines input limits,
timeouts, privilege requirements, supported platforms, and partial-failure
behavior.

### 3.3 Rule Verification and Evaluation

External YAML or JSON is a serialization format, not an authority boundary.
Before parsing or evaluation, the scanner verifies a signed rule envelope that
contains at least:

- Rule-set identifier and schema version
- Monotonically increasing rule-set version
- Issuer/key identifier
- Creation and expiration timestamps
- Payload digest and digital signature

The scanner rejects unknown issuers, invalid or expired signatures, schema
versions it cannot safely interpret, and unauthorized rollbacks. It retains a
last-known-good bundle for recovery. Key rotation and revocation behavior must
be defined before remote rule delivery is enabled.

Rules use a constrained declarative model implemented as an approved CEL subset.
General-purpose scripting engines, including Rhai, are not supported. Limits
cover operations, expression depth, wall-clock time, strings, collections, and
total memory. No rule receives direct filesystem, registry, process,
environment, clock, or network access. CEL functions are explicitly allowlisted
and operate only on the immutable fact set.

### 3.4 Agent-Owned State

The scanner may write only within dedicated agent-owned state and log
locations. This exception does not permit mutation of audited host state.

The local queue uses SQLite and must provide:

- Restrictive permissions from file creation onward
- Protection against symlinks, hard links, reparse points, and path traversal
- Atomic writes and crash recovery
- Configured size limits, rotation, and backpressure
- Corruption detection and a documented recovery policy
- Stable event identifiers for replay detection and deduplication
- Defined behavior when storage is full or unavailable

Queue contents rely initially on operating-system access controls and storage
protection rather than application-level encryption. This decision must be
revisited if the finding data classification or threat model changes.

### 3.5 Transport

Findings and heartbeats are sent using authenticated HTTPS. Transport behavior
must define server trust roots, TLS version policy, connection and request
timeouts, payload limits, redirects, proxy support, retry with bounded
exponential backoff and jitter, acknowledgement, and idempotency.

Mutual TLS is the host-authentication mechanism. Initial enrollment uses a
single-use, short-lived enrollment token delivered out of band. A successful
enrollment issues a host-bound client identity; subsequent authentication uses
mTLS. Credential storage, automatic renewal, rotation, and revocation are part
of the protocol.

## 4. Versioned Data Contracts

The following contracts must be specified and versioned before collector and
platform implementations are coupled:

- Canonical collected-fact schema
- Signed rule-envelope and rule schema
- Finding/result schema, including stable IDs, severity, and confidence
- Heartbeat and scanner-capability schema
- Delivery acknowledgement and retry semantics
- Scanner/platform compatibility rules

All parsers must set explicit limits for document size, nesting, string length,
collection length, and record count.

## 5. Operational Behavior

- Scans are scheduled with bounded concurrency and explicit deadlines.
- Cancellation is cooperative and must release resources promptly.
- Partial results identify unavailable collectors and unevaluated rules.
- Invalid rules fail closed for those rules without terminating the service.
- Telemetry failure queues bounded output locally; it never causes host changes.
- Disk exhaustion, corrupted state, and clock anomalies produce structured
  health events and safe degraded behavior.
- Logs must not contain credentials, rule-signing secrets, or unnecessarily
  sensitive collected data.

## 6. Explicit Non-Goals

- Remediation or configuration changes
- Killing or starting processes
- Installing packages or software updates
- Executing arbitrary commands or scripts
- General-purpose remote administration

## 7. Accepted Baseline Decisions

1. Rules are declarative and evaluated through an approved CEL subset; arbitrary
   scripting is excluded.
2. Rule bundles use Ed25519 signatures and pinned organizational trust roots.
3. The durable local queue uses SQLite and initially relies on operating-system
   storage protection rather than application-level encryption.
4. Initial enrollment exchanges a single-use, short-lived token for an
   automatically rotated, host-bound mTLS identity.
5. The project uses stable Rust and supports vendor-supported Windows and macOS
   releases plus mainstream, actively supported Linux distributions.
6. Everything exchanged with the platform's ingest service is specified in
   the separate `openvibes-protocol` repository, together with a plan shared
   by both sides. The agent may run local-only, with file export instead of
   network delivery.

## 8. Decisions Still Required

1. Per-platform service privilege and isolation details, based on the access
   actually required by each collector.
2. Initial fact, rule, finding, heartbeat, and enrollment protocol schemas.
3. Concrete resource limits, scan intervals, retention bounds, and retry policy.
