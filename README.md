# OpenVIBES Agent

OpenVIBES (Open Vulnerability Inspection & Baseline Evaluation System) is an
open-source vulnerability management system. The OpenVIBES Agent is its
read-only, cross-platform endpoint auditing agent, written in Rust. It collects
host facts, evaluates authenticated declarative rules, queues findings locally,
and sends them to the OpenVIBES Platform over mutually authenticated TLS.

The workspace implements versioned contracts, authenticated rule loading,
bounded evaluation of an approved CEL subset, durable SQLite state, and the
mTLS platform lifecycle (enrollment, renewal, revocation recovery, heartbeats,
and finding delivery). Native collection is still planned. See:

- [`design.md`](design.md) for architecture and trust boundaries.
- [`security.md`](security.md) for mandatory security invariants.
- [`workflow.md`](workflow.md) for CI and release expectations.
- [`docs/contracts-v1.md`](docs/contracts-v1.md) for versioned wire contracts
  and initial resource limits.
- [`docs/plan/initial-implementation.md`](docs/plan/initial-implementation.md)
  for the first implementation milestones.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) for the AI-assisted contribution policy.

Licensed under the [MIT License](LICENSE).

## Workspace

| Crate | Responsibility |
|---|---|
| `openvibes-agent` | Composition root and service lifecycle |
| `openvibes-core` | Capability-neutral domain types and orchestration contracts |
| `openvibes-collectors` | Read-only, platform-specific host observation |
| `openvibes-rules` | Signed rule verification and bounded CEL evaluation |
| `openvibes-storage` | SQLite-backed agent-owned state and delivery queue |
| `openvibes-transport` | Enrollment, mTLS identity, and platform communication |
| `openvibes-testkit` | Test-only mock platform (dev-dependency, never shipped) |

Dependency direction is inward toward `openvibes-core`. Component crates must not
depend on one another; `openvibes-agent` wires them together.

## Local verification

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo test --locked --workspace --all-features
cargo doc --locked --workspace --all-features --no-deps
```

The full CI template remains inactive at `.github/ci.yml.example` until its
action pins, tool versions, and final binary name are resolved.
`.github/workflows/windows.yml` runs clippy and the tests on Windows.

## Running the agent

```sh
openvibes-agent /etc/openvibes/agent.toml
```

```toml
# Agent API of the platform. Without a port, 18423 is used; the platform's
# web interface is a separate service on 443.
platform_url = "https://platform.example"
# The only CA trusted to issue the platform's server certificate.
platform_ca_file = "/etc/openvibes/platform-ca.pem"
# Private agent-owned state; created 0700 if missing, refused if insecure.
state_dir = "/var/lib/openvibes"
# Single-use token for first enrollment; read only while unenrolled.
enrollment_token_file = "/etc/openvibes/enrollment-token"
# Optional explicit proxy; proxy environment variables are ignored.
# proxy_url = "http://proxy.example:3128"
```

All paths must be absolute and unknown keys are rejected. Every minute the
agent loads or enrolls its identity, renews it when due, sends a heartbeat, and
delivers queued findings. Scanning arrives with the first native collector.

## Authenticated rule loading

`openvibes_rules::RuleLoader::load_json` accepts a JSON envelope containing an exact
JSON or YAML rule payload. The caller supplies scoped trusted Ed25519 keys,
current time, and the last accepted rule-set version. Successful verification
returns an immutable `VerifiedRuleSet`. See the contract document for byte
encoding, trust, parser limits, and the caller's persistence responsibilities.

Run its security regression tests with `cargo test --locked -p openvibes-rules`.
The service does not fetch rules yet; the loader is exercised as a library and
through integration tests.
