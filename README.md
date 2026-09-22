# OpenVIBES Agent

OpenVIBES (Open Vulnerability Inspection & Baseline Evaluation System) is an
open-source vulnerability management system. The OpenVIBES Agent is its
read-only, cross-platform endpoint auditing agent, written in Rust. It collects
host facts, evaluates authenticated declarative rules, queues findings locally,
and sends them to the OpenVIBES Platform over mutually authenticated TLS.

The workspace implements versioned contracts, authenticated rule loading, and
bounded evaluation of an approved CEL subset. Native collection, SQLite
persistence, and platform transport are still planned. See:

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

Dependency direction is inward toward `openvibes-core`. Component crates must not
depend on one another; `openvibes-agent` wires them together.

## Local verification

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo test --locked --workspace --all-features
cargo doc --locked --workspace --all-features --no-deps
```

The CI template remains inactive at `.github/ci.yml.example` until its action
pins, tool versions, and final binary name are resolved.

## Authenticated rule loading

`openvibes_rules::RuleLoader::load_json` accepts a JSON envelope containing an exact
JSON or YAML rule payload. The caller supplies scoped trusted Ed25519 keys,
current time, and the last accepted rule-set version. Successful verification
returns an immutable `VerifiedRuleSet`. See the contract document for byte
encoding, trust, parser limits, and the caller's persistence responsibilities.

Run its security regression tests with `cargo test --locked -p openvibes-rules`.
The executable remains a scaffold; the loader is currently exercised as a
library and through integration tests.
