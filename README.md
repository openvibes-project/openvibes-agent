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
- [OpenVIBES Protocol](https://github.com/openvibes-project/openvibes-protocol)
  for the versioned wire contracts, resource limits, and the plan shared with
  the platform's ingest service.
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

The `protocol/` submodule pins the protocol version the agent implements, and
its shared fixtures are part of the test suite:

```sh
git clone --recurse-submodules https://github.com/openvibes-project/openvibes-agent.git
```

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

# Time between scans (60 to 86400, default 3600). Every scan reports its
# matches again as new findings, so this also sets the finding rate.
# scan_interval_seconds = 3600

# Optional rule distribution service (needs platform_url; same CA, proxy, and
# client certificate). Without a port, 18424 is used. Before every scan an
# enrolled agent asks it for a newer bundle of each rule set below.
# distribution_url = "https://rules.example"

# The rule sets this agent runs, each with the keys trusted for it; the
# private signing key never reaches the agent. `bundle_file` is a signed
# bundle provisioned on the host, re-read on every scan; it may be left out
# when a distribution service is configured.
[[rule_sets]]
id = "baseline"
bundle_file = "/etc/openvibes/rules/baseline.json"
trusted_keys = [
  { issuer_key_id = "org.rules", public_key = "<unpadded base64url Ed25519 key>" },
]
```

All paths must be absolute and unknown keys are rejected. Every minute the
agent loads or enrolls its identity, renews it when due, sends a heartbeat, and
delivers queued findings. Scans run at start and then every
`scan_interval_seconds`, with or without a platform: the agent collects host
facts (running processes so far), evaluates every rule set, and queues the
matches. A fetched or provisioned bundle that fails verification, is
expired, or rolls back never replaces the last accepted bundle, which keeps
being used and must itself still be valid; nor does a failed fetch. With no `[[rule_sets]]` the agent does not scan.

### Local-only

Leave out `platform_url` and `platform_ca_file` (and the token and proxy) and
the agent never uses the network; `state_dir` is then the only required key.
Findings stay queued in the state directory until exported:

```sh
openvibes-agent export /etc/openvibes/agent.toml /media/usb
```

Each file holds up to 500 findings as a protocol `FindingExport` document,
readable by its owner only. Exported findings leave the queue once their file
is on disk, so keep the files: they are the only copy. Export refuses to run
while a platform is configured.

## Authenticated rule loading

`openvibes_rules::RuleLoader::load_json` accepts a JSON envelope containing an exact
JSON or YAML rule payload. The caller supplies scoped trusted Ed25519 keys,
current time, and the last accepted rule-set version. Successful verification
returns an immutable `VerifiedRuleSet`. See the contract document for byte
encoding, trust, parser limits, and the caller's persistence responsibilities.

Run its security regression tests with `cargo test --locked -p openvibes-rules`.
The service does not fetch rules yet; the loader is exercised as a library and
through integration tests.
