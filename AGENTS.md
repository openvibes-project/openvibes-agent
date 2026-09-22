# AGENTS.md

Guidance for AI coding agents working in this repository.

## Commands

Toolchain is pinned to Rust 1.95.0 (`rust-toolchain.toml`). CI-equivalent checks — all must pass with no warnings:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo test --locked --workspace --all-features
cargo doc --locked --workspace --all-features --no-deps
```

Single crate / single test:

```sh
cargo test --locked -p openvibes-rules                      # rule-loader security regression suite
cargo test --locked -p openvibes-rules --test loading       # one integration test file
cargo test --locked -p openvibes-rules --test loading rollback   # tests matching a name
```

Always pass `--locked`; `Cargo.lock` is committed and CI relies on it.

## Architecture

Read-only endpoint auditing agent: collect host facts → evaluate signed declarative rules → queue findings in SQLite → send to the OpenVIBES Platform over mTLS. Remediation is an explicit non-goal.

Workspace crates depend **inward on `openvibes-core` only**; component crates must never depend on each other. `openvibes-agent` (the binary) is the sole composition root that wires them together.

- `openvibes-core` — versioned wire contracts (`contracts.rs`) and `ResourceLimits::V1` (`limits.rs`). Must not touch filesystem, OS APIs, SQLite, or network. Contract types validate via the `Validate` trait against explicit limits.
- `openvibes-rules` — the most substantial component:
  - `loader.rs`: `RuleLoader::load_json` verifies a `SignedRuleEnvelope` (scoped Ed25519 trust keys, domain-separated signing preimage, digest, expiry, rollback/version-conflict against caller-supplied `AcceptedVersion`) **before** parsing the payload. Returns `VerifiedRuleSet`, constructible only by the loader. The loader never reads clocks or disk — time and accepted-version state are injected via `LoadContext`, and persisting `AcceptedVersion` is the caller's job.
  - `parsing.rs`: budgeted `serde` visitor enforcing node/depth/byte/list limits and duplicate-key rejection for both JSON and YAML (`serde-saphyr`). Do not replace it with `Value::deserialize` or `IgnoredAny` — that bypasses the budgets.
  - `subset.rs` + `evaluation.rs`: hand-written CEL subset (only `facts['key']`, literals, `!`, unary `-`, `&& || == != < <= > >= in`). A byte-level `preflight` allowlist runs before `cel::PrattParser`; then type-check, then interpret. Every step charges a `Meter` (operation budget, wall-clock deadline, clock-regression detection). Facts from collectors that reported errors yield `RuleOutcome::Unavailable`, and one rule's failure never discards others.
- `openvibes-storage` — `MemoryQueue`: bounded, deduplicating FIFO. `deliver` takes the transport as a closure (so storage never depends on transport) and removes only findings that were in the sent batch *and* named by a valid acknowledgement. SQLite persistence is Milestone 3.
- `openvibes-collectors`, `openvibes-transport` — scaffolds only (descriptor stubs). `openvibes-agent` binary just prints component names; its `tests/vertical_slice.rs` is the end-to-end test (signed rule → evaluation → queue → mock platform).

Limits may be tightened relative to `ResourceLimits::V1` but never raised above it (`parsing::validate_limits`, `Evaluator::new`). Error enums (`LoadError`, `EvaluationError`) are fixed categories that deliberately never echo input content.

The signing-preimage byte format and finding-ID derivation are wire contracts documented in `docs/contracts-v1.md` and pinned by tests in `crates/openvibes-rules/tests/loading.rs`; changing them is a contract change.

## Security invariants (from `security.md` — non-negotiable)

- Every crate has `#![forbid(unsafe_code)]` (also workspace lint); no exceptions in first-party code.
- No `std::process::Command`, shells, or external utilities anywhere in first-party code. OS access is via std or reviewed native Rust bindings.
- Never mutate audited host state; writes only to agent-owned state/log dirs.
- Rules get only immutable pre-collected facts — no filesystem, env, clock, or network access. No general-purpose scripting engines (Rhai explicitly banned). CEL functions are deny-by-default.
- Every parser of untrusted input (host data, rules, config, queue records, network responses) enforces byte, depth, string, collection, and count limits.
- TLS via `rustls`; no certificate-verification bypass in production builds.
- Secrets and sensitive collected values never appear in logs or error messages (see `EnrollmentToken`'s redacting `Debug`).
- Security-sensitive changes need negative/failure-path tests.

## Project state and docs

- `design.md`, `security.md`, `workflow.md`, ADRs in `docs/architecture/`, contracts in `docs/contracts-v1.md`.
- Progress is tracked as checkboxes in `docs/plan/initial-implementation.md`; update it when completing milestone items.
- CI is intentionally inactive at `.github/ci.yml.example`. Do not move it into `.github/workflows/` (GitHub runs every `.yml` there) until actions are pinned to full commit SHAs and the binary name is resolved.
