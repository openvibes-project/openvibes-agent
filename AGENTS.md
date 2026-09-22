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

The `protocol/` git submodule pins the `openvibes-protocol` version this agent implements; clone with `--recurse-submodules` or run `git submodule update --init`. `crates/openvibes-core/tests/protocol_fixtures.rs` checks every shared fixture against the Rust contract types and fails if the submodule is missing. When the protocol changes, bump the submodule in the same change that updates the agent.

## Architecture

Read-only endpoint auditing agent: collect host facts → evaluate signed declarative rules → queue findings in SQLite → send to the OpenVIBES Platform over mTLS. Remediation is an explicit non-goal.

Workspace crates depend **inward on `openvibes-core` only**; component crates must never depend on each other. `openvibes-agent` (the binary) is the sole composition root that wires them together.

- `openvibes-core` — versioned wire contracts (`contracts.rs`) and `ResourceLimits::V1` (`limits.rs`). Must not touch filesystem, OS APIs, SQLite, or network. Contract types validate via the `Validate` trait against explicit limits.
- `openvibes-rules` — the most substantial component:
  - `loader.rs`: `RuleLoader::load_json` verifies a `SignedRuleEnvelope` (scoped Ed25519 trust keys, domain-separated signing preimage, digest, expiry, rollback/version-conflict against caller-supplied `AcceptedVersion`) **before** parsing the payload. Returns `VerifiedRuleSet`, constructible only by the loader. The loader never reads clocks or disk — time and accepted-version state are injected via `LoadContext`, and persisting `AcceptedVersion` is the caller's job.
  - `parsing.rs`: budgeted `serde` visitor enforcing node/depth/byte/list limits and duplicate-key rejection for both JSON and YAML (`serde-saphyr`). Do not replace it with `Value::deserialize` or `IgnoredAny` — that bypasses the budgets.
  - `subset.rs` + `evaluation.rs`: hand-written CEL subset (only `facts['key']`, literals, `!`, unary `-`, `&& || == != < <= > >= in`). A byte-level `preflight` allowlist runs before `cel::PrattParser`; then type-check, then interpret. Every step charges a `Meter` (operation budget, wall-clock deadline, clock-regression detection). Facts from collectors that reported errors yield `RuleOutcome::Unavailable`, and one rule's failure never discards others.
- `openvibes-storage` — `SqliteQueue` (bundled `rusqlite`): durable, deduplicating FIFO bounded by `queue_bytes` via `max_page_count` (over-limit and disk-full both surface as `StorageError::Full`). `deliver` takes the transport as a closure (so storage never depends on transport) and removes only findings that were in the sent batch *and* named by a valid acknowledgement; acknowledged IDs are remembered for `retention_days` so replays are not resent, and other batch members get capped exponential backoff. Time is injected (`now_unix_ms`), never read. Stored rows are untrusted: re-validated on read, and invalid rows are deleted. Schema is versioned via `PRAGMA user_version`. `RuleStore` persists each rule set's accepted envelope plus `AcceptedVersion` fields in a *separate* database (a full queue must never block rule acceptance) and re-checks the rollback floor inside a `BEGIN IMMEDIATE` transaction; the agent converts to/from `AcceptedVersion` and re-verifies the cached envelope through the loader. Both databases share `db::open_database` (no-symlink open, `quick_check`, `application_id` so one kind never opens as the other). `IdentityStore` holds the single host identity (key, chain, agent ID) in a third database kind; replacement is atomic and `secure_delete` overwrites old keys. Failure policies are in ADR-0003. `prepare_state_dir` creates/validates the state directory (absolute, no `..`, not a link; on Unix owner-only `0700`, owned by the effective user via `rustix`, no ancestor renamable by others); existing insecure directories are rejected, never repaired. Database files are refused if linked or foreign and set to `0600`. Windows ACLs are left to the installer.
- `openvibes-transport` — `PlatformClient` (blocking `ureq` over `rustls`/`ring`, ADR-0005): TLS 1.3-only provider, pinned platform CA roots, `max_redirects(0)` with non-2xx mapped to `Rejected`, explicit proxy only, timeouts and body limits from `ResourceLimits`. `HostKey` generates the P-256 key and CSR (`rcgen`); `ClientIdentity` holds the issued chain for mTLS. The HTTP API is specified in the protocol repo (`openvibes-protocol/spec/contracts-v1.md`). `tests/platform.rs` runs against the `openvibes-testkit` mock platform.
- `openvibes-collectors` — scaffold only (descriptor stub).
- `openvibes-agent` — the binary is `openvibes-agent <config.toml>`: `load_config` reads a size-bounded TOML file (`deny_unknown_fields`, absolute paths only) and `Service::tick` runs once a minute (identity → renewal → heartbeat → one delivery batch). A failed renewal is reported in `TickReport` but never blocks delivery while the certificate is still valid. The agent API port defaults to 18423 (`DEFAULT_PLATFORM_PORT`); the platform GUI on 443 is separate. `tests/vertical_slice.rs` is the rule-path end-to-end test (signed rule → evaluation → queue → mock platform). Also a library holding the identity lifecycle: `load_or_enroll` loads the stored identity or enrolls with a token, storing it only after the issued chain parses; `renew_if_due` rotates the key at two thirds of the locally measured lifetime and refuses a renewal for another agent; `forget_if_revoked` deletes the identity only on the structured `TransportError::IdentityRevoked`, never a bare 401/403. `tests/enrollment.rs` is the Milestone 4 end-to-end test (enroll → restart → mTLS delivery → renewal → revocation → re-enrollment).
- `openvibes-testkit` — `publish = false`, dev-dependency only: the rustls mock platform and `rcgen` CA shared by transport and agent tests. Never a runtime dependency.

Limits may be tightened relative to `ResourceLimits::V1` but never raised above it (`parsing::validate_limits`, `Evaluator::new`). Error enums (`LoadError`, `EvaluationError`) are fixed categories that deliberately never echo input content.

The signing-preimage byte format and finding-ID derivation are wire contracts documented in `openvibes-protocol/spec/contracts-v1.md` and pinned by tests in `crates/openvibes-rules/tests/loading.rs`; changing them is a contract change.

## Security invariants (from `security.md` — non-negotiable)

- `clippy.toml` bans `std::process::Command` and certificate-verification bypass methods; extend it when adding a crate with a similar escape hatch.
- Every crate has `#![forbid(unsafe_code)]` (also workspace lint); no exceptions in first-party code.
- No `std::process::Command`, shells, or external utilities anywhere in first-party code. OS access is via std or reviewed native Rust bindings.
- Never mutate audited host state; writes only to agent-owned state/log dirs.
- Rules get only immutable pre-collected facts — no filesystem, env, clock, or network access. No general-purpose scripting engines (Rhai explicitly banned). CEL functions are deny-by-default.
- Every parser of untrusted input (host data, rules, config, queue records, network responses) enforces byte, depth, string, collection, and count limits.
- TLS via `rustls`; no certificate-verification bypass in production builds.
- Secrets and sensitive collected values never appear in logs or error messages (see `EnrollmentToken`'s redacting `Debug`).
- Security-sensitive changes need negative/failure-path tests.

## Project state and docs

- `design.md`, `security.md`, `workflow.md`, ADRs in `docs/architecture/`.
- Wire contracts and the synced agent–collector plan live in the separate `openvibes-protocol` repository (pinned here as the `protocol/` submodule; sibling checkout `../openvibes-protocol`, https://github.com/openvibes-project/openvibes-protocol). Any change to what crosses the agent–platform boundary lands there first and updates its `PLAN.md` for both sides.
- Progress is tracked as checkboxes in `docs/plan/initial-implementation.md`; update it when completing milestone items.
- The full CI is intentionally inactive at `.github/ci.yml.example`. Do not move it into `.github/workflows/` (GitHub runs every `.yml` there) until actions are pinned to full commit SHAs and the binary name is resolved. The one active workflow, `.github/workflows/windows.yml`, runs clippy and tests on Windows so `cfg(not(unix))` code gets compiled; every action in a workflow must be pinned to a full commit SHA with the version in a comment.
