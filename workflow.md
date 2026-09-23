# CI/CD Workflow Specification

## 1. Status

Active as `.github/workflows/ci.yml`: the security-and-lint gate (section 4.1,
items 1–4 and 6 via `clippy.toml`) and the native Ubuntu, Windows, and macOS
test suite (4.2). Not yet active: dependency license and source-policy checks
(4.1 item 5) and target build verification (4.3), which arrive with packaging
in Milestone 6. The binary target is `openvibes-agent`.

## 2. Triggers and Permissions

The workflow runs on pushes to `main` and pull requests targeting it. It may also support manual dispatch for diagnosis.

The workflow must declare minimal permissions:

```yaml
permissions:
  contents: read
```

Additional permissions are granted only to a separate job that demonstrably
needs them. Jobs use explicit timeouts, and concurrency cancellation should
stop superseded runs on the same pull request or branch.

## 3. Pipeline Structure

```text
GitHub pull request or push
             |
             v
  Security audit and lint gate
             |
             +----------------------+
             |                      |
             v                      v
  Native multi-OS tests     Target build verification
```

The test and target-build matrices run in parallel after the security-and-lint
gate succeeds.

## 4. Required Jobs

### 4.1 Security Audit and Code Hygiene

Runs on Ubuntu and performs:

1. `cargo fmt --all --check`
2. `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code`
3. Documentation build with warnings denied
4. RustSec advisory audit
5. Dependency license and source-policy checks
6. Automated forbidden-API policy for external process execution

The repository commits `Cargo.lock`, uses the current stable Rust toolchain, and
pins all CI actions to full commit SHAs.

### 4.2 Native Multi-OS Test Suite

Runs `cargo test --locked --workspace --all-features` on:

- Ubuntu
- Windows
- macOS

This verifies native behavior on the runner architectures. Platform-specific
collector tests must use controlled fixtures and include partial-failure and
permission-denied cases.

The supported-platform policy covers vendor-supported Windows and macOS
releases and mainstream, actively supported Linux distributions. Because hosted
runner images do not cover every supported release, each release records the
exact CI images and versions tested, with additional packaging or smoke tests
used where required.

### 4.3 Target Build Verification

Initial targets are:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-apple-darwin`

Cross compilation proves that a target builds; it does not prove that the
artifact works on that target. Native or emulated smoke tests should be added
where practical. Runner images and linker availability must be validated when
the workflow is activated.

Every expected binary must exist. Artifact upload uses
`if-no-files-found: error`; silently missing output is a failed build.

## 5. Release Pipeline Requirements

Release publishing should be a separate, protected workflow. Before external
distribution it must provide:

- Reproducible, locked release builds
- Platform packaging and service-installation tests
- SHA-256 checksums
- Cryptographic artifact signatures
- Software bill of materials
- Build provenance/attestation
- Explicit approval through a protected release environment

Release credentials must not be available to pull-request jobs.

## 6. Workflow Maintenance

- Pin actions and build tools to immutable versions or full commit SHAs.
- Use reviewed pull requests to update pins.
- Add job timeouts and concurrency controls.
- Cache only safe build outputs; caches are never a trust boundary.
- Do not run untrusted pull-request code with write permissions or secrets.
- Keep the documented matrix synchronized with the executable workflow.
