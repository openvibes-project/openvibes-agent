# Security Policy and Contribution Guardrails

## 1. Threat Model

The scanner processes attacker-influenced host data and may require elevated
read access. A compromise could expose endpoint data, falsify audit findings,
or become a local privilege-escalation path.

Primary threats include:

1. Malicious, forged, expired, or rolled-back rule bundles.
2. Network interception, endpoint impersonation, replay, or egress hijacking.
3. Malformed host data causing parser failure, resource exhaustion, or crashes.
4. Tampering with the local queue, configuration, credentials, or executable.
5. Supply-chain compromise through Rust dependencies, CI actions, or build
   tooling.
6. Excessive service privileges magnifying an otherwise limited defect.

## 2. Inviolable Security Invariants

### 2.1 No Unsafe Application Code

- Every workspace crate uses `#![forbid(unsafe_code)]`.
- CI compiles all targets and features with `-F unsafe-code`.
- Exceptions are not allowed in first-party code. Dependencies requiring
  unsafe code must be reviewed and minimized; the Rust lint does not inspect
  dependency internals.

### 2.2 Read-Only Host Observation

- The scanner never remediates, kills or starts processes, changes registry
  keys, installs packages, or changes audited host configuration.
- Writes are restricted to documented agent-owned state and log directories.
- Agent-owned files are created with secure permissions; this is not considered
  mutation of audited host state.
- Collectors expose read-only interfaces and must have mutation-focused tests.

### 2.3 No Shell or External Process Execution

- First-party scanner code must not use `std::process::Command`, shells, PowerShell,
  `cmd.exe`, `/bin/sh`, or external utilities.
- OS interaction uses the Rust standard library or reviewed native Rust
  bindings.
- CI must include an automated forbidden-API policy in addition to code review.
- Dependencies capable of spawning processes require explicit security review.

### 2.4 Authenticated, Resource-Bounded Rules

- Rule bundles are verified before parsing and evaluation.
- Trust includes issuer identity, signature, schema version, expiration, and
  rollback protection.
- Rules evaluate immutable, pre-collected facts and have no direct host or
  network capabilities.
- Rules use a declarative model implemented as an approved CEL subset.
- General-purpose scripting engines, including Rhai, are prohibited.
- Enforced limits include operations, wall-clock time, expression depth, string
  and collection sizes, and total memory.
- CEL functions are deny-by-default and explicitly allowlisted.
- Rule envelopes are signed with Ed25519 and verified against pinned
  organizational trust roots. Trust-root rotation itself requires authenticated
  metadata signed by an already trusted key, with an explicit recovery process.

### 2.5 Least Privilege and Isolation

- Each collector documents why elevated access is needed.
- The runtime uses the least-privileged service identity supported by the host.
- Privilege dropping or isolation of privileged collection is preferred when
  feasible.
- Parsing, rule evaluation, queue handling, and network egress must not inherit
  privileges merely for implementation convenience.

## 3. Data Protection

### 3.1 Data in Transit

- Findings, heartbeats, enrollment, and rule retrieval use HTTPS with `rustls`.
- Certificate validation is mandatory. Dangerous certificate-verification
  overrides are forbidden in production builds.
- The allowed TLS versions and cipher policy must be configured explicitly.
- Mutual TLS is the endpoint identity mechanism. A single-use, short-lived
  enrollment token is exchanged for a host-bound client identity. Private-key
  protection, automatic renewal and rotation, and platform-initiated revocation
  are mandatory parts of the protocol.
- Redirects are disabled unless explicitly allowlisted. Requests use bounded
  timeouts, payload sizes, retries, and backoff.
- Application records use stable identifiers and acknowledgements to resist
  duplicate processing and replay.

### 3.2 Data at Rest

- Linux/macOS state files are created mode `0600` and owned by the scanner
  service identity. Directories are created mode `0700`.
- Windows state uses a DACL restricted to the scanner service identity and
  required administrators; broad inherited permissions are removed.
- State paths reject symlinks, hard-link surprises, reparse-point traversal,
  and path traversal.
- Queue storage is bounded and provides atomicity, corruption detection, and a
  defined disk-full policy.
- The SQLite queue initially relies on operating-system access controls and
  storage protection. Application-level encryption becomes mandatory if the
  stored finding data is later classified as sensitive beyond those controls.

### 3.3 Input Handling

- Host data, rules, configuration, queue records, and network responses are
  untrusted.
- Parsers enforce maximum byte size, nesting depth, string length, collection
  length, and record count.
- Parser errors are structured and do not crash the service.
- Secrets and unnecessarily sensitive collected values are redacted from logs.

## 4. Build and Supply-Chain Requirements

- `Cargo.lock` is committed and CI uses `--locked`.
- GitHub Actions are pinned to reviewed full commit SHAs.
- Build tools are installed at fixed versions, never from a moving Git HEAD.
- Dependencies are audited for vulnerabilities, licenses, sources, and
  unnecessary capabilities.
- Release artifacts have checksums, signatures, an SBOM, and build provenance.
- Updates to CI pins and security tooling occur through reviewed pull requests.
- Builds use the current stable Rust toolchain. CI and release notes record the
  tested vendor-supported Windows and macOS releases and mainstream,
  actively-supported Linux distributions.

## 5. Maintainer Review Checklist

- [ ] Formatting, Clippy, tests, and documentation checks pass without warnings.
- [ ] All first-party crates retain `#![forbid(unsafe_code)]`.
- [ ] No external-process execution or new mutation capability was introduced.
- [ ] Collector privileges and new native dependencies are justified.
- [ ] Rule, parser, and protocol inputs have explicit resource limits.
- [ ] No certificate-verification bypass or insecure production feature exists.
- [ ] Dependency vulnerability, license, and source-policy checks pass.
- [ ] Security-sensitive behavior includes negative and failure-path tests.
- [ ] No secret or sensitive endpoint data is exposed through logs or errors.

## 6. Vulnerability Reporting

A private vulnerability-reporting channel and response policy must be added
before public distribution. Security reports should not initially be filed as
public issues when disclosure could put deployed endpoints at risk.
