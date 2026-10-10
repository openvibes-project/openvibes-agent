<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/openvibes-wordmark-dark.svg">
    <img src="docs/brand/openvibes-wordmark-light.svg" alt="OpenVIBES" width="560">
  </picture>
</p>

<h3 align="center">OpenVIBES Agent</h3>

<p align="center">
  The read-only endpoint agent of OpenVIBES (Open Vulnerability Inspection
  &amp; Baseline Evaluation System): it looks, evaluates, and reports, and it
  never changes the host it runs on.
</p>

---

> **AI disclosure:** OpenVIBES is built with the help of AI coding tools
> (Claude Code and Codex), and they will continue to be used. Every change
> still goes through a pull request and the full CI checks before it is
> merged. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the policy.

## What OpenVIBES is

OpenVIBES is an open-source, self-hosted vulnerability and configuration
auditing system for fleets of **1,000 to 50,000 hosts**. A small agent on
every host collects facts, evaluates signed audit rules against them, and
reports the results over mutually authenticated TLS. The platform keeps
agent identities, distributes rules, matches every host's packages against
security advisories, and ranks what to fix. Everything is self-hosted: no
vendor cloud, no telemetry, and air-gapped hosts are supported.

## The repositories

| Repository | What it is |
|---|---|
| **openvibes-agent** (this one) | The endpoint agent (Rust; Linux, Windows, macOS): collectors, signed-rule evaluation, a durable local queue, and the mTLS client. |
| [openvibes-platform](https://github.com/openvibes-project/openvibes-platform) | The server side: ingest (port 18423), rule distribution (18424), vulnerability matching and enrichment, the admin CLI, the built-in PKI, packaging, and, in progress, the web console with its AI assistant. |
| [openvibes-protocol](https://github.com/openvibes-project/openvibes-protocol) | The single source of truth for everything exchanged between agent and platform: the spec, JSON Schemas, shared valid and invalid fixtures, and the paired plan. Pinned here as the `protocol/` submodule. |

```
 host: openvibes-agent                     openvibes-platform
   collectors -> facts                       ingest        :18423  enroll, renew, heartbeat,
   signed rules -> evaluate  --- mTLS 1.3 -->                      findings, inventory
   SQLite queue -> send      <-- mTLS 1.3 ---  distribution  :18424  signed rule bundles

 with no platform: export to files (air-gapped hosts)
```

## Capabilities

### Collecting facts

Collectors run without shells or external programs, and each can be
switched on or off (`collectors`):

- **Processes** (`process.names`, `process.count`): on Linux, Windows, and
  macOS, with the same meaning on each.
- **Installed packages** (`package.names`, `package.count`): RPM 4.16+
  (SQLite database) and dpkg, including a dpkg package's source package
  and version. The RPM database is read without SQLite ever creating or
  writing a file beside it, even as root.
- **Listening ports** (`port.{tcp,udp}.{exposed,local,listeners}`, and a
  count of exposed ports): exposed means bound to a non-loopback address.
- **Services** (with a platform): listening sockets and the services behind
  them, sent when they change. The exact program behind each port (its
  process name, never a command line) comes from a small root helper the
  packages install and enable, so the agent itself stays unprivileged.
- **Process starts** (`process_events`, Linux, with a platform): threat
  alarms. Program starts come from the agent's own eBPF program (kernel 5.8+
  with BTF), or from kernel audit when eBPF can't load; the agent logs which
  and why. Alarm rules run on each start, and an alarm reaches the platform
  in seconds.
- **Operating system and running kernel:** used for inventory reports.
- **Unsupported systems:** a collector that doesn't support a system says
  so explicitly (`unsupported`), never reports empty data.

### Evaluating rules

- **Signed rule sets:** Ed25519 with trusted keys scoped per rule set, a
  signing preimage that can't be reused for anything else, and a digest.
  Expired bundles, rollbacks, and version conflicts are refused, all
  before the payload is parsed.
- **Parsing:** the JSON or YAML payload goes through a budgeted parser
  that enforces node, depth, byte, and list limits and rejects duplicate
  keys.
- **Expressions:** a small hand-written subset of CEL: `facts['key']`,
  literals, comparisons, `!`, `&&`, `||`, `in`. Every step counts against
  an operation budget and a deadline.
- **Isolation:** rules see only the pre-collected facts, never files, the
  environment, the clock, or the network. No scripting engines.
- **Missing facts:** a rule whose facts are unavailable reports
  `Unavailable`, not "no match". One rule's failure never discards the
  others.
- **MITRE ATT&CK:** a rule may carry the ATT&CK techniques it covers
  (validated, 1 to 16 pairs); the platform's Coverage page reads them.

### Reporting to the platform

- **Enrollment:** a one-time token, a P-256 host key, and a CSR. The
  certificate is renewed at two-thirds of its lifetime, and the agent
  recovers from revocation or an expired certificate by re-enrolling.
- **Transport:** TLS 1.3 only (rustls) with pinned platform CA roots,
  mutual TLS, no redirects, and an explicit proxy only (proxy environment
  variables are ignored).
- **Delivery:** a durable, deduplicating SQLite queue with a size bound.
  Findings leave the queue only when the platform acknowledges them, with
  capped backoff on failure. Queue rows are re-validated when read.
- **Findings as changes:** a match is reported when it starts, changes or
  ends, not again on every scan.
- **Heartbeats:** every minute, with the enabled collectors
  (capabilities) and a health report (scans, queue, rule sets, alarms).
- **Inventory reports:** operating system, packages, and running kernel,
  sent when they change, as changes after the first full report.
- **Rule updates:** before each scan, newer rule bundles are fetched from
  the distribution service and verified like local ones. A bad or failed
  fetch never replaces the last accepted bundle.

### Running without a platform

With no platform configured the agent never uses the network. Findings
and the package inventory are exported to files (`openvibes-agent export`)
to be carried to the platform by hand.

### Safe to run as root or SYSTEM

- **Files it reads:** the configuration, CA, token, and bundle files, and
  every folder and link on the way to them, must be owned by root or the
  agent's user and not writable by others. The token must not be readable
  by others.
- **Its own state:** the state directory is created owner-only and
  refused, never repaired, if it is insecure.
- **Special files:** FIFOs and devices are refused without blocking.
- **Exports:** writing into a directory another user controls is refused.
- **Code rules:** no `unsafe` code, no `std::process::Command`, no
  certificate-verification bypass (enforced by lints), and secrets never
  appear in logs.

### Packaging

- **RPM, .deb and Arch packages** of one binary (Fedora 44, AlmaLinux and
  Rocky 9+, Debian 12+, Ubuntu 22.04+, Arch; x86_64), signed with the
  OpenVIBES key and released with checksums: a hardened systemd unit (own
  user, system-call filter, read-only system), tested on install, upgrade
  and erase under a real systemd on each system
  ([docs/components/packaging.md](docs/components/packaging.md)). The
  website's `install.sh` (and the console's install command) adds the
  matching repository and installs it.
- **`openvibes-test alarm|finding`** ships in every package: any user can
  make the host raise the harmless test alarm or finding, to check the whole
  pipeline end to end.
- **CI:** Linux, Windows, and macOS.

## Planned

- **Service packages for Windows and macOS** (Windows service, launchd),
  with a restricted state-directory ACL on Windows.
- **Host keys in OS key stores:** TPM, Keychain, or DPAPI.
- **Release artifacts:** SBOMs and provenance (packages are already signed,
  with checksums).
- **Hardening facts** (protocol P19): sshd settings, sysctls, file modes,
  mount options and more, read by the root-facts helper, for the
  per-OS hardening rules.
- **Alpine:** an apk package collector, for the platform's OSV-based
  Alpine support.
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents.
- **More fact families** as rules need them.

## Documentation

- [`design.md`](design.md): architecture and trust boundaries.
- [`security.md`](security.md): mandatory security invariants.
- [`workflow.md`](workflow.md): CI and release expectations.
- [`docs/components/`](docs/components/): one page per crate.
- [`docs/plan/initial-implementation.md`](docs/plan/initial-implementation.md):
  milestones and progress.
- [OpenVIBES Protocol](https://github.com/openvibes-project/openvibes-protocol):
  the wire contracts, resource limits, and the plan shared with the
  platform.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the AI-assisted contribution policy.

Licensed under the [Apache License 2.0](LICENSE).

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

`.github/workflows/ci.yml` runs these checks plus a RustSec audit on Ubuntu,
then clippy and the tests on Ubuntu, Windows, and macOS (see `workflow.md`).

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
facts (running processes, installed packages, listening ports), evaluates
every rule set, and queues the matches. With a `distribution_url`, each rule
set's newer bundle is fetched from the distribution service before the scan. A fetched or provisioned bundle that fails verification, is
expired, or rolls back never replaces the last accepted bundle, which keeps
being used and must itself still be valid; nor does a failed fetch. With no `[[rule_sets]]` the agent does not scan.

### Local-only

Leave out `platform_url` and `platform_ca_file` (and the token and proxy) and
the agent never uses the network; `state_dir` is then the only required key.
Findings stay queued in the state directory until exported, for at most the
queue retention (30 days), after which they are pruned. Run the export as the
agent's service user: the state directory must be owned by the user that
opens it.

```sh
openvibes-agent export /etc/openvibes/agent.toml /media/usb
```

Each file holds up to 500 findings as a protocol `FindingExport` document,
readable by its owner only; a batch is also kept under the 1 MiB document
limit, so large findings make smaller files. Every export also writes a fresh
`openvibes-inventory-*.json` (`InventoryExport`): the installed packages from
the RPM or dpkg database (skipped, with a reason, if it would exceed 1 MiB;
the findings are exported regardless). Exported findings leave the queue once their file
is on disk, so keep the files: they are the only copy. Export refuses to run
while a platform is configured.

## Authenticated rule loading

`openvibes_rules::RuleLoader::load_json` accepts a JSON envelope containing an exact
JSON or YAML rule payload. The caller supplies scoped trusted Ed25519 keys,
current time, and the last accepted rule-set version. Successful verification
returns an immutable `VerifiedRuleSet`. See the contract document for byte
encoding, trust, parser limits, and the caller's persistence responsibilities.

Run its security regression tests with `cargo test --locked -p openvibes-rules`.
The service uses the same loader for provisioned bundle files and for bundles
fetched from the distribution service.
