# openvibes-agent

## Purpose

`openvibes-agent` is the service binary and sole composition root. It wires
configuration, identity lifecycle, collection, signed-rule evaluation,
durable findings, heartbeat, delivery, and local-only export.

## Interfaces

- CLI: `openvibes-agent <config.toml>` and local-only `export`.
- Ingest: enroll, renew, heartbeat, and finding delivery over TLS 1.3/mTLS.
- Distribution: rule-bundle fetch over mTLS.

Each online tick sends a heartbeat before one finding batch. The heartbeat
includes the scanner version, capabilities, observation time, and the optional
hostname from `openvibes-collectors::hostname()`. The hostname is only an
operator label; the certificate-bound `agent_id` remains the identity.

## Configuration

The bounded TOML configuration is documented in the architecture and sample
configuration. Hostname reporting has no setting: the agent reports the OS
value when available and otherwise omits it.

## Failure behaviour

With a distribution service, a provisioned `bundle_file` older than the
fetched bundle is expected and not reported as a rollback; a rollback from
the service itself, or in a file-only setup, still is.

A full queue (256 MiB) is backpressure, not a failed scan: matches that do
not fit are counted in `ScanReport::not_queued` and logged, and the rest of
the scan and its report (including a revocation signalled by the
distribution service) still go through.

Scanning with the distribution service: a rule set with no bundle yet
(none provisioned, none accepted, nothing fetched) reports `NoRuleBundle`,
not a configuration error. A scan that ran before the first enrollment is
due again as soon as the agent enrolls, so distribution-only rule sets are
fetched within a minute rather than a whole scan interval later. If the
distribution client cannot be built (for example a damaged stored
identity), that error is reported for each distribution-only rule set and
file-provisioned rule sets are still scanned.

A corrupt queue (`quick_check` fails, or the file is not our database) is
moved aside inside the state directory as `queue.sqlite.corrupt-<ms>` with
its journal, and a fresh queue replaces it (ADR-0003). The agent keeps
running and logs the moved file's name; the findings in it are lost, and
the next scan regenerates current findings.

Export: an inventory that would exceed the 1 MiB document limit (about 8,500
RPM packages) is not written and is reported as the inventory's error; the
finding export files are written regardless.

Enrollment: the host key is stored before the first attempt and reused for
every attempt with the same token, so a lost response is retried with the
same key and the platform returns the same identity. When the platform
revokes the identity, the agent deletes it (keeping its queue) and refuses
the token it enrolled with: it waits for a new token (`TokenRefused`), so a
revoked host cannot come back through a fleet token.

A certificate that has expired by the agent's clock (for example a laptop
switched off past its renewal window) cannot renew. The agent drops the
identity, keeps its queue, and enrolls again with its token file on the same
tick; this needs a token with uses left (a fleet token or a new one). A bare
401 never triggers this, only the certificate's own expiry.

A finding the platform refuses permanently (for example observed more than
an hour in the future by the platform's clock) is acknowledged with a
reason in `rejected_findings`. It leaves the queue like any acknowledged
finding and is counted by reason in `TickReport::rejected`; the service
logs one line per reason. One bad finding never holds up the rest.

Failure to obtain a hostname does not fail a tick; the optional field is
absent. A failed heartbeat is reported in `TickReport::heartbeat_error`
and does not hold up finding delivery in the same tick; only an explicit
revocation ends the tick. Hostname never changes enrollment, certificate
authorisation, revocation, or finding identity.

## Resource use

Measured on Fedora 44 (3,610 RPMs, collectors for processes, packages, and
ports):
- One scan takes ~0.05–0.07 s of CPU, with 18 MB peak RSS.
- Idle it uses 0 CPU and 16.7 MB RSS, on 1 thread.
- The binary is 6.3 MB.
- It opens one TLS connection per 60 s tick.

Recommended: 64 MB RAM and 400 MB disk free (the queue alone may reach
256 MiB, plus the SQLite journal and the other state databases).
Platform-side sizing is in `openvibes-platform/docs/sizing.md`.

## Test

```sh
cargo test --locked -p openvibes-agent --test service
cargo test --locked -p openvibes-transport --test platform
```
