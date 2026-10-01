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

`collectors` chooses which host collectors each scan runs (default: all):

```toml
collectors = ["processes", "ports"]   # of "processes", "packages", "ports"
```

`"process_events"` is also accepted in the list (P14, Linux, with a
platform). It turns on threat alarms, described below. It is off unless
listed, so a configuration written before P14 behaves as before. The
packaged `agent.toml` of a new install lists it.

An unknown name, a repeat, or an empty list is a configuration error. A
disabled collector is not run at all (skipping `packages` also skips
reading the RPM or dpkg database) and is not a collection failure: rules
over its facts report unavailable, never compliant, and the scan is not
marked partial. Without `packages`, a local-only export writes no inventory
file and reports why. The inventory file also carries the host's `os`
(os-release `ID`, `VERSION_ID`) and `running_kernel` (P3b), which the
platform's importer needs to match vulnerabilities. The service logs the enabled collectors at start, and
every heartbeat lists them in `capabilities` (`collector.processes`,
`collector.packages`, `collector.ports`; protocol P7), so the platform can
show why a rule is unavailable on a host.

**Inventory reports (protocol P8).** With a platform and the `packages`
collector, each due scan (on the scan interval, with or without rule sets)
also collects the OS (`os_release`), the running kernel (`running_kernel`,
protocol P9) and package list, sorts it, and computes the protocol's
inventory fingerprint (P11: SHA-256 over the normalised records); a reboot
into another kernel changes the digest, so the platform learns it and can
tell an installed kernel fix from a running one. On the next tick, after heartbeat and delivery, the agent
sends an `InventoryReport` to `/v1/inventory` unless the platform already
accepted that exact inventory: the accepted digest is kept in
`inventory.sha256` in the state directory (0600), so a restart does not
resend. A failed send is reported in `TickReport::inventory_error`. A
network error or 5xx (a busy platform answers 503), 408 or 429 is retried with a back-off
(1, 2, 4 … minutes, up to an hour, per inventory; a changed inventory is
sent at once); an
inventory the platform refuses (4xx) or that is over the inventory limits
(50,000 packages, 8 MiB) is reported once and not sent again until it
changes or the agent restarts.

Changes (protocol P11): after a 2xx the agent keeps the inventory it sent
as `inventory-base.json` (0600), written before `inventory.sha256`. Later
inventories are sent as an `InventoryChanges` to `/v1/inventory/changes`
(the packages added and removed since that base) when the base's
fingerprint is the acknowledged one and the change set is at most half the
size of the full report; otherwise, and when the platform answers 409
`inventory_resync`, 404 (a platform before P11: full reports until the
agent restarts) or refuses the change set with another 4xx, the full report
is sent in the same tick. A gzip full report refused with 400 is sent again
uncompressed in the same tick (a platform before P11 reads plain JSON); if
that is accepted, full reports stay uncompressed, with no change sets,
until the agent restarts. A missing,
corrupt or mismatched base file means a full report. Both inventory
endpoints are sent gzip-compressed (`openvibes-transport`). Heartbeats list `inventory.packages` while an inventory
is available. Local-only agents, hosts without os-release, and agents
without `packages` send nothing. Measured on Fedora 44 (3,613 packages,
release build): the package read takes ~55 ms, sorting and hashing ~2 ms,
and the report is ~440 KB, sent only when packages change.

Health (protocol P12): every heartbeat carries a `health` report built by
`src/health.rs`:
- the queue's pending count, oldest age, bytes and limit, and its durable
  `dropped_total` and `rejected_total`;
- the last scan: time, interval, rule counts and each collector's outcome;
- each rule set's version and expiry in use, and why its last bundle was
  refused;
- storage errors since start, and the last clock jump.

A part of the report that would make it invalid is left out and the rest
is sent (#66): rule sets beyond 64, collectors or rejection reasons beyond
16, a negative timestamp, a version 0. The journal says what was left out
when that changes ("the health report leaves out: …", then "… is complete
again"). Only a report still invalid after that is dropped, and the rest
of the heartbeat is sent. A full queue drops its oldest findings instead of refusing new
ones (`openvibes-storage`), so every scan's matches are queued.

Finding changes (protocol P13, `src/matches.rs`): with a platform
configured, a scan does not queue its matches. It records them in a match
state kept as `matches.json` (0600, read up to 16 MiB; missing or
unreadable means nothing acknowledged), and each tick sends one
`FindingChanges` to `/v1/findings/changes` before the heartbeat, only when
something differs from the set the platform acknowledged: `started`,
`changed` (rule version, severity, message or evidence set; the start time
is kept), `ended`, and `transient` matches that started and ended between
two acknowledgements (at most 100 and 1.5 MiB; more are counted in
`transient_dropped`). A match ends only when a scan evaluates its rule
without a match, the rule is gone from its set's evaluated bundle, or its
rule set is no longer configured; unavailable or failed rules, and a set
without a usable bundle, keep it open. Current and acknowledged
matches together hold at most 500 slots and 6 MiB (an ended match keeps its
slot until the platform has its end); a new match, or a change that grows a
match, past either bound is left out and counted in
`health.matches_truncated`, so a replace always fits. Each repeat keeps the
match's start and takes the latest scan's finding id. The first delivery
(and the first after re-enrolling, or after a 409), and any diff of more
than 500 entries, is a `replace`. A 409 `findings_resync` on a diff brings
a replace in the same tick; a 409 on a replace and any other refusal or
failure back off 1, 2, 4 … minutes up to an hour. A heartbeat carries
`match_sha256` (the acknowledged digest), except while a change set or
replace is undelivered: the acknowledged set would then confirm matches
the latest scan ended. So while a change set keeps being refused (backoff
up to an hour), the platform stops refreshing its open matches, and they
age out of the console until delivery works again. An acknowledged match without a rule set (never
sent by P13) is ended by a replace. A heartbeat answered 409
`findings_resync` counts as delivered and asks for a replace unless one is
backing off. A 404 (a platform before P13) moves the current matches into
the queue in the same tick, and scans queue per scan until the agent
restarts. Local-only agents always queue per scan, so export is unchanged.

**Threat alarms (protocol P14).** With `process_events` on, an alarm
thread runs beside the one-minute loop, because an alarm cannot wait a
minute. For each process start from kernel audit it:
1. records the start in a process table, so it knows the lineage. A
   parent missing from the table is read from `/proc` and kept as
   *seeded*. The reader thread reads the direct parent as soon as the
   event arrives, so a parent that exits while the engine is busy still
   counts. That covers daemons started before the agent and
   workers forked without exec, like nginx. A seeded `exe` that this
   unprivileged agent cannot read is `argv[0]` when absolute, else
   `[comm]`, so rules should name parents with `parent.name`, not
   `parent.exe`. On Debian and Ubuntu `/bin/sh` is dash, so
   `process.name` is `dash` there: match both names, or match `argv[0]`
   in the command line. The table holds at most 32,768 entries and an
   estimated 1 MiB; exited processes stay 60 s.
2. runs every `process_event` rule of the scan's bundles on the unmasked
   values. The service hands the thread the compiled rules after each
   scan and its identity after each renewal.
3. masks each process's arguments with its own `exe` (a seeded, synthetic
   `exe` is also masked with `argv[0]`), caps them, and cuts an alarm over
   64 KiB, farthest ancestor first.
4. collapses repeats. The key is a SHA-256 of rule set, rule, `exe`,
   parent `exe` and the masked command line. A repeat within 10 minutes of
   the first match raises `count`. At most 4,096 keys are kept, oldest out.
5. queues the alarm in `alarms.sqlite`, a separate database, so a full
   finding queue never blocks alarms, and the other way round.

`alarm_id` is `alarm.` plus 16 random bytes. The first unsent alarm is
sent to `/v1/alarms` (gzip) after 5 s, in batches of at most 100 alarms
and 256 KiB. A delivered alarm whose count grew is sent again with the
same id. The platform's answer decides what happens next:
- 400 or 413: the batch is dropped and counted.
- 404 (a platform before P14): the alarms stay queued, the agent retries
  hourly, and health reports `platform_unsupported`.
- Anything else, including another 4xx or a redirect (a proxy, a moved
  host): the agent backs off from 30 s up to an hour and keeps the
  alarms.

Alarms still queued when the agent restarts are sent without waiting for
a new one.

The queue holds 1,000 unsent alarms. A new one pushes out the oldest,
counted in `dropped_total`, which is durable and never decreases. A
delivered row goes first and is not counted.

Every heartbeat carries `health.alarms`:
- the collector outcome;
- events and alarms dropped;
- alarms pending;
- `platform_unsupported`;
- the counts of rules accepted, refused, and running without a `programs`
  prefilter.

The collector outcome is `not_found` until the first exec event arrives.
The agent cannot list audit rules without `CAP_AUDIT_CONTROL`, so it
cannot tell a quiet host from a stopped auditd or a missing rule; an
outcome that stays `not_found` points to one of those. Without
`CAP_AUDIT_READ` the outcome is `permission_denied` and the agent runs on
without alarms. A local-only agent has nowhere to send alarms, so
it does not start the thread.

## Failure behaviour

Clock jumps: all agent times are UTC (Unix milliseconds), so a timezone or
daylight-saving change never matters. Each scan and tick compares how far
the wall clock moved with the monotonic clock, which cannot be set; a
difference over 5 minutes is a jump (`TickReport::clock_jump_ms`, logged).
Forward jumps accumulate as skew, and the two decisions that lose data
(queue retention pruning and dropping an expired certificate) use wall
time minus that skew, so a jump never deletes findings or the identity.
Finding timestamps keep the wall clock. The skew resets at restart.

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

Files the configuration names, and the configuration itself, are read
through `open_input_file`: a file another user could change, a
world-readable token, or a FIFO or device is refused with `InsecureFile`
(for a bundle file, reported for its rule set). Export refuses an output
directory another user could redirect (`ExportFailure::Insecure`), so an
agent running as root never writes where others choose.

Export: an inventory over the inventory limits (50,000 packages, 8 MiB; a
real RPM package is about 134 bytes) is not written and is reported as the inventory's error; the
finding export files are written regardless.

Enrollment: the host key is stored before the first attempt and reused for
every attempt with the same token, so a lost response is retried with the
same key and the platform returns the same identity. When the platform
revokes the identity, the agent deletes it (keeping its queue) and refuses
the token it enrolled with: it waits for a new token (`TokenRefused`), so a
revoked host cannot come back through a fleet token. The tick that enrolls
(first time, or again after expiry) reports `TickReport::enrolled_as`, and
the agent logs `openvibes-agent: enrolled as AGENT_ID` once; the platform's
install script waits for that line.

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

Threat alarms add one reader thread and one alarm thread. Their budget is
under +5 MB RSS and under 1 % of one core at 100 execs/s. The CI job
`alarms-kernel` measures this on each run and prints it in the "cost:"
line of its log. It runs 120 s of ~110 execs/s with varying arguments, 10
of them alarms, and measures the test process on the GitHub runner, not a
reference VM.

Recommended: 64 MB RAM and 400 MB disk free (the queue alone may reach
256 MiB, plus the SQLite journal and the other state databases).
Platform-side sizing is in `openvibes-platform/docs/sizing.md`.

## Test

```sh
cargo test --locked -p openvibes-agent --test service
cargo test --locked -p openvibes-agent --test alarms    # alarm thread, recorded audit records
bash scripts/alarms-kernel-e2e.sh                        # real kernel; needs sudo (CI: alarms-kernel)
cargo test --locked -p openvibes-transport --test platform
```
