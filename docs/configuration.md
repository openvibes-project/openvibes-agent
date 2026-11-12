# Configuring and running the agent

The packages and the console's install command write this file for you;
this page is for running the agent by hand or checking what a setting does.

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
# enrolled agent asks it for a newer bundle of each rule set below. Left
# out, the project's own rule sets come from the platform's host on 18424.
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

## Local-only

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
