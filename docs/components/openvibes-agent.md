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

Failure to obtain a hostname does not fail a tick; the optional field is
absent. A heartbeat transport failure is reported through `TickReport` and
normal retry behaviour. Hostname never changes enrollment, certificate
authorisation, revocation, or finding identity.

## Test

```sh
cargo test --locked -p openvibes-agent --test service
cargo test --locked -p openvibes-transport --test platform
```
