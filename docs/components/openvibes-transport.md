# openvibes-transport

## Purpose

The agent's HTTPS client for the platform's ingest and distribution
services. It never touches disk: storing keys and certificates is the
composition root's job.

## Interfaces

- **`PlatformClient`:** `enroll`, `renew`, `heartbeat`, `deliver`, and
  `fetch_rule_bundle`.
  - TLS 1.3 only, and it trusts only the configured CA bundle.
  - No redirects; proxy environment variables are ignored.
  - Timeouts and response bodies are bounded.
- **`HostKey`:** `generate` makes a fresh P-256 key, and `from_key_pem`
  rebuilds a stored one. Either way it signs a CSR with an empty subject,
  as the protocol requires.
- **`ClientIdentity`:** the issued chain plus its key, used for mTLS.
- **`TransportConfig`:** carries `DEFAULT_PLATFORM_PORT` (18423) and
  `DEFAULT_DISTRIBUTION_PORT` (18424).

## Configuration

`platform_url`, `platform_ca_file`, `distribution_url`, and `proxy_url` in the
agent configuration.

## Failure behaviour

Errors are fixed `TransportError` categories. Only a 401 or 403 carrying a
`PlatformError` with code `identity_revoked` becomes `IdentityRevoked`; a
bare 401 or 403 is `Rejected` and never deletes the identity.

## Test

```sh
cargo test --locked -p openvibes-transport
```
