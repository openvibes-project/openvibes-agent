# ADR-0005: Blocking `ureq` over `rustls` with `ring` for Platform Transport

## Status

Accepted

## Context

The scanner makes a few sequential HTTPS requests per scan cycle: enrollment,
finding delivery, and heartbeats. `security.md` requires `rustls`, pinned
server trust, explicit TLS versions, no redirects, bounded timeouts and
payloads, and mTLS host identity. The HTTP response parser is exposed to the
network, so it must be a maintained library rather than project code.

## Decision

- HTTP: `ureq` 3 with default features off and `rustls-no-provider`. It is
  blocking, so the agent needs no async runtime.
- TLS: `rustls` with the `ring` crypto provider, restricted to TLS 1.3 cipher
  suites so no older version can be negotiated. `ring` avoids the C and CMake
  build that `aws-lc-rs` needs on Windows.
- Trust: only the configured platform CA bundle (`RootCerts::Specific`);
  system and WebPKI roots are never used.
- Host identity: an ECDSA P-256 key generated with `rcgen`, enrolled through a
  CSR. P-256 client certificates interoperate with every mainstream TLS
  server stack.
- `clippy.toml` bans the certificate-verification bypass methods and
  `std::process::Command`, so these invariants fail CI rather than relying
  on review.

## Rationale

`ureq` exposes each control the security policy needs (`https_only`,
`max_redirects(0)`, explicit proxy, connect and global timeouts, header and
body limits, client certificates, custom crypto provider) with a small
dependency tree. `reqwest` would add `tokio` and `hyper` for no benefit to a
sequential client.

## Trade-offs

- `ureq` marks its `rustls` crypto-provider hook as outside its semver
  guarantees; a `ureq` minor update may need code changes. The TLS 1.3 policy
  is covered by a test against a TLS 1.2-only server.
- `ureq` enables the `rustls` `tls12` feature. It stays compiled in, but no
  TLS 1.2 cipher suite is offered.
- The private key is held in memory by `ureq` without zeroization.

## Revisit Trigger

Revisit if the agent needs concurrent requests, HTTP/2, or FIPS-validated
cryptography (which would favour `aws-lc-rs`).
