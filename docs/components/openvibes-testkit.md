# openvibes-testkit

## Purpose

Test-only mock platform: a real `rustls` server backed by an `rcgen` CA that
answers one scripted reply per connection. It is never a runtime
dependency.

## Interfaces

- **`Pki`:**
  - `roots_pem`: the mock CA's root certificates;
  - `issue_client`: issues a client certificate for a CSR;
  - `server_config(require_client_cert, tls12_only)`: a server TLS
    configuration.
- **`serve(config, handlers)`:** serves one scripted `Handler` per
  connection. It returns the base URL and a channel of what each request
  looked like (`Seen`: path, body, whether a client certificate was sent).
- **Reply helpers:** `json`, `status`, and `Reply`.

## Configuration

None.

## Failure behaviour

Test helpers panic on misuse; that is the intent.

## Test

It is exercised by the agent and transport integration tests.
