# openvibes-storage

## Purpose

Durable agent state in SQLite (bundled, so every platform runs the same
reviewed version), confined to the agent-owned state directory.

## Interfaces

- **`prepare_state_dir`:** creates or checks the state directory. It must
  be owned by the effective user with no group or other access, and only
  root and the effective user may be able to change what its path resolves
  to (the same chain check as `open_input_file`, made before anything is
  created).
- **`open_input_file`:** opens a file the agent reads but does not own
  (configuration, CA bundle, token, provisioned rule bundle). On Unix every
  entry the path passes through, as written, as resolved, and through
  every link's target, must be owned by root or the effective user; no
  directory may let others rename entries unless sticky; no file may be
  group- or other-writable. It must be a regular file, opened with
  `O_NONBLOCK | O_NOFOLLOW` on the resolved path, so a FIFO or device is
  refused instead of hanging the agent. A secret (the token) must not be
  readable by others either.
- **`check_output_dir`:** the same chain check for a directory the agent
  writes into for an operator (export).
- **`SqliteQueue` (`queue.sqlite`):**
  - holds findings durably, up to 256 MiB, for 30 days;
  - `deliver` sends one due batch of at most 500 findings and under the
    1 MiB document limit, and removes only the findings that are
    acknowledged;
  - failures back off exponentially with equal jitter.
- **`IdentityStore` (`identity.sqlite`, schema version 2):**
  - holds the host key, certificate chain, and times;
  - holds the pending enrollment key for a token (`begin_enrollment`,
    `set_pending_key`, `adopt_enrolled`);
  - refuses a revoked identity's token (`forget_revoked`, `is_refused`);
  - `replace` for renewal, and `clear` on expiry.
- **`RuleStore` (`rules.sqlite`):** the last accepted bundle and rollback
  floor for each rule set.
- **`install_id`:** a random installation id, created once.

## Configuration

`state_dir` in the agent configuration.

## Failure behaviour

- **Corrupt database:** a failed `quick_check`, a foreign file, or an
  invalid record is `StorageError::Corrupt` and is never repaired or treated
  as absent. The agent moves a corrupt queue aside (ADR-0003).
- **Version:** a newer schema version is `UnsupportedSchema`. Older
  versions are upgraded in place.
- **Full queue or disk:** returns `Full` with nothing written.

## Test

```sh
cargo test --locked -p openvibes-storage
```
