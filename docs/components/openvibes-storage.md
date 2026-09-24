# openvibes-storage

## Purpose

Durable agent state in SQLite (bundled, so every platform runs the same
reviewed version), confined to the agent-owned state directory.

## Interfaces

- **`prepare_state_dir`:** creates or checks the state directory. It must
  be owned by the effective user with no group or other access, and no
  ancestor may let other users rename entries.
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
