# ADR-0003: Use SQLite for Agent-Owned Durable State

## Status

Accepted

## Context

Findings must survive restarts and intermittent network failures. The queue
needs bounded retention, atomic updates, acknowledgement tracking, replay-safe
identifiers, and corruption handling.

## Decision

Use SQLite within a dedicated agent-owned state directory. Initially rely on
operating-system file permissions and storage protection rather than
application-level encryption.

Access SQLite through `rusqlite` with the `bundled` feature and default features
disabled. Every platform then links the same SQLite version, pinned by
`Cargo.lock`, instead of whatever system library a host provides.

### Failure Policies

- **Corrupt database.** `SqliteQueue::open` runs `PRAGMA quick_check` and
  returns `StorageError::Corrupt` for a failed check, a non-SQLite file, or a
  database with foreign tables. The queue never repairs or deletes the file
  itself. The agent (composition root) moves the file aside inside the state
  directory, emits a health event, and opens a fresh queue. Findings in the
  corrupt file are lost; the next scan regenerates current findings.
- **Invalid stored records.** Rows are untrusted on read. A row that exceeds
  `document_bytes`, fails to parse, fails contract validation, or whose body ID
  differs from its key column can never be delivered, so `deliver` deletes it
  and sends the rest of the batch. Until health events exist, the deletion is
  silent; reporting a discard count is required once they do.
- **Full queue or disk.** Writes past `queue_bytes` and a full disk both return
  `StorageError::Full` with nothing written. The caller applies backpressure; no
  existing finding is evicted to make room.
- **Invalid rule bundle records.** Unlike findings, a rule bundle record that
  fails validation is reported as `StorageError::Corrupt` and never deleted or
  treated as absent: that would silently remove the rollback floor. The agent
  must not load cached or updated bundles for that rule set until an operator
  resolves it.
- **Invalid identity record.** A damaged host identity is `Corrupt`, never
  treated as absent: re-enrollment needs an operator-issued token, so the
  agent must report it rather than silently lose its identity.
- **Wrong database kind.** The queue, rule store, and identity store live in
  separate files so a full queue cannot block persisting an accepted bundle
  or a rotated identity. Each is stamped
  with its own `PRAGMA application_id`; opening one as the other is `Corrupt`.
- **Insecure state path.** `prepare_state_dir` and database opens return
  `StorageError::InsecurePath` for a relative or `..` path, a symlink or
  hard link, a directory with group/other access or not owned by the agent's
  effective user, or an ancestor another user could rename entries in. The
  agent refuses to start rather than repairing permissions, since loose
  permissions may mean the state was already tampered with. On Windows these
  ownership checks are not performed; the installer must set an ACL limited
  to SYSTEM and Administrators.
- **Newer schema.** An unknown `user_version` returns
  `StorageError::UnsupportedSchema`; the queue is left untouched for a newer agent.

## Rationale

SQLite supplies proven transactions and crash recovery and avoids designing a
custom journal format. A single local writer does not require a separate
database service.

## Trade-offs

- SQLite security fixes arrive only through a `libsqlite3-sys` update and an
  agent release, not through host OS patching.
- The bundled C library is compiled at build time, which needs a C toolchain.
- Deleted content is overwritten (`secure_delete`), at some write cost.
- OS storage protection does not protect data from an already privileged local
  attacker.

## Revisit Trigger

Require application-level encryption if finding data is reclassified or the
threat model must protect it from privileged offline access.
