# ADR-0002: Use Declarative CEL Rules Signed with Ed25519

## Status

Accepted

## Context

Rules must be remotely distributable without becoming a remote-code-execution
mechanism. The scanner must also reject forged, expired, and rolled-back rule
sets.

## Decision

Use a constrained declarative rule language implemented as an approved CEL
subset. General-purpose scripting engines are prohibited. Package rules in a
versioned envelope signed with Ed25519 and verify them against pinned
organizational trust roots before parsing or evaluation.

## Rationale

Declarative CEL rules are expressive enough for fact evaluation while offering
a smaller capability surface than embedded scripting. Ed25519 provides compact
keys and signatures with deterministic signing behavior.

## Trade-offs

- Rules cannot implement arbitrary algorithms or access live host state.
- The exact Rust CEL implementation must pass a security and maintenance review.
- Trust-root recovery and rotation require an explicit operational process.

## Revisit Trigger

Revisit the CEL subset only when a concrete audit rule cannot be represented
safely. Do not add general-purpose scripting as a convenience shortcut.
