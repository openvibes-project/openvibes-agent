# Scanner Contracts Version 1

## Compatibility Policy

Every top-level wire document contains a required numeric `schema_version`.
Version 1 payload readers ignore additional object fields so optional fields can
be introduced compatibly. The outer signed envelope rejects unknown fields:
its signing format covers a fixed field set, so extra fields must never be
mistaken for authenticated metadata. Envelope extensions require a new signing
format and schema version. Readers reject unknown enum values, missing required
fields, invalid bounded values, and any unsupported schema version.

Inputs are size-checked before JSON or YAML decoding and semantically validated
immediately afterward. Deserialization alone does not make a document trusted.

## Identifier and Time Encoding

Identifiers contain 1 to 128 ASCII letters, digits, dots, underscores, colons,
or hyphens. They never contain paths, whitespace, control characters, or
user-facing text.

Timestamps are signed integers containing milliseconds since the Unix epoch.
Clock-based acceptance windows are enforced by the component consuming the
document; structural validation additionally requires rule-envelope expiration
to be later than creation.

## Fact Model

Version 1 facts are deliberately typed and cannot contain arbitrary nested
objects. Supported values are booleans, signed 64-bit integers, strings, and
lists of strings. Each fact has a stable namespaced key and source collector.
A fact set also carries structured collector errors so partial scans remain
observable.

The CEL binding is a flat map named `facts`, from each canonical key to its
unwrapped typed value. For example, `process.names` is a string-list fact and
the example rule uses `'sshd' in facts['process.names']`. A missing fact, or one
whose collector reported an error, produces an unavailable result rather than
silently implying compliance.

The approved subset is `facts['<literal key>']`, Boolean/integer/string
literals, `!`, unary `-`, `&&`, `||`, `==`, `!=`, `<`, `<=`, `>`, `>=`, and
`string in string_list`. Other identifiers, functions, macros, member access,
and triple-quoted strings are rejected. Every referenced fact and operand type
is checked before execution, including branches a short circuit would skip.

## Rules and Findings

A rule set contains declarative CEL rules with stable IDs, positive monotonic
versions, severity, confidence from 0 to 100, a bounded expression, and a
finding message. JSON and YAML examples live beside the contract tests:

- `crates/openvibes-core/tests/fixtures/rule-set-v1.json`
- `crates/openvibes-core/tests/fixtures/rule-set-v1.yaml`

A finding records the generating scan, exact rule ID and version, severity,
confidence, message, and bounded evidence fact keys. Its ID is generated once,
persisted with the queue record, and reused for every delivery attempt.

## Signed Rule Envelope

The signature covers a deterministic, domain-separated preimage. Version 1 is:

1. ASCII `OPENVIBES-RULE-ENVELOPE-V1` followed by a zero byte.
2. Schema version as an unsigned 16-bit big-endian integer.
3. Rule-set ID as unsigned 32-bit big-endian byte length plus UTF-8 bytes.
4. Rule-set version as an unsigned 64-bit big-endian integer.
5. Issuer key ID as unsigned 32-bit big-endian byte length plus UTF-8 bytes.
6. Creation and expiration times as signed 64-bit big-endian integers.
7. Encoding byte: `1` for JSON or `2` for YAML.
8. Payload as unsigned 64-bit big-endian byte length plus exact UTF-8 bytes.
9. Raw 32-byte SHA-256 payload digest.

The signature field is excluded from the preimage. The digest is lowercase
hexadecimal on the wire. The 64-byte Ed25519 signature is encoded as unpadded
base64url. The payload string is the exact UTF-8 byte sequence after outer JSON
string decoding; JSON escape spelling and envelope field order are not signed.
Payload whitespace and line endings are signed and must not be normalized.

The loader first parses a bounded JSON envelope and checks its fields and the
expected rule-set identity. It resolves a trusted key scoped to that identity,
checks the SHA-256 digest, and verifies Ed25519 strictly. It checks time and
rollback policy before parsing the authenticated payload as JSON or YAML.

### Trust, Time, and Accepted Versions

`RuleLoader` takes provisioned `TrustedRuleKey` records, each containing a
rule-set ID, issuer-key ID, and Ed25519 public key. Weak public keys and duplicate
scope/key identifiers are rejected. Keys carried in incoming bundles are never
trusted. No private signing key is required by the scanner.

`LoadContext` supplies the expected rule-set ID, trusted current Unix time, and
the last accepted version. Validity is `created_at <= now < expires_at`, with no
implicit clock-skew grace period. Negative clock values and state for another
rule set are rejected.

The acceptance record contains the rule-set ID, version, and SHA-256 of the
entire signing preimage. A lower version is rejected. An equal version is
accepted only when the preimage digest is identical, allowing reload after
restart without allowing new content under the same version. Changing expiry,
issuer, encoding, or payload requires a higher version.

The loader performs no I/O. The composition root must atomically persist the
accepted bundle and record, serialize concurrent acceptance, and restore that
record before future loads. A missing/corrupted record after prior enrollment
must not be treated as first use. An identical cached bundle still requires a
currently trusted key and an unexpired signature interval. Durable persistence
and authenticated trust-root rotation remain later milestones.

### Parser Boundaries

The JSON envelope and decoded payload each have a 1 MiB byte ceiling. Envelope
metadata and JSON escaping count toward the outer ceiling, so a payload near
1 MiB may not fit within an envelope.

A common bounded visitor traverses every JSON/YAML value, including ignored
optional fields, and limits depth, nodes, collection lengths, individual
strings, and aggregate decoded string bytes. Duplicate keys and trailing
documents are rejected. CEL expressions receive their separate 16 KiB allowance
only in the rule expression field. Parser error output does not echo input.

YAML additionally limits events, retained anchors, alias replay, comments, and
scalar bytes. Merge keys, unsupported tags, and external includes are rejected;
property interpolation and include features are disabled. An entire-stream
preflight also rejects malformed content following an explicit `...` end marker.

Only a successful load creates `VerifiedRuleSet`, whose fields are private and
whose rule access is immutable. It proves authentication and contract validity
at load time; it does not prove CEL syntax, types, or evaluation budgets.
`Evaluator` accepts only this type and rechecks expiry throughout evaluation.

## Initial Resource Limits

| Resource | Version 1 limit |
|---|---:|
| Serialized document | 1 MiB |
| Document nesting depth | 32 |
| Parsed rule-document values and mapping keys | 20,000 |
| Aggregate decoded string bytes per document | 1 MiB |
| General string | 4 KiB |
| Identifier | 128 bytes |
| Facts per scan | 10,000 |
| Rules per set | 512 |
| YAML alias replay | 10,000 events, depth 16, 64 expansions per anchor |
| CEL expression | 16 KiB |
| General list | 1,024 items |
| Evidence per finding | 128 keys |
| CEL operations per rule | 50,000 |
| CEL expression depth | 32 |
| Evaluation wall time | 100 ms |
| Complete scan | 300 seconds |
| SQLite queue | 256 MiB |
| Queue retention | 30 days |
| Delivery batch | 500 findings |
| Retry delay | 15 seconds to 1 hour |

These are security limits, not performance targets. Raising them requires test
coverage and a resource-exhaustion review.

The loader accepts tighter limits but rejects zero general limits or limits
above these safety ceilings. Alias limits can be set to zero to disable replay.
The evaluator enforces the CEL expression, operation, depth, evidence, fact
input, and wall-time limits. Scan deadlines, queue limits, and delivery policies
are specified here but will be enforced by their respective later components.
