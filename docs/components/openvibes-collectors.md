# openvibes-collectors

## Purpose

Read-only host collectors. They observe host state and never modify it or
start an external process. Each collector returns all of its facts, or
none of them and one structured `CollectorError`, so a rule never sees a
partial list.

## Interfaces

- **`collect_processes`:** `process.names` (sorted, unique) and
  `process.count`. Linux reads `/proc`, which is world-readable. Windows and
  macOS have their own implementations; other systems report `unsupported`.
- **`collect_packages`:** `package.names` and `package.count`, from the RPM
  or dpkg database, parsed with bounds checks. Linux only. `package_facts`
  builds the facts from a package list. dpkg packages carry their `Source`
  package and, for a binNMU, the source's own version, when they differ
  from the binary's (protocol P10): Debian and Ubuntu publish
  vulnerabilities per source package.
- **`collect_ports`:** listening sockets per protocol (`tcp`, `udp`):
  - `port.<proto>.exposed` and `port.<proto>.exposed.count`: ports bound to
    a non-loopback address;
  - `port.<proto>.local`: ports bound only to loopback;
  - `port.<proto>.listeners`: every bound `address:port`.

  Linux reads `/proc/net`. "Exposed" describes the bind address, not
  reachability.
- **`os_release`:** the host's `ID` and `VERSION_ID` from `/etc/os-release`
  (falling back to `/usr/lib/os-release`, at most 64 KiB read), for the
  inventory report. `None` when neither file exists, a key is missing (a
  rolling distribution has no `VERSION_ID`), or a value is not an identifier.
- **`running_kernel`:** the running kernel's release as `uname -r` prints
  it (the `uname` system call, no file read), for the inventory report
  (protocol P9). `None` if it has characters the schema does not allow.
- **`hostname`:** the OS-reported host name, or `None` if it is empty. It
  is an operator label and never identity.

## Configuration

None. Callers pass a deadline and `ResourceLimits`.

## Failure behaviour

Any of these yields no facts and one `CollectorError` with a fixed code
(`PermissionDenied`, `NotFound`, `TimedOut`, `InvalidData`, `Unsupported`,
`Internal`) and a bounded message:
- an unreadable or malformed source;
- a passed deadline;
- more values than the 10,000-item fact list limit.

The rules engine treats facts from a failed collector as unavailable, never
as compliant.

## Test

```sh
cargo test --locked -p openvibes-collectors
```
