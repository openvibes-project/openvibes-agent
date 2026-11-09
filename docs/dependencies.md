# Dependencies

Everything the agent depends on, in two lists: what goes into the finished
builds (the packages and the hosts they run on), and what is needed only to
develop, test and build them. Each list names the dependencies we chose
ourselves; the indirect ones they pull in are counted, not listed.
`Cargo.lock` and `ebpf/openvibes-agent-ebpf/Cargo.lock` hold the full,
exact sets.

Checked against `main` on 2026-10-22. Update this page in the same change
that adds, removes or bumps a dependency, and update everything before
each release ([Before each release](#before-each-release)); the commands under
[Refreshing this page](#refreshing-this-page) print the current state.

## Before each release

Every release brings all dependencies up to date first, in a pull request
of its own that merges before the tag. Its CI and the local gate must be
green, including `cargo audit`.

1. Rust crates: raise every version in the `Cargo.toml` files to the newest
   release, then `cargo update`.
2. The Rust toolchain in `rust-toolchain.toml` (and `rust-version`) to the
   newest stable.
3. The eBPF program: `aya-ebpf`, its nightly
   (`ebpf/openvibes-agent-ebpf/rust-toolchain.toml`) and `bpf-linker`
   (`scripts/ebpf-tools.sh`).
4. The `protocol/` submodule to the newest openvibes-protocol `main`.
5. CI: the commit pins of the GitHub Actions, `cargo-audit`, and the
   container images.

A dependency may stay behind only with the reason written next to it on
this page. The same pull request then updates this page: versions,
counts and the date.

## 1. In the finished builds

### Rust crates compiled into the programs

The packages ship `openvibes-agent` and `openvibes-test` (the test-alarm
program, which uses no crates beyond our own). The agent compiles in the 19 crates below and **110 indirect crates** (129
in all), plus 14 crates used only by build scripts (proc-macros and
`build.rs` helpers such as `aya-build`, not in the program).

| Crate | Version | Licence | Used for |
|---|---|---|---|
| aya | 0.14.0 | MIT OR Apache-2.0 | Loading the eBPF program and reading its events |
| aya-obj | 0.3.0 | MIT OR Apache-2.0 | Reading the eBPF object file |
| base64 | 0.23.1 | MIT OR Apache-2.0 | Encoding keys and signatures |
| cel | 0.14.5 | MIT | Evaluating rule expressions (CEL) |
| ed25519-dalek | 3.0.0 | BSD-3-Clause | Checking the signature of rule bundles |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | gzip for uploads |
| log | 0.4.34 | MIT OR Apache-2.0 | Hands log lines to the Windows Event Log (on Linux nothing reads it) |
| memchr | 2.8.3 | Unlicense OR MIT | Fast scanning of `/proc` files |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | The agent's key and certificate request at enrollment |
| rusqlite | 0.41.1 | MIT | The on-disk queue and state (SQLite 3.54.1 compiled in, public domain; 0.41 for RUSTSEC-2026-0459, #137) |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | System calls |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT | mTLS to the platform |
| serde | 1.0.229 | MIT OR Apache-2.0 | Reading and writing data formats |
| serde-saphyr | 1.3.0 | MIT OR Apache-2.0 | Reading YAML rules |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | JSON |
| sha2 | 0.11.0 | MIT OR Apache-2.0 | Checksums and fingerprints |
| toml | 1.1.6 | MIT OR Apache-2.0 | Reading `agent.toml` |
| ureq | 3.4.2 | MIT OR Apache-2.0 | HTTPS client to the platform |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | Wiping secrets from memory |

The Rust standard library (from the Rust toolchain, MIT OR Apache-2.0) is
compiled in as well.

### Windows only

The Windows build adds four crates (and their `windows-sys`, `widestring`
and `winreg` bindings). Each needs `unsafe` code inside it to call Windows
(security.md 2.1); the agent's own code stays `forbid(unsafe_code)`.

| Crate | Version | Licence | Used for |
|---|---|---|---|
| sysinfo | 0.39.6 | MIT | Process names (`Process::kill*` banned in `clippy.toml`) |
| windows-service | 0.8.1 | MIT OR Apache-2.0 | Running as a Windows service (Mullvad) |
| winlog2 | 0.3.2 | MIT OR Apache-2.0 | Writing log lines to the Windows Event Log (its message table is vendored in `crates/openvibes-agent/res/`, see NOTICE) |
| winreg | 0.55.0 | MIT | Reading installed programs and the Windows version from the registry (P22); also used by winlog2 |

Review of `winlog2` 0.3.2 (2026-11-08): three `unsafe` calls,
`RegisterEventSourceW` with a NUL-terminated name, `ReportEventW` with one
string that lives across the call, and `DeregisterEventSource` on drop. Its
`register` and `deregister` write the registry; the agent never calls them
(the installer registers the event source). Its build script only compiles
the bundled message table with `winresource`, into winlog2's own library,
where it never reaches the exe; the agent's `build.rs` links the same table
into `openvibes-agent.exe` with `winresource` 0.1.34 (MIT, a build
dependency on Windows hosts only), so Event Viewer shows the text (#129). `eventlog` was the other
candidate; it was not taken because it pulls in the full `windows` 0.58
crate and its build script prints every environment variable.

### The eBPF program inside the agent

`ebpf/openvibes-agent-ebpf` builds to an eBPF object that is embedded in
the agent. Its own licence is MIT OR GPL-2.0-only (the kernel needs a
GPL-compatible licence string).

| Crate | Version | Licence | Used for |
|---|---|---|---|
| aya-ebpf | 0.2.1 (pinned with `=`) | MIT OR Apache-2.0 | Writing the program; brings `aya-ebpf-bindings`, `aya-ebpf-cty` and `aya-ebpf-macros` |

### What the packages require from the operating system

| Package format | Requires |
|---|---|
| RPM (Fedora, AlmaLinux) | coreutils, diffutils, gawk, grep (install scripts); systemd |
| Debian, Ubuntu | libc6 (>= 2.34), libgcc-s1, diffutils, gawk or mawk, systemd |
| Arch | glibc, libgcc, sh, systemd, coreutils, diffutils, gawk, grep |

### What it needs from the host and the network

| What | Why |
|---|---|
| Linux with BTF (`/sys/kernel/btf/vmlinux`) | The eBPF program; without it the agent falls back to kernel audit |
| Kernel audit with an exec rule loaded (auditd) | Fallback source for process events; without either, the agent runs without alarms |
| `/proc` and `/sys` | Host facts |
| An OpenVIBES platform | Enrollment, rule bundles and receiving findings (the only network peer) |

## 2. For development only

Nothing below ships.

### Toolchains

| Tool | Version | Used for |
|---|---|---|
| Rust | 1.95.0 (`rust-toolchain.toml`, with clippy and rustfmt), edition 2024 | Building and checking every crate |
| Rust nightly | nightly-2026-10-07 with rust-src (`ebpf/openvibes-agent-ebpf/rust-toolchain.toml`) | Building the eBPF program |
| bpf-linker | v0.11.1, pinned by checksum in `scripts/ebpf-tools.sh` | Linking the eBPF program |
| gcc, binutils | the distribution's | Building SQLite and the agent |
| rpm-build, systemd-rpm-macros, rpm-sign, gnupg2 | Fedora's | Building and signing the RPM |
| debhelper, dpkg-dev, lintian | Debian's | Building and checking the Debian package |
| namcap | Arch's | Checking the Arch package |

### Our own crates used only in tests

| Crate | Used for |
|---|---|
| openvibes-testkit | A mock platform (rustls server with an rcgen CA) for tests |
| `protocol/` (git submodule of openvibes-protocol) | Schemas and fixtures the tests check against |

All other crates the tests use are already in the list above.

### Continuous integration

| What | Version | Used for |
|---|---|---|
| GitHub runners | `ubuntu-24.04`, `windows-latest`, `macos-latest` | Every job; Windows also builds and tests the MSI |
| Containers | `registry.fedoraproject.org/fedora:44`, `debian:12`, `archlinux:base-devel` | Package builds |
| msitools (`wixl`, `msibuild`) | Fedora's | Building the Windows MSI (LGPL-2.1-or-later) |
| System test images | AlmaLinux 9, Arch, Debian 12, Ubuntu 22.04 | Installing and running the packages |
| actions/checkout, upload-artifact, download-artifact | pinned by commit | Workflow steps |
| Swatinem/rust-cache | pinned by commit | Rust build cache |
| taiki-e/install-action | pinned by commit | Installs cargo-audit |
| cargo-audit | 0.22.2 | Rust advisories (`cargo audit`) |
| SonarSource/sonarqube-scan-action | pinned by commit | Code analysis (SonarCloud) |
| Ubuntu packages | auditd, jq, libcap2-bin, rpm2cpio, cpio, strace | System tests |
| gh | Fedora's | Publishing releases |

## Refreshing this page

```sh
# Direct dependencies and licences per crate
cargo tree --edges normal --depth 1 --format '{p} {l}' --target x86_64-unknown-linux-gnu
# Everything compiled into the agent
cargo tree -p openvibes-agent --edges normal --prefix none --target x86_64-unknown-linux-gnu | sort -u
# The same for Windows
cargo tree -p openvibes-agent --edges normal --prefix none --target x86_64-pc-windows-msvc | sort -u
# The eBPF program
grep -A1 '^name = ' ebpf/openvibes-agent-ebpf/Cargo.lock
```
