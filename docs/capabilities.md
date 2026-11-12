# What the agent does

The agent in detail, as of release 0.3.0. The [README](../README.md) is the
short version; [configuration.md](configuration.md) covers its settings.

## Collecting facts

Collectors run without shells or external programs, and each can be
switched on or off (`collectors`):

- **Processes** (`process.names`, `process.count`): on Linux, Windows, and
  macOS, with the same meaning on each.
- **Installed packages** (`package.names`, `package.count`): RPM 4.16+
  (SQLite database) and dpkg, including a dpkg package's source package
  and version; on Windows, the programs Apps and Features lists (from the
  registry). The RPM database is read without SQLite ever creating or
  writing a file beside it, even as root.
- **Listening ports** (`port.{tcp,udp}.{exposed,local,listeners}`, and a
  count of exposed ports): exposed means bound to a non-loopback address.
- **Services** (with a platform): listening sockets and the services behind
  them, sent when they change. The exact program behind each port (its
  process name, never a command line) comes from a small root helper the
  packages install and enable, so the agent itself stays unprivileged.
- **Process starts** (`process_events`, Linux, with a platform; always
  on): threat alarms. Program starts come from the agent's own eBPF program (kernel 5.8+
  with BTF), or from kernel audit when eBPF can't load; the agent logs which
  and why. Alarm rules run on each start, and an alarm reaches the platform
  in seconds.
- **Hardening** (Linux, with the root helper): sshd settings, sysctls,
  file modes, mount options, services, accounts, audit and login settings,
  each read from a file (never by running a program) and named in the
  protocol's fact catalog. A source that can't be read makes its rules
  unavailable, never false.
- **Operating system and running kernel:** used for inventory reports
  (on Windows, the version with its build and update revision).
- **Unsupported systems:** a collector that doesn't support a system says
  so explicitly (`unsupported`), never reports empty data.

## Evaluating rules

- **Signed rule sets:** Ed25519 with trusted keys scoped per rule set, a
  signing preimage that can't be reused for anything else, and a digest.
  Expired bundles, rollbacks, and version conflicts are refused, all
  before the payload is parsed.
- **Parsing:** the JSON or YAML payload goes through a budgeted parser
  that enforces node, depth, byte, and list limits and rejects duplicate
  keys.
- **Expressions:** a small hand-written subset of CEL: `facts['key']`,
  literals, comparisons, `!`, `&&`, `||`, `in`. Every step counts against
  an operation budget and a deadline.
- **Isolation:** rules see only the pre-collected facts, never files, the
  environment, the clock, or the network. No scripting engines.
- **Missing facts:** a rule whose facts are unavailable reports
  `Unavailable`, not "no match". One rule's failure never discards the
  others.
- **The project's own rule sets** (baseline, alarms, hardening level 1
  and 2) are built in with their public key, so a host gets them with no
  configuration line; the platform decides per host which hardening sets
  run (`410`: not assigned) and the agent reports that in its health.
- **MITRE ATT&CK:** a rule may carry the ATT&CK techniques it covers
  (validated, 1 to 16 pairs); the platform's Coverage page reads them.

## Reporting to the platform

- **Enrollment:** a one-time token, a P-256 host key, and a CSR. The
  certificate is renewed at two-thirds of its lifetime, and the agent
  recovers from revocation or an expired certificate by re-enrolling.
- **Transport:** TLS 1.3 only (rustls) with pinned platform CA roots,
  mutual TLS, no redirects, and an explicit proxy only (proxy environment
  variables are ignored).
- **Delivery:** a durable, deduplicating SQLite queue with a size bound.
  Findings leave the queue only when the platform acknowledges them, with
  capped backoff on failure. Queue rows are re-validated when read.
- **Findings as changes:** a match is reported when it starts, changes or
  ends, not again on every scan.
- **Heartbeats:** every minute, with the enabled collectors
  (capabilities) and a health report (scans, queue, rule sets, alarms).
- **Inventory reports:** operating system, packages, and running kernel,
  sent when they change, as changes after the first full report.
- **Rule updates:** before each scan, newer rule bundles are fetched from
  the distribution service and verified like local ones. A bad or failed
  fetch never replaces the last accepted bundle.

## Running without a platform

With no platform configured the agent never uses the network. Findings
and the package inventory are exported to files (`openvibes-agent export`)
to be carried to the platform by hand.

## Safe to run as root or SYSTEM

- **Files it reads:** the configuration, CA, token, and bundle files, and
  every folder and link on the way to them, must be owned by root or the
  agent's user and not writable by others. The token must not be readable
  by others.
- **Its own state:** the state directory is created owner-only and
  refused, never repaired, if it is insecure.
- **Special files:** FIFOs and devices are refused without blocking.
- **Exports:** writing into a directory another user controls is refused.
- **Code rules:** no `unsafe` code, no `std::process::Command`, no
  certificate-verification bypass (enforced by lints), and secrets never
  appear in logs.

## Packaging

- **RPM, .deb and Arch packages** of one binary (Fedora 44, AlmaLinux and
  Rocky 9+, Debian 12+, Ubuntu 22.04+, Arch; x86_64), signed with the
  OpenVIBES key and released with checksums: a hardened systemd unit (own
  user, system-call filter, read-only system), tested on install, upgrade
  and erase under a real systemd on each system
  ([docs/components/packaging.md](components/packaging.md)). The
  website's `install.sh` (and the console's install command) adds the
  matching repository and installs it.
- **Windows MSI (preview)**, x64, for Windows 10 22H2 and 11 and Windows
  Server 2016 to 2025: the agent as a service under its own virtual
  account, configuration and identity readable only by SYSTEM and
  Administrators, the platform settings as install properties, no reboot
  ever, and an uninstall that leaves nothing; released with a checksum and
  a detached signature, no Authenticode signature yet
  ([docs/install-windows.md](install-windows.md)).
- **`openvibes-test alarm|finding`** ships in every Linux package: any user can
  make the host raise the harmless test alarm or finding, to check the whole
  pipeline end to end.
- **CI:** Linux, Windows, and macOS.

## Planned

- **macOS:** a launchd package (#97).
- **Windows, after the preview:** an Authenticode-signed MSI, listening
  ports and services, threat alarms (ETW), Windows rules, vulnerability
  matching, and the MSI fetching the platform's CA by its fingerprint.
- **Host keys in OS key stores:** TPM, Keychain, or DPAPI.
- **Release artifacts:** SBOMs and provenance (packages are already signed,
  with checksums).
- **Alpine:** an apk package collector, for the platform's OSV-based
  Alpine support.
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents.
- **More fact families** as rules need them.

