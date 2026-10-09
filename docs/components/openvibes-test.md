# `openvibes-test`

**Purpose.** A harmless program any user runs to make this host raise the
OpenVIBES test alarm or test finding, so they can see the whole pipeline
work, like the EICAR file for antivirus (platform spec
`2026-10-09-test-triggers-design.md`). The agent itself never spawns
processes; the user does.

**Interfaces.** `/usr/bin/openvibes-test` (0755, in the agent RPM).

- `openvibes-test alarm`: prints what to expect and exits 0. Its process
  start matches the signed rule `alarm.openvibes.test` (`baseline-alarms`).
- `openvibes-test finding [--minutes N]`: sleeps so the next scan sees
  `openvibes-test` in `process.names` and `test.openvibes.running`
  (`baseline`) matches. Ends on Ctrl-C, SIGTERM, or after N minutes
  (default 120, 1 to 1440).
- `--help`; anything else exits 2.

The name is 14 bytes, under the kernel's 15-byte `comm`, so both rules see
it in full.

**Configuration.** None. It reads no file (the agent's configuration is not
readable by users), so it cannot know when the next scan is and says the
default (hourly).

**Failure behaviour.** It cannot fail in a way that matters: no I/O beyond
stdout. "Nothing in the console" is the signal the user is after: alarms
off, rule set not loaded, or delivery broken.

**How to test.** `cargo test -p openvibes-test` (arguments, the name
limit); `scripts/check-rpm.sh` checks the installed mode (0755, not
setuid) and runs `openvibes-test alarm`. End to end: run it on a
lab host and look for the test alarm in the console.
