#![forbid(unsafe_code)]

//! `openvibes-test`: makes this host raise the harmless OpenVIBES test alarm
//! or test finding, so a user can see the whole pipeline work (platform spec
//! `2026-10-09-test-triggers-design.md`). Its start is the alarm; while it
//! runs, a scan sees it in `process.names`. It reads and writes nothing and
//! never talks to the agent or the platform.

use std::{process::ExitCode, thread, time::Duration};

const USAGE: &str = "\
Usage: openvibes-test alarm
       openvibes-test finding [--minutes N]

alarm    Start and exit. Within a few seconds the console should show
         \"OpenVIBES test alarm\" for this host.
finding  Keep running until the agent's next scan sees it (hourly by
         default), then stop with Ctrl-C. Stops by itself after
         --minutes (default 120, at most 1440).

Results show on the host's page in the console under \"Last test\".";

const DEFAULT_MINUTES: u64 = 120;
const MAX_MINUTES: u64 = 1440;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Alarm,
    Finding { minutes: u64 },
    Help,
}

fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [cmd] if cmd == "alarm" => Ok(Command::Alarm),
        [cmd] if cmd == "finding" => Ok(Command::Finding {
            minutes: DEFAULT_MINUTES,
        }),
        [cmd, flag, value] if cmd == "finding" && flag == "--minutes" => value
            .parse()
            .ok()
            .filter(|m| (1..=MAX_MINUTES).contains(m))
            .map(|minutes| Command::Finding { minutes })
            .ok_or_else(|| format!("--minutes wants 1 to {MAX_MINUTES}, not {value}")),
        [flag] if flag == "--help" || flag == "-h" => Ok(Command::Help),
        _ => Err("unknown arguments".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Command::Help) => println!("{USAGE}"),
        Ok(Command::Alarm) => println!(
            "Started the OpenVIBES test program. Within a few seconds the console \
             should show \"OpenVIBES test alarm\" for this host.\nNothing there? Check \
             that alarms are on for this host (Host page, Health)."
        ),
        Ok(Command::Finding { minutes }) => {
            println!(
                "Running until the agent's next scan sees this program (hourly by \
                 default). The console will show \"OpenVIBES test program is running\" \
                 for this host.\nStop with Ctrl-C once it is there; stops by itself in \
                 {minutes} minutes."
            );
            // Sleeping costs nothing; Ctrl-C and SIGTERM end it as usual.
            thread::sleep(Duration::from_secs(minutes * 60));
        }
        Err(error) => {
            eprintln!("openvibes-test: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{Command, DEFAULT_MINUTES, parse};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands_parse() {
        assert_eq!(parse(&args(&["alarm"])), Ok(Command::Alarm));
        assert_eq!(
            parse(&args(&["finding"])),
            Ok(Command::Finding {
                minutes: DEFAULT_MINUTES
            })
        );
        assert_eq!(
            parse(&args(&["finding", "--minutes", "5"])),
            Ok(Command::Finding { minutes: 5 })
        );
        assert_eq!(parse(&args(&["--help"])), Ok(Command::Help));
    }

    #[test]
    fn bad_arguments_are_refused() {
        for bad in [
            &[][..],
            &["alarm", "x"],
            &["finding", "--minutes", "0"],
            &["finding", "--minutes", "1441"],
            &["finding", "--minutes", "-1"],
            &["finding", "--minutes"],
            &["scan"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_name_fits_the_kernel_comm_limit() {
        // process.names and the alarm's process.name come from the 15-byte
        // comm; the test rules match the full name.
        assert!(env!("CARGO_PKG_NAME").len() <= 15);
    }
}
