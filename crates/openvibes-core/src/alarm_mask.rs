//! Secret masking and argument capping for alarms (protocol P14, "Process
//! events and alarms"). Pure functions: the agent calls them after rule
//! evaluation and before queueing, so rules see the real command line and
//! the platform never does.

use crate::alarm::ALARM_ARGS_BYTES;

const MASK: &str = "***";
/// Programs whose `-p<value>` is a password (`sshpass` also `-p value`).
const P_PASSWORD_PROGRAMS: [&str; 6] = [
    "mysql",
    "mariadb",
    "mysqldump",
    "mariadb-dump",
    "mysqladmin",
    "sshpass",
];
/// Programs whose `-c SCRIPT` is masked word by word.
const SHELLS: [&str; 5] = ["sh", "bash", "dash", "zsh", "ash"];
/// Flags whose value (`=value` or the next argument) is masked.
const VALUE_FLAGS: [&str; 7] = [
    "--password",
    "--passwd",
    "--pass",
    "--token",
    "--secret",
    "--api-key",
    "--apikey",
];
/// `NAME=value` is masked when the upper-cased `NAME` ends in one of these.
const SECRET_SUFFIXES: [&str; 5] = ["PASSWORD", "PASSWD", "SECRET", "TOKEN", "KEY"];
/// Words after which a new command starts inside a `-c` script.
const SEPARATORS: [&str; 5] = [";", "|", "||", "&&", "&"];

/// What the word after the current one is.
#[derive(Clone, Copy, PartialEq)]
enum Next {
    Plain,
    /// A secret value: replaced whole.
    Secret,
    /// `user:password`: the part after the first `:` is replaced.
    UserPassword,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Masks the arguments of a process whose executed file is `exe`; the
/// result has exactly as many arguments. The basename of `exe` (not of
/// `argv[0]`) decides whether `-p` is a password.
#[must_use]
pub fn mask_args(exe: &str, args: &[String]) -> Vec<String> {
    let program = basename(exe);
    let mut out = Vec::with_capacity(args.len());
    let mut next = Next::Plain;
    for (i, arg) in args.iter().enumerate() {
        let (masked, following) = mask_one(program, arg, next, args.get(i + 1).is_some());
        out.push(masked);
        next = following;
    }
    if SHELLS.contains(&program) {
        for i in 1..args.len() {
            if args[i - 1] == "-c" {
                out[i] = mask_script(&args[i]);
            }
        }
    }
    out
}

/// One word, given what the previous word said about it.
fn mask_one(program: &str, word: &str, this: Next, has_next: bool) -> (String, Next) {
    match this {
        Next::Secret => (MASK.into(), Next::Plain),
        Next::UserPassword => (mask_user_password(word), Next::Plain),
        Next::Plain => mask_word(program, word, has_next),
    }
}

/// One word on its own; returns the masked word and what the next word is.
fn mask_word(program: &str, word: &str, has_next: bool) -> (String, Next) {
    let lower = word.to_ascii_lowercase();
    if P_PASSWORD_PROGRAMS.contains(&program) && word.starts_with("-p") && !word.starts_with("--") {
        if word.len() > 2 {
            return (format!("-p{MASK}"), Next::Plain);
        }
        // A bare -p: sshpass takes the next word as the password; the MySQL
        // tools prompt for it, so their next word is kept.
        let next = if program == "sshpass" && has_next {
            Next::Secret
        } else {
            Next::Plain
        };
        return (word.into(), next);
    }
    for flag in VALUE_FLAGS {
        if lower == flag {
            let next = if has_next { Next::Secret } else { Next::Plain };
            return (word.into(), next);
        }
        if lower.len() > flag.len() + 1
            && lower.starts_with(flag)
            && lower.as_bytes()[flag.len()] == b'='
        {
            return (format!("{}={MASK}", &word[..flag.len()]), Next::Plain);
        }
    }
    if lower == "-u" || lower == "--user" {
        return (word.into(), Next::UserPassword);
    }
    if lower.starts_with("--user=") {
        return (
            format!("{}{}", &word[..7], mask_user_password(&word[7..])),
            Next::Plain,
        );
    }
    if lower.starts_with("authorization:") {
        return (format!("{}: {MASK}", &word[..13]), Next::Plain);
    }
    if word.starts_with("pass:") && word.len() > 5 {
        return (format!("pass:{MASK}"), Next::Plain);
    }
    if let Some((name, value)) = word.split_once('=') {
        let is_name =
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let upper = name.to_ascii_uppercase();
        if is_name && !value.is_empty() && SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
            return (format!("{name}={MASK}"), Next::Plain);
        }
    }
    (mask_url(word), Next::Plain)
}

/// `user:password` → `user:***`; a value without `:` is kept.
fn mask_user_password(word: &str) -> String {
    match word.split_once(':') {
        Some((user, password)) if !password.is_empty() => format!("{user}:{MASK}"),
        _ => word.into(),
    }
}

/// The password of every `scheme://user:password@host` in `word`; the
/// userinfo runs to the last `@` before the host's first `/`.
fn mask_url(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut rest = word;
    while let Some(start) = rest.find("://") {
        let (head, tail) = rest.split_at(start + 3);
        out.push_str(head);
        let authority_end = tail.find('/').unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at) if authority[..at].contains(':') => {
                let colon = authority[..at].find(':').unwrap_or(0);
                out.push_str(&authority[..=colon]);
                out.push_str(MASK);
                out.push_str(&authority[at..]);
            }
            _ => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

/// A `-c` script, word by word: each word's program is the first word of
/// its command, a command starting at the script's start or after a
/// separator word (or a word ending in `;`), with `NAME=value` words before
/// it skipped. The script's whitespace is kept; quoting is not interpreted.
fn mask_script(script: &str) -> String {
    let words: Vec<(usize, usize)> = word_ranges(script);
    let mut out = String::with_capacity(script.len());
    let mut last = 0;
    let mut program = String::new();
    let mut at_command_start = true;
    let mut next = Next::Plain;
    for (index, &(start, end)) in words.iter().enumerate() {
        out.push_str(&script[last..start]);
        let word = &script[start..end];
        // A trailing `;` separates commands; it is not part of a value.
        let (body, semicolon) = match word.strip_suffix(';') {
            Some(body) if !body.is_empty() => (body, ";"),
            _ => (word, ""),
        };
        let is_separator = SEPARATORS.contains(&word);
        if at_command_start && !is_separator && !is_assignment(body) {
            program = basename(body).to_owned();
            at_command_start = false;
        }
        let (masked, following) = if is_separator {
            (word.to_owned(), Next::Plain)
        } else {
            let (m, f) = mask_one(&program, body, next, index + 1 < words.len());
            (format!("{m}{semicolon}"), f)
        };
        out.push_str(&masked);
        next = following;
        if is_separator || !semicolon.is_empty() {
            at_command_start = true;
            next = Next::Plain;
        }
        last = end;
    }
    out.push_str(&script[last..]);
    out
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Byte ranges of the ASCII-whitespace-separated words of `text`.
fn word_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (i, byte) in text.bytes().enumerate() {
        match (byte.is_ascii_whitespace(), start) {
            (true, Some(s)) => {
                ranges.push((s, i));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(s) = start {
        ranges.push((s, text.len()));
    }
    ranges
}

/// Caps arguments to 4096 UTF-8 bytes joined by single spaces: whole
/// arguments while they fit; a first argument that alone is too long is cut
/// on a character boundary. Returns the kept arguments and whether anything
/// was cut. Nothing is appended.
#[must_use]
pub fn cap_args(args: Vec<String>) -> (Vec<String>, bool) {
    let total = args.len();
    let mut used = 0;
    let mut kept: Vec<String> = Vec::new();
    for arg in args {
        let extra = arg.len() + usize::from(!kept.is_empty());
        if used + extra <= ALARM_ARGS_BYTES {
            used += extra;
            kept.push(arg);
            continue;
        }
        if kept.is_empty() {
            let mut end = ALARM_ARGS_BYTES;
            while !arg.is_char_boundary(end) {
                end -= 1;
            }
            kept.push(arg[..end].to_owned());
        }
        return (kept, true);
    }
    let cut = kept.len() < total;
    (kept, cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        exe: String,
        args: Vec<String>,
        masked: Vec<String>,
    }

    #[test]
    fn masking_matches_every_protocol_vector() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../../protocol/vectors/alarm-masking.json"))
                .unwrap();
        assert!(vectors.len() >= 19);
        for v in vectors {
            let masked = mask_args(&v.exe, &v.args);
            assert_eq!(masked.len(), v.args.len(), "{}", v.name);
            assert_eq!(masked, v.masked, "{}", v.name);
        }
    }

    #[test]
    fn capping_keeps_whole_arguments_and_marks_the_cut() {
        let (kept, cut) = cap_args(vec!["a".repeat(3000), "b".repeat(2000)]);
        assert_eq!((kept.len(), cut), (1, true));
        let (kept, cut) = cap_args(vec!["x".into(), "y".into()]);
        assert_eq!((kept, cut), (vec!["x".to_owned(), "y".to_owned()], false));
    }

    #[test]
    fn a_long_first_argument_is_cut_on_a_character_boundary() {
        let (kept, cut) = cap_args(vec!["é".repeat(3000)]); // 6000 bytes
        assert!(cut);
        assert_eq!(kept.len(), 1);
        assert!(kept[0].len() <= 4096 && kept[0].chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_trailing_semicolon_stays_a_separator() {
        let masked = mask_args(
            "/usr/bin/sh",
            &["sh".into(), "-c".into(), "export PGPASSWORD=x; psql".into()],
        );
        assert_eq!(masked[2], "export PGPASSWORD=***; psql");
    }

    #[test]
    fn a_url_password_runs_to_the_last_at_before_the_host() {
        assert_eq!(
            mask_url("DATABASE_URL=postgres://app:p@ss@db/x"),
            "DATABASE_URL=postgres://app:***@db/x"
        );
    }
}
