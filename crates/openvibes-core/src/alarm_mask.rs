//! Secret masking and argument capping for alarms (protocol P14, "Process
//! events and alarms"). Pure functions: the agent calls them after rule
//! evaluation and before queueing, so rules see the real command line and
//! the platform never does.

use crate::alarm::{ALARM_ARGS, ALARM_ARGS_BYTES};

const MASK: &str = "***";
/// Programs whose attached `-p<value>` is a password (`sshpass` also takes
/// `-p value`).
const P_PROGRAMS: [&str; 6] = [
    "mysql",
    "mariadb",
    "mysqldump",
    "mariadb-dump",
    "mysqladmin",
    "sshpass",
];
/// Programs whose `-c SCRIPT` is masked word by word.
const SHELLS: [&str; 7] = ["sh", "bash", "dash", "zsh", "ash", "su", "runuser"];
/// `--NAME` flags whose value is secret, by the end of `NAME`.
const LONG_FLAG_SUFFIXES: [&str; 7] = [
    "password",
    "passwd",
    "pass",
    "passphrase",
    "token",
    "secret",
    "key",
];
/// `-NAME` flags whose value is secret, by the end of `NAME`.
const SHORT_FLAG_SUFFIXES: [&str; 5] = ["password", "passwd", "passphrase", "storepass", "keypass"];
/// `NAME=value` pairs whose value is secret, by the end of the upper-cased `NAME`.
const PAIR_SUFFIXES: [&str; 9] = [
    "PASSWORD",
    "PASSWD",
    "PASS",
    "PWD",
    "PASSPHRASE",
    "SECRET",
    "TOKEN",
    "KEY",
    "AUTH",
];
/// Header names whose value is secret (besides names ending in these
/// suffixes).
const SECRET_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "private-token",
];
const HEADER_SUFFIXES: [&str; 3] = ["token", "key", "secret"];

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// What a word says about the word after it.
#[derive(Clone, Copy, PartialEq)]
enum Next {
    Plain,
    /// The whole next word is secret.
    Secret,
    /// The next word is `user:password`.
    UserPassword,
}

/// Masking state across the words of one argument list or script.
struct Context {
    /// Attached `-p<value>` is a password.
    p_program: bool,
    /// `-p value` is a password too.
    sshpass: bool,
    next: Next,
}

/// Masks the arguments of a process whose executed file is `exe`, as the
/// contract lists; the result has exactly as many arguments. Each rule
/// marks secret characters and each run of them becomes `***`.
#[must_use]
pub fn mask_args(exe: &str, args: &[String]) -> Vec<String> {
    let program = basename(exe);
    let scripts = script_arguments(program, args);
    let mut context = Context {
        p_program: P_PROGRAMS.contains(&program),
        sshpass: program == "sshpass",
        next: Next::Plain,
    };
    let mut out = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        if scripts.contains(&i) {
            out.push(mask_script(arg));
            context.next = Next::Plain;
            continue;
        }
        let marks = mark_word(arg, &mut context, i > 0);
        out.push(replace_marked(arg, &marks));
    }
    out
}

/// Shells whose `-c` script is masked; `su`/`runuser` take `-c` anywhere later.
const SCRIPT_SHELLS: [&str; 5] = ["sh", "bash", "dash", "zsh", "ash"];
/// Shell options that take the next word as their value.
const SHELL_OPTIONS_WITH_VALUE: [&str; 6] = ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"];

/// Indexes of the arguments that are shell scripts: after a `-c` flag of the
/// process itself when its exe is a shell (or busybox run as one), and inside
/// any process's arguments after a shell word (only shell options between it
/// and the `-c`) or a `su`/`runuser` word (any later `-c`).
fn script_arguments(program: &str, args: &[String]) -> std::collections::BTreeSet<usize> {
    let mut scripts = std::collections::BTreeSet::new();
    let exe_is_shell = SHELLS.contains(&program)
        || (program == "busybox"
            && args
                .first()
                .is_some_and(|argv0| SHELLS.contains(&basename(argv0))));
    if exe_is_shell {
        for i in 1..args.len() {
            if is_c_flag(&args[i - 1]) {
                scripts.insert(i);
            }
        }
    }
    for (i, word) in args.iter().enumerate() {
        let name = basename(word);
        if SCRIPT_SHELLS.contains(&name) {
            let mut j = i + 1;
            while let Some(option) = args.get(j) {
                if is_c_flag(option) {
                    scripts.insert(j + 1);
                    break;
                }
                let is_option =
                    option != "--" && (option.starts_with('-') || option.starts_with('+'));
                if !is_option {
                    break;
                }
                j += if SHELL_OPTIONS_WITH_VALUE.contains(&option.as_str()) {
                    2
                } else {
                    1
                };
            }
        } else if name == "su" || name == "runuser" {
            for (k, later) in args.iter().enumerate().skip(i + 1) {
                if is_c_flag(later) {
                    scripts.insert(k + 1);
                }
            }
        }
    }
    scripts.retain(|index| *index < args.len());
    scripts
}

/// `-c`, or a single-dash cluster of letters containing `c` (`-lc`).
fn is_c_flag(word: &str) -> bool {
    word.strip_prefix('-').is_some_and(|flags| {
        !flags.starts_with('-')
            && !flags.is_empty()
            && flags.bytes().all(|b| b.is_ascii_alphabetic())
            && flags.contains('c')
    })
}

/// A script, word by word with the same rules; its whitespace is kept and
/// every script word may be a program word.
fn mask_script(script: &str) -> String {
    let mut context = Context {
        p_program: false,
        sshpass: false,
        next: Next::Plain,
    };
    let mut marks = Vec::new();
    for (start, end) in word_ranges(script) {
        for (a, b) in mark_word(&script[start..end], &mut context, true) {
            marks.push((start + a, start + b));
        }
    }
    replace_marked(script, &marks)
}

/// The secret byte ranges of one word; updates `context` for the next word.
/// `may_be_program`: the word may switch on `-p` masking (not `argv[0]`).
fn mark_word(word: &str, context: &mut Context, may_be_program: bool) -> Vec<(usize, usize)> {
    let mut marks = Vec::new();
    let this = std::mem::replace(&mut context.next, Next::Plain);
    match this {
        Next::Secret => {
            marks.push((0, word.len()));
            return marks;
        }
        Next::UserPassword => {
            mark_user_password(word, 0, &mut marks);
            return marks;
        }
        Next::Plain => {}
    }
    let lower = word.to_ascii_lowercase();
    // -p<value>, and sshpass's -p value.
    if context.p_program && word.starts_with("-p") && !word.starts_with("--") {
        if word.len() > 2 {
            marks.push((2, word.len()));
        } else if context.sshpass {
            context.next = Next::Secret;
        }
    }
    // --NAME / -NAME flags with a secret value.
    if let Some(rest) = lower.strip_prefix("--") {
        flag_value(word, rest, 2, &LONG_FLAG_SUFFIXES, context, &mut marks);
    } else if let Some(rest) = lower.strip_prefix('-') {
        flag_value(word, rest, 1, &SHORT_FLAG_SUFFIXES, context, &mut marks);
    }
    // user:password after -u, --user, --proxy-user.
    if lower == "-u" || lower == "--user" || lower == "--proxy-user" {
        context.next = Next::UserPassword;
    } else if let Some(prefix) = ["--user=", "--proxy-user="]
        .into_iter()
        .find(|prefix| lower.starts_with(prefix))
    {
        mark_user_password(&word[prefix.len()..], prefix.len(), &mut marks);
    } else if lower.starts_with("-u") && !lower.starts_with("--") && word.len() > 2 {
        mark_user_password(&word[2..], 2, &mut marks);
    }
    // Header values.
    let header_at = if lower.starts_with("--header=") {
        9
    } else if lower.starts_with("-h") && !lower.starts_with("--") && word.len() > 2 {
        2
    } else {
        0
    };
    mark_header(word, header_at, &mut marks);
    // pass:value
    if word.len() > 5 && word.starts_with("pass:") {
        marks.push((5, word.len()));
    }
    mark_pairs(word, &mut marks);
    mark_urls(word, &mut marks);
    if may_be_program {
        let trimmed = ["$(", "(", "`", "'", "\""]
            .into_iter()
            .find_map(|prefix| word.strip_prefix(prefix))
            .unwrap_or(word);
        let name = basename(trimmed);
        if P_PROGRAMS.contains(&name) {
            context.p_program = true;
            context.sshpass |= name == "sshpass";
        }
    }
    marks
}

/// `rest` is the flag without its dashes (`offset` bytes into `word`).
fn flag_value(
    word: &str,
    rest: &str,
    offset: usize,
    suffixes: &[&str],
    context: &mut Context,
    marks: &mut Vec<(usize, usize)>,
) {
    let (name, value_at) = match rest.find('=') {
        Some(eq) => (&rest[..eq], Some(offset + eq + 1)),
        None => (rest, None),
    };
    if name.is_empty() || !suffixes.iter().any(|suffix| name.ends_with(suffix)) {
        return;
    }
    match value_at {
        Some(at) if at < word.len() => marks.push((at, word.len())),
        Some(_) => {}
        None => context.next = Next::Secret,
    }
}

/// `user:password` starting at `offset`: the part after the first `:`.
fn mark_user_password(value: &str, offset: usize, marks: &mut Vec<(usize, usize)>) {
    if let Some(colon) = value.find(':')
        && colon + 1 < value.len()
    {
        marks.push((offset + colon + 1, offset + value.len()));
    }
}

/// A `Name: value` header starting at `at`.
fn mark_header(word: &str, at: usize, marks: &mut Vec<(usize, usize)>) {
    let header = &word[at..];
    let Some(colon) = header.find(':') else {
        return;
    };
    let name = header[..colon].to_ascii_lowercase();
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let secret = SECRET_HEADERS.contains(&name.as_str())
        || HEADER_SUFFIXES.iter().any(|suffix| name.ends_with(suffix));
    if !valid || !secret {
        return;
    }
    let mut start = at + colon + 1;
    while word.as_bytes().get(start) == Some(&b' ') {
        start += 1;
    }
    if start < word.len() {
        marks.push((start, word.len()));
    }
}

/// Every `NAME=value` pair whose `NAME` ends in a secret suffix.
fn mark_pairs(word: &str, marks: &mut Vec<(usize, usize)>) {
    let bytes = word.as_bytes();
    for (eq, _) in word.match_indices('=') {
        let name_start = bytes[..eq]
            .iter()
            .rposition(|b| matches!(b, b'=' | b',' | b'&' | b'?' | b';'))
            .map_or(0, |i| i + 1);
        let name = word[name_start..eq].to_ascii_uppercase();
        if name.is_empty() || !PAIR_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
            continue;
        }
        let value_end = bytes[eq + 1..]
            .iter()
            .position(|b| matches!(b, b',' | b'&' | b';'))
            .map_or(word.len(), |i| eq + 1 + i);
        if value_end > eq + 1 {
            marks.push((eq + 1, value_end));
        }
    }
}

/// The password in every `scheme://user:password@host` of `word`.
fn mark_urls(word: &str, marks: &mut Vec<(usize, usize)>) {
    for (scheme_end, _) in word.match_indices("://") {
        let start = scheme_end + 3;
        let authority_end = word[start..]
            .find(['/', '?', '#'])
            .map_or(word.len(), |i| start + i);
        let authority = &word[start..authority_end];
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        if let Some(colon) = authority[..at].find(':')
            && colon + 1 < at
        {
            marks.push((start + colon + 1, start + at));
        }
    }
}

/// Replaces each run of marked bytes of `text` with `***`.
fn replace_marked(text: &str, marks: &[(usize, usize)]) -> String {
    if marks.is_empty() {
        return text.to_owned();
    }
    let mut sorted = marks.to_vec();
    sorted.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (start, end) in sorted {
        match runs.last_mut() {
            Some(run) if start <= run.1 => run.1 = run.1.max(end),
            _ => runs.push((start, end)),
        }
    }
    for (start, end) in runs {
        out.push_str(&text[last..start]);
        out.push_str(MASK);
        last = end;
    }
    out.push_str(&text[last..]);
    out
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

/// Caps arguments to at most 256 and 4096 UTF-8 bytes joined by single
/// spaces: whole arguments while they fit; a first argument that alone is too long is cut
/// on a character boundary. Returns the kept arguments and whether anything
/// was cut. Nothing is appended.
#[must_use]
pub fn cap_args(args: Vec<String>) -> (Vec<String>, bool) {
    let total = args.len();
    let mut used = 0;
    let mut kept: Vec<String> = Vec::new();
    for arg in args {
        if kept.len() == ALARM_ARGS {
            return (kept, true);
        }
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
        assert!(vectors.len() >= 74);
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
    fn more_than_256_arguments_are_cut_to_256() {
        let (kept, cut) = cap_args(vec!["a".to_owned(); 300]);
        assert_eq!((kept.len(), cut), (256, true));
        let (kept, cut) = cap_args(vec!["a".to_owned(); 256]);
        assert_eq!((kept.len(), cut), (256, false));
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
            mask_args(
                "/usr/bin/env",
                &["env".into(), "DATABASE_URL=postgres://app:p@ss@db/x".into()]
            )[1],
            "DATABASE_URL=postgres://app:***@db/x"
        );
    }
}
