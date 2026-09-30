//! Kernel audit records → process starts (pure; no I/O).
//!
//! Each netlink message is a 16-byte header (length u32, type u16, flags
//! u16, sequence u32, port u32, native endian) and the text
//! `audit(SECONDS.MILLIS:SERIAL): key=value …`. One event is several records
//! sharing `SERIAL`, `SYSCALL` first and `EOE` last. A string value is
//! `"quoted"` (the kernel quotes only text without quotes, spaces, control or
//! non-ASCII bytes) or hex; numbers are decimal.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

/// The packaged audit rule's key (`-k openvibes-exec`).
pub const EXEC_KEY: &str = "openvibes-exec";

/// The kernel's longest audit message (`MAX_AUDIT_MESSAGE_LENGTH`).
pub const MAX_MESSAGE: usize = 8_970;

/// Argument bytes kept per event; later ones are cut and the start marked
/// `args_truncated`. Cutting instead of dropping the event means a padded
/// command line still raises its alarm.
pub const EVENT_ARG_BYTES: usize = 65_536;

/// How long an event may wait for its `EOE`.
pub const EVENT_WAIT: Duration = Duration::from_secs(1);

/// Events waiting for their `EOE` at once.
pub const OPEN_EVENTS: usize = 64;

const HEADER: usize = 16;
const SYSCALL: u16 = 1300;
const CWD: u16 = 1307;
const EXECVE: u16 = 1309;
const EOE: u16 = 1320;
/// Separates several rule keys in one `key=` value.
const KEY_SEPARATOR: u8 = 0x01;

/// One successful `execve`/`execveat`, raw bytes; decoding is the caller's.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessStart {
    /// Process id.
    pub pid: u32,
    /// Parent process id.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// The executed file.
    pub exe: Vec<u8>,
    /// Arguments, `argv[0]` first.
    pub args: Vec<Vec<u8>>,
    /// Arguments were cut at [`EVENT_ARG_BYTES`] or arrived incomplete.
    pub args_truncated: bool,
    /// Working directory, when the event carried one.
    pub cwd: Option<Vec<u8>>,
    /// When the kernel logged it (Unix ms).
    pub at_unix_ms: i64,
}

struct Open {
    since: Instant,
    start: ProcessStart,
    arg_bytes: usize,
    argc: Option<usize>,
}

/// Joins the records of each exec event into one [`ProcessStart`].
#[derive(Default)]
pub struct Joiner {
    open: BTreeMap<u64, Open>,
    dropped: u64,
}

impl Joiner {
    /// Takes one netlink message; returns the event it finishes, if any.
    /// Records of other events, other keys and failed calls are ignored.
    pub fn push(&mut self, message: &[u8], now: Instant) -> Option<ProcessStart> {
        let (kind, serial, at_unix_ms, fields) = split(message)?;
        if kind == SYSCALL {
            let start = syscall(fields, at_unix_ms)?;
            if self.open.len() >= OPEN_EVENTS {
                let oldest = self
                    .open
                    .iter()
                    .min_by_key(|(_, open)| open.since)
                    .map(|(serial, _)| *serial)?;
                self.open.remove(&oldest);
                self.dropped += 1;
            }
            let open = Open {
                since: now,
                start,
                arg_bytes: 0,
                argc: None,
            };
            if self.open.insert(serial, open).is_some() {
                self.dropped += 1;
            }
            return None;
        }
        let open = self.open.get_mut(&serial)?;
        match kind {
            CWD => {
                open.start.cwd = Fields(fields)
                    .find(|(key, _)| *key == b"cwd")
                    .and_then(|(_, value)| string(value));
            }
            EXECVE => execve(open, fields),
            EOE => {
                let mut open = self.open.remove(&serial)?;
                if open.argc.is_none_or(|argc| open.start.args.len() < argc) {
                    open.start.args_truncated = true;
                }
                return Some(open.start);
            }
            _ => {}
        }
        None
    }

    /// Drops events waiting longer than [`EVENT_WAIT`]; returns how many
    /// events were lost since the last call (these, and those pushed out
    /// by [`OPEN_EVENTS`]).
    pub fn expire(&mut self, now: Instant) -> u64 {
        let before = self.open.len();
        self.open
            .retain(|_, open| now.saturating_duration_since(open.since) <= EVENT_WAIT);
        let lost = self.dropped + (before - self.open.len()) as u64;
        self.dropped = 0;
        lost
    }
}

/// Header and prefix: (type, serial, unix ms, the fields text).
fn split(message: &[u8]) -> Option<(u16, u64, i64, &[u8])> {
    let head = message.get(..HEADER)?;
    let len = u32::from_ne_bytes(head[0..4].try_into().ok()?) as usize;
    let kind = u16::from_ne_bytes(head[4..6].try_into().ok()?);
    let body = message.get(HEADER..len.min(message.len()).min(MAX_MESSAGE))?;
    let body = body.strip_prefix(b"audit(")?;
    let close = body.iter().position(|b| *b == b')')?;
    let stamp = std::str::from_utf8(&body[..close]).ok()?;
    let (time, serial) = stamp.split_once(':')?;
    let (secs, millis) = time.split_once('.')?;
    let at = secs
        .parse::<i64>()
        .ok()?
        .checked_mul(1000)?
        .checked_add(millis.parse::<i64>().ok()?)?;
    let rest = body[close + 1..]
        .strip_prefix(b":")
        .unwrap_or(&body[close + 1..]);
    Some((kind, serial.parse().ok()?, at, rest))
}

/// `key=value` pairs of a record, raw (a quoted value keeps its quotes).
struct Fields<'a>(&'a [u8]);

impl<'a> Iterator for Fields<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let text = self.0.trim_ascii_start();
            let text = text.split(|b| *b == 0).next().unwrap_or_default();
            if text.is_empty() {
                return None;
            }
            let eq = text.iter().position(|b| *b == b'=' || *b == b' ');
            let Some(eq) = eq.filter(|at| text[*at] == b'=') else {
                // A word without `=`: skip it.
                let end = text.iter().position(|b| *b == b' ').unwrap_or(text.len());
                self.0 = &text[end..];
                continue;
            };
            let key = &text[..eq];
            let rest = &text[eq + 1..];
            let end = if rest.first() == Some(&b'"') {
                rest[1..]
                    .iter()
                    .position(|b| *b == b'"')
                    .map_or(rest.len(), |at| at + 2)
            } else {
                rest.iter().position(|b| *b == b' ').unwrap_or(rest.len())
            };
            self.0 = &rest[end..];
            return Some((key, &rest[..end]));
        }
    }
}

/// A string value: quoted text, or hex. `None` for anything else, such as
/// `(null)`.
fn string(value: &[u8]) -> Option<Vec<u8>> {
    if let Some(inner) = value.strip_prefix(b"\"") {
        return inner.strip_suffix(b"\"").map(<[u8]>::to_vec);
    }
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16);
            Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect()
}

fn number<T: std::str::FromStr>(value: &[u8]) -> Option<T> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// A `SYSCALL` record of a successful exec carrying [`EXEC_KEY`].
fn syscall(fields: &[u8], at_unix_ms: i64) -> Option<ProcessStart> {
    let mut start = ProcessStart {
        at_unix_ms,
        ..ProcessStart::default()
    };
    let (mut success, mut keyed) = (false, false);
    for (key, value) in Fields(fields) {
        match key {
            b"success" => success = value == b"yes",
            b"pid" => start.pid = number(value)?,
            b"ppid" => start.ppid = number(value)?,
            b"uid" => start.uid = number(value)?,
            b"exe" => start.exe = string(value).unwrap_or_default(),
            b"key" => {
                keyed = string(value).is_some_and(|keys| {
                    keys.split(|b| *b == KEY_SEPARATOR)
                        .any(|k| k == EXEC_KEY.as_bytes())
                });
            }
            _ => {}
        }
    }
    (success && keyed).then_some(start)
}

/// An `EXECVE` record: `argc=`, `aN=`, or `aN_len=` then `aN[i]=` pieces.
/// Pieces arrive in order, possibly across several records.
fn execve(open: &mut Open, fields: &[u8]) {
    for (key, value) in Fields(fields) {
        if key == b"argc" {
            open.argc = number(value);
            continue;
        }
        let Some(name) = key.strip_prefix(b"a") else {
            continue;
        };
        let (index, piece) = match name.iter().position(|b| *b == b'[' || *b == b'_') {
            Some(at) if name[at] == b'_' => continue, // `aN_len`: pieces follow.
            Some(at) => (&name[..at], true),
            None => (name, false),
        };
        let (Some(index), Some(bytes)) = (number::<usize>(index), string(value)) else {
            open.start.args_truncated = true;
            continue;
        };
        let args = &mut open.start.args;
        let appends = piece && index + 1 == args.len();
        if !appends && index != args.len() {
            // Out of order or a gap: keep what came in order.
            open.start.args_truncated = true;
            continue;
        }
        let room = EVENT_ARG_BYTES - open.arg_bytes;
        if bytes.len() > room {
            open.start.args_truncated = true;
        }
        let kept = &bytes[..bytes.len().min(room)];
        open.arg_bytes += kept.len();
        if appends {
            if let Some(last) = args.last_mut() {
                last.extend_from_slice(kept);
            }
        } else if room > 0 || bytes.is_empty() {
            args.push(kept.to_vec());
        }
    }
}
