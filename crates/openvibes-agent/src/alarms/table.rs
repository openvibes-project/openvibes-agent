//! The process table: who started whom, for lineage (pure; `/proc` reads
//! come in through a `lookup` closure).
//!
//! Exec events add entries. A parent the table has never seen (it started
//! before the agent, or forked without exec like an nginx worker) is read
//! from `/proc` on the spot and kept as *seeded*.

use std::{collections::BTreeMap, time::Duration, time::Instant};

use openvibes_collectors::process_events::{ProcessStart, Seeded};
use openvibes_core::{ALARM_ANCESTORS, AlarmProcess, cap_args, mask_args};
use openvibes_rules::{EventValue, ProcessEvent};

/// Longest `exe`, `name` or `cwd` kept, in bytes.
pub const PATH_BYTES: usize = 4_096;
/// Longest command line a rule sees, in bytes.
pub const CMDLINE_BYTES: usize = 262_144;
/// Argument bytes kept per table entry (for ancestors and `parent.cmdline`).
pub const ENTRY_ARG_BYTES: usize = 4_096;
/// Most entries.
pub const MAX_ENTRIES: usize = 32_768;
/// Most bytes the entries hold, estimated.
// ponytail: the estimate undercounts allocator and map overhead about 2x;
// 1 MiB estimated measured ~2 MiB RSS under 100 execs/s (board #86).
pub const MAX_BYTES: usize = 1 << 20;
/// How long an exited process stays, for the lineage of late events.
/// Events wait at most seconds for the engine, and a child whose parent
/// exited is reparented (its `ppid` changes), so a minute is plenty.
pub const EXITED_KEPT: Duration = Duration::from_secs(60);
/// Estimated bytes per entry besides its strings.
const ENTRY_OVERHEAD: usize = 160;

/// One process in the table.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Process id.
    pub pid: u32,
    /// Parent process id when it started (0: none).
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// Effective user id.
    pub euid: u32,
    /// Executed file; for a seeded process the readable link, else an
    /// absolute `argv[0]`, else `[comm]`.
    pub exe: String,
    /// Basename of `exe`, or `comm` for a seeded process.
    pub name: String,
    /// Arguments, cut at [`ENTRY_ARG_BYTES`].
    pub args: Vec<String>,
    /// Arguments were cut.
    pub args_truncated: bool,
    /// Working directory, when known.
    pub cwd: Option<String>,
    /// Read from `/proc` rather than an exec event.
    pub seeded: bool,
    /// `exe` is `argv[0]` or `[comm]`, not the real link.
    synthetic_exe: bool,
    seen: Instant,
    exited: Option<Instant>,
}

impl Entry {
    fn bytes(&self) -> usize {
        ENTRY_OVERHEAD
            + self.exe.len()
            + self.name.len()
            + self.args.iter().map(|arg| arg.len() + 24).sum::<usize>()
            + self.cwd.as_ref().map_or(0, String::len)
    }

    /// The alarm's view: arguments masked with this process's own exe
    /// (and `argv[0]` when the exe is synthetic), then capped.
    #[must_use]
    pub fn to_alarm_process(&self) -> AlarmProcess {
        let mut args = mask_args(&self.exe, &self.args);
        if self.synthetic_exe
            && let Some(argv0) = self.args.first()
        {
            args = mask_args(argv0, &args);
        }
        let (args, cut) = cap_args(args);
        AlarmProcess {
            pid: self.pid,
            exe: self.exe.clone(),
            args,
            cwd: self.cwd.clone(),
            uid: self.uid,
            euid: self.euid,
            truncated: cut || self.args_truncated,
            seeded: self.seeded,
        }
    }
}

/// A process and its ancestors, parent first.
#[derive(Clone, Debug)]
pub struct Lineage {
    /// The process that started.
    pub process: Entry,
    /// Its parent, then further ancestors (at most [`ALARM_ANCESTORS`]).
    pub ancestors: Vec<Entry>,
}

impl Lineage {
    /// The alarm's processes: the process, then its ancestors.
    #[must_use]
    pub fn to_alarm_processes(&self) -> (AlarmProcess, Vec<AlarmProcess>) {
        (
            self.process.to_alarm_process(),
            self.ancestors.iter().map(Entry::to_alarm_process).collect(),
        )
    }
}

/// Processes by pid.
#[derive(Default)]
pub struct ProcessTable {
    entries: BTreeMap<u32, Entry>,
    bytes: usize,
}

impl ProcessTable {
    /// Entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records an exec and returns its event values and lineage. Parents
    /// the table lacks are read with `lookup` (from `/proc`).
    pub fn start(
        &mut self,
        start: &ProcessStart,
        now: Instant,
        mut lookup: impl FnMut(u32) -> Option<Seeded>,
    ) -> (ProcessEvent, Lineage) {
        let mut ancestors = Vec::new();
        let mut next = start.ppid;
        while next != 0 && ancestors.len() < ALARM_ANCESTORS {
            if !self.entries.contains_key(&next) {
                // The reader's snapshot of the parent first: it may have
                // exited since.
                let snapshot = start.parent.clone().filter(|_| next == start.ppid);
                let Some(seeded) = snapshot
                    .or_else(|| lookup(next))
                    .filter(|seeded| seeded.pid == next)
                else {
                    break;
                };
                self.insert(from_seeded(&seeded, now));
            }
            let Some(entry) = self.entries.get(&next) else {
                break;
            };
            let parent = entry.ppid;
            ancestors.push(entry.clone());
            if parent == next || ancestors.iter().any(|seen| seen.pid == parent) {
                break;
            }
            next = parent;
        }

        let args: Vec<String> = start.args.iter().map(|arg| lossy(arg)).collect();
        let (cmdline, cmdline_cut) = cut(args.join(" "), CMDLINE_BYTES);
        let process = from_start(start, &args, now);
        let event = event(
            &process,
            &cmdline,
            cmdline_cut || start.args_truncated,
            &ancestors,
        );
        self.insert(process.clone());
        (event, Lineage { process, ancestors })
    }

    /// Marks processes `alive` says are gone as exited, and removes those
    /// exited longer than [`EXITED_KEPT`].
    // ponytail: a pid reused within EXITED_KEPT by a process that never
    // execs keeps the old entry; compare /proc start times if that bites
    // (pid_max is 4M on current systems, so reuse is rare).
    pub fn reap(&mut self, alive: impl Fn(u32) -> bool, now: Instant) {
        for entry in self.entries.values_mut() {
            if entry.exited.is_none() && !alive(entry.pid) {
                entry.exited = Some(now);
            }
        }
        let before: Vec<u32> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .exited
                    .is_some_and(|at| now.saturating_duration_since(at) > EXITED_KEPT)
            })
            .map(|(pid, _)| *pid)
            .collect();
        for pid in before {
            self.remove(pid);
        }
    }

    fn insert(&mut self, entry: Entry) {
        self.bytes += entry.bytes();
        if let Some(old) = self.entries.insert(entry.pid, entry) {
            self.bytes -= old.bytes();
        }
        if self.entries.len() > MAX_ENTRIES || self.bytes > MAX_BYTES {
            self.evict();
        }
    }

    fn remove(&mut self, pid: u32) {
        if let Some(old) = self.entries.remove(&pid) {
            self.bytes -= old.bytes();
        }
    }

    /// Frees an eighth of the room at once (so a full table does not scan
    /// on every exec): exited first, then seeded, then the oldest.
    fn evict(&mut self) {
        let mut order: Vec<(u8, Instant, u32)> = self
            .entries
            .values()
            .map(|entry| {
                let class = match (entry.exited, entry.seeded) {
                    (Some(_), _) => 0,
                    (None, true) => 1,
                    (None, false) => 2,
                };
                (class, entry.exited.unwrap_or(entry.seen), entry.pid)
            })
            .collect();
        order.sort_unstable();
        let (max_entries, max_bytes) = (MAX_ENTRIES / 8 * 7, MAX_BYTES / 8 * 7);
        for (_, _, pid) in order {
            if self.entries.len() <= max_entries && self.bytes <= max_bytes {
                break;
            }
            self.remove(pid);
        }
    }
}

/// UTF-8 with U+FFFD for invalid sequences.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Cuts `text` to at most `max` bytes on a character boundary.
fn cut(mut text: String, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

fn path(bytes: &[u8]) -> String {
    cut(lossy(bytes), PATH_BYTES).0
}

fn basename(exe: &str) -> &str {
    exe.rsplit('/').next().unwrap_or(exe)
}

/// Whole arguments while they fit in [`ENTRY_ARG_BYTES`]; the first one is
/// cut if it alone is longer.
fn keep_args(args: &[String]) -> (Vec<String>, bool) {
    let mut used = 0;
    let mut kept = Vec::new();
    for arg in args {
        if used + arg.len() > ENTRY_ARG_BYTES {
            if kept.is_empty() {
                kept.push(cut(arg.clone(), ENTRY_ARG_BYTES).0);
            }
            return (kept, true);
        }
        used += arg.len();
        kept.push(arg.clone());
    }
    (kept, false)
}

fn from_start(start: &ProcessStart, args: &[String], now: Instant) -> Entry {
    let exe = path(&start.exe);
    let (kept, cut) = keep_args(args);
    Entry {
        pid: start.pid,
        ppid: start.ppid,
        uid: start.uid,
        euid: start.euid,
        name: basename(&exe).to_owned(),
        exe,
        args: kept,
        args_truncated: cut || start.args_truncated,
        cwd: start.cwd.as_deref().map(path),
        seeded: false,
        synthetic_exe: false,
        seen: now,
        exited: None,
    }
}

/// A seeded process's `exe`: the readable link, else an absolute
/// `argv[0]`, else `[comm]`; never empty.
fn seeded_exe(seeded: &Seeded, name: &str) -> (String, bool) {
    if let Some(link) = seeded.exe.as_deref().filter(|link| !link.is_empty()) {
        return (path(link), false);
    }
    if let Some(argv0) = seeded.args.first().filter(|arg| arg.starts_with(b"/")) {
        return (path(argv0), true);
    }
    if name.is_empty() {
        return ("[unknown]".to_owned(), true);
    }
    (format!("[{name}]"), true)
}

fn from_seeded(seeded: &Seeded, now: Instant) -> Entry {
    let name = path(&seeded.name);
    let (exe, synthetic_exe) = seeded_exe(seeded, &name);
    let args: Vec<String> = seeded.args.iter().map(|arg| lossy(arg)).collect();
    let (args, cut) = keep_args(&args);
    Entry {
        pid: seeded.pid,
        ppid: seeded.ppid,
        uid: seeded.uid,
        euid: seeded.euid,
        name,
        exe,
        args,
        args_truncated: cut || seeded.args_truncated,
        cwd: seeded.cwd.as_deref().map(path),
        seeded: true,
        synthetic_exe,
        seen: now,
        exited: None,
    }
}

/// The `event` values of one start. Every value is within its key's bound
/// by construction, so `set` cannot refuse it.
fn event(process: &Entry, cmdline: &str, truncated: bool, ancestors: &[Entry]) -> ProcessEvent {
    let mut event = ProcessEvent::default();
    let mut set = |key: &str, value: EventValue| {
        let _ = event.set(key, value);
    };
    let text = |value: &str| EventValue::String(value.to_owned());
    set("process.exe", text(&process.exe));
    set("process.name", text(&process.name));
    set("process.cmdline", text(cmdline));
    set("process.cmdline_truncated", EventValue::Boolean(truncated));
    if let Some(cwd) = &process.cwd {
        set("process.cwd", text(cwd));
    }
    set("process.uid", EventValue::Integer(process.uid.into()));
    set("process.euid", EventValue::Integer(process.euid.into()));
    if let Some(parent) = ancestors.first() {
        set("parent.exe", text(&parent.exe));
        set("parent.name", text(&parent.name));
        set("parent.cmdline", text(&parent.args.join(" ")));
        let list = |pick: fn(&Entry) -> &str| {
            let mut items: Vec<String> = ancestors.iter().map(|a| pick(a).to_owned()).collect();
            items.sort_unstable();
            items.dedup();
            EventValue::Strings(items)
        };
        set("ancestors.names", list(|a| &a.name));
        set("ancestors.exes", list(|a| &a.exe));
    }
    event
}
