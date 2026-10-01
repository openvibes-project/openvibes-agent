//! The alarm thread (Linux): beside the one-minute main loop, because an
//! alarm cannot wait a minute. It owns the audit reader, the engine, the
//! alarm queue and delivery; it shares rules, identity and health with the
//! service through [`AlarmShared`].

use std::{
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc::{RecvTimeoutError, sync_channel},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openvibes_collectors::process_events::{
    ProcessStart, Seeded, Source, open_audit_socket, read_process, spawn_reader,
};
use openvibes_core::{AlarmBatch, AlarmHealth, CollectorOutcome, Identifier, SchemaVersion};
use openvibes_rules::EvaluationClock;
use openvibes_storage::AlarmQueue;
use openvibes_transport::{ClientIdentity, PlatformClient, TransportConfig, TransportError};

use super::engine::{Engine, RulePair};

/// Starts beyond this many waiting for the engine are dropped and counted.
pub const CHANNEL: usize = 4_096;
/// After a wakeup, how long the thread lets starts queue up.
const COALESCE: Duration = Duration::from_millis(5);
/// Starts evaluated per queue transaction, at most.
const DRAIN: usize = 256;
/// The first alarm waits this long for others to share its batch.
pub const SEND_AFTER: Duration = Duration::from_secs(5);
/// After a 404 (a platform before P14), the next try.
pub const UNSUPPORTED_RETRY: Duration = Duration::from_secs(3_600);
const RETRY_FIRST: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(3_600);
const REAP_EVERY: Duration = Duration::from_secs(60);

/// What the service and the alarm thread share.
pub struct AlarmShared {
    /// The rules in use, replaced after each scan.
    pub rules: Vec<RulePair>,
    /// Agent id and client identity once enrolled.
    pub identity: Option<(Identifier, ClientIdentity)>,
    /// Health for the heartbeat; the thread writes its parts, the service
    /// the rule counts.
    pub health: AlarmHealth,
    /// Process starts evaluated, rule runs that failed, and rule runs a
    /// missing value made unavailable, since start (for the log and tests).
    pub starts: u64,
    /// See `starts`.
    pub rule_failures: u64,
    /// See `starts`.
    pub rule_unavailable: u64,
}

impl Default for AlarmShared {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            identity: None,
            starts: 0,
            rule_failures: 0,
            rule_unavailable: 0,
            health: AlarmHealth {
                collector: CollectorOutcome::Ok,
                events_dropped_total: 0,
                alarms_dropped_total: 0,
                pending: 0,
                platform_unsupported: false,
                rules_accepted: 0,
                rules_refused: 0,
                rules_without_prefilter: 0,
            },
        }
    }
}

/// Shared state behind one lock.
pub type Shared = Arc<Mutex<AlarmShared>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, AlarmShared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Opens the audit socket and starts the thread. On failure the collector
/// outcome goes into the health report and the agent runs without alarms.
pub fn spawn(
    transport: TransportConfig,
    shared: &Shared,
    state_dir: &Path,
) -> Option<JoinHandle<()>> {
    match open_audit_socket() {
        Ok(socket) => {
            if let Some(bytes) = socket.recv_buffer() {
                eprintln!(
                    "openvibes-agent: reading process starts from kernel audit (receive buffer {} KiB)",
                    bytes / 1024
                );
            }
            spawn_with(socket, read_process, transport, shared, state_dir)
        }
        Err(error) => {
            lock(shared).health.collector = error.code.into();
            None
        }
    }
}

/// [`spawn`] with any source and `/proc` lookup (tests use recorded ones).
pub fn spawn_with<S: Source + 'static>(
    source: S,
    lookup: fn(u32) -> Option<Seeded>,
    transport: TransportConfig,
    shared: &Shared,
    state_dir: &Path,
) -> Option<JoinHandle<()>> {
    let fail = |outcome| {
        lock(shared).health.collector = outcome;
        None
    };
    let Ok(queue) = AlarmQueue::open(&state_dir.join("alarms.sqlite")) else {
        return fail(CollectorOutcome::Internal);
    };
    let (tx, rx) = sync_channel(CHANNEL);
    let dropped = Arc::new(AtomicU64::new(0));
    if spawn_reader(source, tx, Arc::clone(&dropped), lookup).is_err() {
        return fail(CollectorOutcome::Internal);
    }
    // Until the first keyed exec event arrives, the collector cannot tell
    // a quiet host from a missing audit rule or a stopped auditd: it says
    // `not_found` (no exec records to read), then `ok`.
    lock(shared).health.collector = CollectorOutcome::NotFound;
    // Alarms kept across a restart go out without waiting for a new one.
    let now = Instant::now();
    let unsent_since = queue.pending().ok().filter(|n| *n > 0).map(|_| now);
    let mut engine = Engine::default();
    engine.trace = std::env::var_os("OPENVIBES_TRACE_STARTS").is_some();
    let mut worker = Worker {
        engine,
        queue,
        transport,
        shared: Arc::clone(shared),
        lookup,
        unsent_since,
        next_try: now,
        retry: RETRY_FIRST,
        logged_dropped: 0,
        logged_at: None,
    };
    std::thread::Builder::new()
        .name("alarms".into())
        .spawn(move || {
            let (mut last_reap, mut last_report) = (Instant::now(), None);
            loop {
                let received = rx.recv_timeout(Duration::from_secs(1));
                let now = Instant::now();
                match received {
                    Ok(start) => {
                        // Let the burst arrive, then take everything that
                        // is waiting: one wakeup and one queue transaction
                        // (one disk sync) per burst, not per start.
                        std::thread::sleep(COALESCE);
                        let mut starts = vec![start];
                        starts.extend(rx.try_iter().take(DRAIN - 1));
                        worker.on_starts(&starts, now);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        eprintln!(
                            "openvibes-agent: the audit socket failed; alarms are off until the agent restarts"
                        );
                        lock(&worker.shared).health.collector = CollectorOutcome::Internal;
                        return;
                    }
                }
                if now.duration_since(last_reap) >= REAP_EVERY {
                    worker
                        .engine
                        .reap(|pid| Path::new(&format!("/proc/{pid}")).exists(), now);
                    last_reap = now;
                }
                worker.deliver_if_due(now);
                if last_report.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1)) {
                    worker.report(dropped.load(Ordering::Relaxed), now);
                    last_report = Some(now);
                }
            }
        })
        .ok()
}

struct Worker {
    engine: Engine,
    queue: AlarmQueue,
    transport: TransportConfig,
    shared: Shared,
    lookup: fn(u32) -> Option<Seeded>,
    /// When the oldest unsent alarm was queued.
    unsent_since: Option<Instant>,
    next_try: Instant,
    retry: Duration,
    /// Lost starts last logged, and when.
    logged_dropped: u64,
    logged_at: Option<Instant>,
}

struct Clock {
    origin: Instant,
    unix_ms: i64,
}

impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
    fn unix_ms(&self) -> i64 {
        self.unix_ms
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// `alarm.` and 16 random bytes in hex; `None` if the kernel will not
/// give them (the match is then lost and counted, never given a shared id).
fn random_alarm_id() -> Option<Identifier> {
    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    // getrandom blocks only before the kernel's pool is seeded at boot; a
    // short read or EINTR is retried.
    while filled < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => return None,
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return None,
        }
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Identifier::new(format!("alarm.{hex}")).ok()
}

impl Worker {
    fn on_starts(&mut self, starts: &[Box<ProcessStart>], now: Instant) {
        let rules = {
            let mut shared = lock(&self.shared);
            shared.health.collector = CollectorOutcome::Ok;
            shared.starts += starts.len() as u64;
            shared.rules.clone()
        };
        let unix_ms = unix_ms();
        let mut alarms = Vec::new();
        for start in starts {
            // Each start gets its own evaluation deadline.
            let clock = Clock {
                origin: Instant::now(),
                unix_ms,
            };
            alarms.extend(self.engine.on_start(
                start,
                &rules,
                &clock,
                now,
                self.lookup,
                random_alarm_id,
            ));
        }
        // Lost matches and alarms the queue refused count as dropped.
        let mut lost = std::mem::take(&mut self.engine.lost);
        if !alarms.is_empty() {
            match self.queue.upsert_all(&alarms) {
                Ok(refused) => {
                    lost += refused;
                    if refused < alarms.len() as u64 {
                        self.unsent_since.get_or_insert(now);
                    }
                }
                Err(_) => lost += alarms.len() as u64,
            }
        }
        if lost > 0 && self.queue.add_dropped(lost).is_err() {
            // The queue cannot record it either; keep it for later.
            self.engine.lost += lost;
        }
    }

    fn deliver_if_due(&mut self, now: Instant) {
        let due = self
            .unsent_since
            .is_some_and(|since| now.duration_since(since) >= SEND_AFTER);
        if !due || now < self.next_try {
            return;
        }
        let Ok(batch) = self.queue.batch() else {
            return;
        };
        if batch.is_empty() {
            self.unsent_since = None;
            return;
        }
        let Some((agent_id, identity)) = lock(&self.shared).identity.clone() else {
            // Not enrolled yet: the next tick of the service enrolls.
            self.next_try = now + RETRY_FIRST;
            return;
        };
        let alarms = AlarmBatch {
            schema_version: SchemaVersion::V1,
            agent_id,
            dropped_total: self.queue.dropped_total().unwrap_or(0),
            alarms: batch,
        };
        let sent = PlatformClient::new(&self.transport, Some(&identity))
            .and_then(|client| client.send_alarms(&alarms));
        let unsupported = matches!(sent, Err(TransportError::NotFound));
        lock(&self.shared).health.platform_unsupported = unsupported;
        match sent {
            Ok(()) => {
                let _ = self.queue.sent(&alarms.alarms);
                self.retry = RETRY_FIRST;
            }
            Err(TransportError::Rejected | TransportError::InvalidRequest) => {
                let _ = self.queue.drop_batch(&alarms.alarms);
            }
            Err(TransportError::NotFound) => self.next_try = now + UNSUPPORTED_RETRY,
            Err(_) => {
                self.next_try = now + self.retry;
                self.retry = (self.retry * 2).min(RETRY_MAX);
            }
        }
    }

    fn report(&mut self, events_dropped: u64, now: Instant) {
        // Lost process starts are logged, at most once a minute.
        if events_dropped > self.logged_dropped
            && self
                .logged_at
                .is_none_or(|at| now.duration_since(at) >= REAP_EVERY)
        {
            eprintln!(
                "openvibes-agent: {} process starts lost before evaluation ({events_dropped} since start)",
                events_dropped - self.logged_dropped
            );
            self.logged_dropped = events_dropped;
            self.logged_at = Some(now);
        }
        let mut shared = lock(&self.shared);
        shared.rule_failures = self.engine.failures;
        shared.rule_unavailable = self.engine.unavailable;
        let health = &mut shared.health;
        health.events_dropped_total = events_dropped;
        if let Ok(dropped) = self.queue.dropped_total() {
            health.alarms_dropped_total = dropped;
        }
        if let Ok(pending) = self.queue.pending() {
            health.pending = pending;
        }
    }
}
