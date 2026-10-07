//! The audit side of the reader: audit messages in, joined process starts
//! out (the forwarding half is in `forward.rs`).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::SyncSender,
    },
    thread::JoinHandle,
    time::Instant,
};

use super::{
    Joiner, MAX_MESSAGE, Next, ProcessStart, Seeded, StartSource, forward::spawn_forwarder,
};

/// What one receive gave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received {
    /// A message of this many bytes.
    Message(usize),
    /// The kernel dropped messages because the socket buffer was full
    /// (`ENOBUFS`); reading goes on.
    Lost,
    /// Nothing arrived before the timeout.
    Idle,
    /// The source failed for good.
    Closed,
}

/// Process starts lost before evaluation, by cause, since the reader
/// started. The causes call for different fixes: a socket overflow wants a
/// bigger buffer or a quieter audit rule, an unfinished event wants a look
/// at the audit stream, a full queue means the engine cannot keep up.
#[derive(Debug, Default)]
pub struct Drops {
    /// The kernel overflowed the audit socket (`ENOBUFS`).
    pub overflow: AtomicU64,
    /// An event never got its closing record in time, or was pushed out by
    /// too many open events.
    pub unfinished: AtomicU64,
    /// The channel to the engine was full.
    pub queue_full: AtomicU64,
}

impl Drops {
    /// All causes together.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
            + self.unfinished.load(Ordering::Relaxed)
            + self.queue_full.load(Ordering::Relaxed)
    }
}

/// Pids of recent execs remembered, to skip snapshots of known parents.
pub const RECENT_EXECS: usize = 4_096;

/// Where audit messages come from: the socket, or recorded ones in tests.
pub trait Source: Send {
    /// Receives one message into `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> Received;
}

/// Audit messages joined into process starts: [`Source`] plus [`Joiner`].
pub struct AuditStarts<S: Source> {
    source: S,
    joiner: Joiner,
    buf: Vec<u8>,
    /// Expirations that happened on a receive that also returned a start or
    /// a loss; reported by the next call so none is lost or counted twice.
    pending: u64,
}

impl<S: Source> AuditStarts<S> {
    /// Wraps `source`.
    #[must_use]
    pub fn new(source: S) -> Self {
        Self {
            source,
            joiner: Joiner::default(),
            buf: vec![0; MAX_MESSAGE + 16],
            pending: 0,
        }
    }
}

impl<S: Source> StartSource for AuditStarts<S> {
    fn next(&mut self) -> Next {
        if self.pending > 0 {
            return Next::Unfinished(std::mem::take(&mut self.pending));
        }
        let now = Instant::now();
        let got = match self.source.recv(&mut self.buf) {
            Received::Message(len) => {
                let len = len.min(self.buf.len());
                self.joiner
                    .push(&self.buf[..len], now)
                    .map_or(Next::Idle, Next::Start)
            }
            Received::Lost => Next::Lost(1),
            Received::Idle => Next::Idle,
            Received::Closed => return Next::Closed,
        };
        let expired = self.joiner.expire(now);
        if expired == 0 {
            return got;
        }
        if matches!(got, Next::Idle) {
            return Next::Unfinished(expired);
        }
        self.pending = expired;
        got
    }
}

/// Starts the reader: joins records, reads each start's parent with
/// `lookup` (from `/proc`) at once, and hands the start to `tx` with
/// `try_send`. A full channel, an unfinished event and a kernel `ENOBUFS`
/// each add to `dropped` under its own cause; the reader never blocks on the
/// channel. It stops when the source closes or the receiver is gone.
pub fn spawn_reader<S: Source + 'static>(
    source: S,
    tx: SyncSender<Box<ProcessStart>>,
    dropped: Arc<Drops>,
    lookup: fn(u32) -> Option<Seeded>,
) -> std::io::Result<JoinHandle<()>> {
    spawn_forwarder(
        "audit-reader",
        AuditStarts::new(source),
        tx,
        dropped,
        lookup,
    )
}
