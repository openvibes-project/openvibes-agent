//! The reader thread: audit messages in, joined process starts out, never
//! waiting on whoever consumes them.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{SyncSender, TrySendError},
    },
    thread::JoinHandle,
    time::Instant,
};

use super::{Joiner, MAX_MESSAGE, ProcessStart, Seeded};

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

/// Pids of recent execs remembered, to skip snapshots of known parents.
pub const RECENT_EXECS: usize = 4_096;

/// Where audit messages come from: the socket, or recorded ones in tests.
pub trait Source: Send {
    /// Receives one message into `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> Received;
}

/// Starts the reader: joins records, reads each start's parent with
/// `lookup` (from `/proc`) at once, and hands the start to `tx` with
/// `try_send`. A full channel, an unfinished event and a kernel `ENOBUFS`
/// each add to `dropped`; the reader never blocks on the channel. It stops
/// when the source closes or the receiver is gone.
pub fn spawn_reader<S: Source + 'static>(
    mut source: S,
    tx: SyncSender<ProcessStart>,
    dropped: Arc<AtomicU64>,
    lookup: fn(u32) -> Option<Seeded>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("audit-reader".into())
        .spawn(move || {
            let mut joiner = Joiner::default();
            // Pids the reader saw exec: the engine's table already knows
            // them, so their children need no /proc snapshot.
            let mut recent = std::collections::HashSet::new();
            let mut order = std::collections::VecDeque::new();
            let mut buf = vec![0; MAX_MESSAGE + 16];
            loop {
                let now = Instant::now();
                match source.recv(&mut buf) {
                    Received::Message(len) => {
                        if let Some(mut start) = joiner.push(&buf[..len.min(buf.len())], now) {
                            if start.ppid != 0 && !recent.contains(&start.ppid) {
                                start.parent = lookup(start.ppid);
                            }
                            let pid = start.pid;
                            match tx.try_send(start) {
                                // Known to the engine's table only once sent.
                                Ok(()) => {
                                    if recent.insert(pid) {
                                        order.push_back(pid);
                                        if order.len() > RECENT_EXECS
                                            && let Some(old) = order.pop_front()
                                        {
                                            recent.remove(&old);
                                        }
                                    }
                                }
                                Err(TrySendError::Full(_)) => {
                                    // Its children need a snapshot again.
                                    recent.remove(&pid);
                                    dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Disconnected(_)) => return,
                            }
                        }
                    }
                    Received::Lost => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Received::Idle => {}
                    Received::Closed => return,
                }
                dropped.fetch_add(joiner.expire(now), Ordering::Relaxed);
            }
        })
}
