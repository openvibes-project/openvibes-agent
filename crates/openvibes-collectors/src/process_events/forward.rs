//! The forwarding half of the reader: process starts in from any source,
//! parent lookup, the recent-exec set, `try_send` to the engine, drop
//! counting, never waiting on whoever consumes them.

use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::Ordering,
        mpsc::{SyncSender, TrySendError},
    },
    thread::JoinHandle,
};

use super::{Drops, ProcessStart, RECENT_EXECS, Seeded};

/// One step of a source of process starts (audit joined, or eBPF records).
// Returned by value once per event and moved straight into a Box.
#[allow(clippy::large_enum_variant)]
pub enum Next {
    /// A process start.
    Start(ProcessStart),
    /// The source lost this many starts to a full kernel buffer.
    Lost(u64),
    /// This many events never finished and were dropped.
    Unfinished(u64),
    /// Nothing arrived before the timeout.
    Idle,
    /// The source failed for good.
    Closed,
}

/// Anything that yields process starts.
pub trait StartSource: Send {
    /// Blocks for a bounded time and returns the next step.
    fn next(&mut self) -> Next;
}

impl<S: StartSource + ?Sized> StartSource for Box<S> {
    fn next(&mut self) -> Next {
        (**self).next()
    }
}

/// Starts the forwarding thread `name`: parent lookup for unknown parents,
/// the recent-exec set, `try_send` to the engine, drop counting. It stops
/// when the source closes or the receiver is gone.
pub fn spawn_forwarder<S: StartSource + 'static>(
    name: &str,
    mut source: S,
    tx: SyncSender<Box<ProcessStart>>,
    dropped: Arc<Drops>,
    lookup: fn(u32) -> Option<Seeded>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            // Pids seen exec: the engine's table already knows them, so their
            // children need no /proc snapshot.
            let mut recent = HashSet::new();
            let mut order = VecDeque::new();
            loop {
                match source.next() {
                    Next::Start(mut start) => {
                        if start.ppid != 0 && !recent.contains(&start.ppid) {
                            start.parent = lookup(start.ppid);
                        }
                        let pid = start.pid;
                        // Boxed: the channel's 4,096 slots then hold pointers,
                        // not whole starts.
                        match tx.try_send(Box::new(start)) {
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
                                dropped.queue_full.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => return,
                        }
                    }
                    Next::Lost(n) => {
                        dropped.overflow.fetch_add(n, Ordering::Relaxed);
                    }
                    Next::Unfinished(n) => {
                        dropped.unfinished.fetch_add(n, Ordering::Relaxed);
                    }
                    Next::Idle => {}
                    Next::Closed => return,
                }
            }
        })
}
