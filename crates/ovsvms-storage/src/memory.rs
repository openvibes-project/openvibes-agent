use std::{
    collections::{HashSet, VecDeque},
    fmt,
};

use ovsvms_core::{DeliveryAcknowledgement, Finding, Identifier, ResourceLimits, Validate};

/// Fixed queue failure categories; no finding content is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// Capacity or delivery batch limit is zero or above the V1 ceiling.
    InvalidLimits,
    /// The finding violates its versioned contract.
    InvalidFinding,
    /// The queue is at capacity; the caller must apply backpressure.
    Full,
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid queue limits",
            Self::InvalidFinding => "invalid finding contract",
            Self::Full => "finding queue is full",
        })
    }
}

impl std::error::Error for QueueError {}

/// Why a delivery attempt left every finding queued.
#[derive(Debug, Eq, PartialEq)]
pub enum DeliveryError<E> {
    /// The transport failed; the batch remains queued for retry.
    Transport(E),
    /// The platform response violates the acknowledgement contract.
    InvalidAcknowledgement,
}

impl<E: fmt::Display> fmt::Display for DeliveryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "finding delivery failed: {error}"),
            Self::InvalidAcknowledgement => f.write_str("invalid delivery acknowledgement"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for DeliveryError<E> {}

/// Bounded, deduplicating FIFO of findings awaiting platform acknowledgement.
///
/// Findings leave the queue only when the platform acknowledges them as part of
/// the batch they were sent in; a failed or partial delivery keeps them queued.
// ponytail: count-bounded and lost on restart; the SQLite queue (Milestone 3)
// bounds by `queue_bytes`, adds retention, and remembers acknowledged IDs.
pub struct MemoryQueue {
    limits: ResourceLimits,
    capacity: usize,
    pending: VecDeque<Finding>,
    ids: HashSet<Identifier>,
}

impl MemoryQueue {
    /// Creates a queue holding at most `capacity` findings. Limits may tighten,
    /// but never exceed, the V1 delivery batch ceiling.
    pub fn new(limits: ResourceLimits, capacity: usize) -> Result<Self, QueueError> {
        let batch = limits.delivery_batch_items;
        if capacity == 0 || batch == 0 || batch > ResourceLimits::V1.delivery_batch_items {
            return Err(QueueError::InvalidLimits);
        }
        Ok(Self {
            limits,
            capacity,
            pending: VecDeque::new(),
            ids: HashSet::new(),
        })
    }

    /// Queues a validated finding. Returns `false` when a finding with the same
    /// stable identifier is already pending, so replays are delivered once.
    pub fn enqueue(&mut self, finding: Finding) -> Result<bool, QueueError> {
        finding
            .validate(self.limits)
            .map_err(|_| QueueError::InvalidFinding)?;
        if self.ids.contains(&finding.finding_id) {
            return Ok(false);
        }
        if self.pending.len() >= self.capacity {
            return Err(QueueError::Full);
        }
        self.ids.insert(finding.finding_id.clone());
        self.pending.push_back(finding);
        Ok(true)
    }

    /// Number of findings awaiting acknowledgement.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no findings await acknowledgement.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Sends the oldest bounded batch through `send` and removes only findings
    /// that were in that batch and are named by a valid acknowledgement.
    /// Acknowledged IDs outside the batch are ignored, so a faulty or hostile
    /// response cannot discard findings that were never delivered.
    /// Returns the number of findings removed; `send` is not called when empty.
    pub fn deliver<E>(
        &mut self,
        send: impl FnOnce(&[Finding]) -> Result<DeliveryAcknowledgement, E>,
    ) -> Result<usize, DeliveryError<E>> {
        let size = self.pending.len().min(self.limits.delivery_batch_items);
        if size == 0 {
            return Ok(0);
        }
        let batch = &self.pending.make_contiguous()[..size];
        let ack = send(batch).map_err(DeliveryError::Transport)?;
        ack.validate(self.limits)
            .map_err(|_| DeliveryError::InvalidAcknowledgement)?;
        let accepted: HashSet<&Identifier> = ack.accepted_finding_ids.iter().collect();
        let delivered: HashSet<Identifier> = batch
            .iter()
            .filter(|finding| accepted.contains(&finding.finding_id))
            .map(|finding| finding.finding_id.clone())
            .collect();
        self.pending
            .retain(|finding| !delivered.contains(&finding.finding_id));
        self.ids.retain(|id| !delivered.contains(id));
        Ok(delivered.len())
    }
}

#[cfg(test)]
mod tests {
    use ovsvms_core::{
        Confidence, DeliveryAcknowledgement, Finding, Identifier, ResourceLimits, SchemaVersion,
        Severity,
    };

    use super::{DeliveryError, MemoryQueue, QueueError};

    fn id(value: &str) -> Identifier {
        Identifier::new(value).unwrap()
    }

    fn finding(name: &str) -> Finding {
        Finding {
            schema_version: SchemaVersion::V1,
            finding_id: id(name),
            scan_id: id("scan.1"),
            rule_id: id("rule.1"),
            rule_version: 1,
            observed_at_unix_ms: 1,
            severity: Severity::Low,
            confidence: Confidence::new(50).unwrap(),
            message: "synthetic".into(),
            evidence: Vec::new(),
        }
    }

    fn ack(ids: &[&str]) -> DeliveryAcknowledgement {
        DeliveryAcknowledgement {
            schema_version: SchemaVersion::V1,
            accepted_finding_ids: ids.iter().map(|name| id(name)).collect(),
            acknowledged_at_unix_ms: 2,
        }
    }

    fn queue(capacity: usize, batch: usize) -> MemoryQueue {
        let limits = ResourceLimits {
            delivery_batch_items: batch,
            ..ResourceLimits::V1
        };
        let mut queue = MemoryQueue::new(limits, capacity).unwrap();
        for name in ["f.a", "f.b", "f.c"].into_iter().take(capacity) {
            assert!(queue.enqueue(finding(name)).unwrap());
        }
        queue
    }

    #[test]
    fn limits_are_bounded() {
        let over = ResourceLimits {
            delivery_batch_items: ResourceLimits::V1.delivery_batch_items + 1,
            ..ResourceLimits::V1
        };
        assert_eq!(
            MemoryQueue::new(ResourceLimits::V1, 0).err(),
            Some(QueueError::InvalidLimits)
        );
        assert_eq!(
            MemoryQueue::new(over, 1).err(),
            Some(QueueError::InvalidLimits)
        );
    }

    #[test]
    fn enqueue_validates_deduplicates_and_applies_backpressure() {
        let mut queue = queue(2, 10);
        assert_eq!(queue.enqueue(finding("f.a")), Ok(false));
        assert_eq!(queue.enqueue(finding("f.c")), Err(QueueError::Full));
        let mut invalid = finding("f.d");
        invalid.message.clear();
        assert_eq!(queue.enqueue(invalid), Err(QueueError::InvalidFinding));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn delivery_is_batched_fifo_and_removes_only_acknowledged_batch_members() {
        let mut queue = queue(3, 2);
        let mut sent = Vec::new();
        // f.c was never sent in this batch, so acknowledging it must not drop it.
        let removed = queue
            .deliver(|batch| {
                sent = batch.iter().map(|f| f.finding_id.clone()).collect();
                Ok::<_, ()>(ack(&["f.a", "f.c"]))
            })
            .unwrap();
        assert_eq!(sent, [id("f.a"), id("f.b")]);
        assert_eq!(removed, 1);
        assert_eq!(queue.len(), 2);
        // The acknowledged ID may be queued again; unacknowledged ones stay deduplicated.
        assert_eq!(queue.enqueue(finding("f.a")), Ok(true));
        assert_eq!(queue.enqueue(finding("f.b")), Ok(false));
    }

    #[test]
    fn failed_or_invalid_delivery_keeps_everything_queued() {
        let mut queue = queue(3, 10);
        assert_eq!(
            queue.deliver(|_| Err("offline")),
            Err(DeliveryError::Transport("offline"))
        );
        let mut bad = ack(&["f.a"]);
        bad.acknowledged_at_unix_ms = -1;
        assert_eq!(
            queue.deliver(|_| Ok::<_, ()>(bad)),
            Err(DeliveryError::InvalidAcknowledgement)
        );
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn empty_queue_does_not_call_transport() {
        let mut queue = MemoryQueue::new(ResourceLimits::V1, 1).unwrap();
        assert_eq!(
            queue.deliver(|_| -> Result<DeliveryAcknowledgement, ()> {
                panic!("transport called for an empty queue")
            }),
            Ok(0)
        );
        assert!(queue.is_empty());
    }
}
