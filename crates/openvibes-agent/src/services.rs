//! Host services delivery (protocol P15): the listeners and services of the
//! last scan go to `POST /v1/services` when their digest changed since the
//! platform last acknowledged them, and at least once a day.

use std::path::{Path, PathBuf};

use openvibes_core::{
    HOST_SERVICES_BYTES, HostService, HostServices, Identifier, Owners, SERVICES_MAX_LISTENERS,
    SERVICES_MAX_SERVICES, SchemaVersion, ServiceListener, hex, listener_row, service_row,
    services_digest,
};
use openvibes_transport::{PlatformClient, TransportError};

/// Resend an unchanged list after this long.
const RESEND_MS: i64 = 24 * 60 * 60 * 1000;
/// Room left in the document for everything but the two lists.
const ENVELOPE_BYTES: usize = 1_024;

/// One scan's listeners and services, cut to the limits, with their digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) owners: Owners,
    pub(crate) listeners: Vec<ServiceListener>,
    pub(crate) services: Vec<HostService>,
    pub(crate) collected_at_unix_ms: i64,
    pub(crate) sha256: String,
    /// A list was cut to the limits.
    pub(crate) truncated: bool,
}

impl Snapshot {
    /// Sorts and deduplicates both lists in digest order, keeps the first
    /// entries within the count and size limits (contract, "Host
    /// services"), and computes the digest of what is kept.
    pub(crate) fn new(
        owners: Owners,
        listeners: Vec<ServiceListener>,
        services: Vec<HostService>,
        collected_at_unix_ms: i64,
    ) -> Self {
        let mut budget = HOST_SERVICES_BYTES - ENVELOPE_BYTES;
        let mut truncated = false;
        let listeners = keep(
            listeners,
            listener_row,
            SERVICES_MAX_LISTENERS,
            &mut budget,
            &mut truncated,
        );
        let services = keep(
            services,
            service_row,
            SERVICES_MAX_SERVICES,
            &mut budget,
            &mut truncated,
        );
        let sha256 = hex(&services_digest(&listeners, &services));
        Self {
            owners,
            listeners,
            services,
            collected_at_unix_ms,
            sha256,
            truncated,
        }
    }
}

/// `items` sorted and deduplicated by `row`, at most `max`, and only while
/// their serialized JSON (plus a comma each) fits `budget`; sets
/// `truncated` when any is left out.
fn keep<T: serde::Serialize>(
    items: Vec<T>,
    row: fn(&T) -> String,
    max: usize,
    budget: &mut usize,
    truncated: &mut bool,
) -> Vec<T> {
    let mut rows: Vec<(String, T)> = items.into_iter().map(|item| (row(&item), item)).collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.dedup_by(|a, b| a.0 == b.0);
    *truncated |= rows.len() > max;
    let mut kept = Vec::new();
    for (_, item) in rows.into_iter().take(max) {
        let size = serde_json::to_vec(&item).map_or(usize::MAX, |bytes| bytes.len() + 1);
        if size > *budget {
            *truncated = true;
            break;
        }
        *budget -= size;
        kept.push(item);
    }
    kept
}

/// What the platform has, and whether to send again.
#[derive(Debug, Default)]
pub(crate) struct Delivery {
    /// The last scan's lists.
    pub(crate) pending: Option<Snapshot>,
    /// Digest and time of the last list the platform acknowledged, kept in
    /// the state directory as `SHA256 UNIX_MS`.
    acked: Option<(String, i64)>,
    ack_file: PathBuf,
    /// A digest the platform refused (400, 413) or that is invalid: not
    /// sent again until the lists change.
    refused: Option<String>,
    /// Collection time of a snapshot whose send failed: retried with the
    /// next scan's snapshot, not every tick.
    failed: Option<i64>,
    /// The platform answered 404 (before P15): nothing more until restart.
    unsupported: bool,
    /// Whether the last logged report was cut.
    logged_truncated: bool,
}

/// File in the state directory holding the acknowledged digest and time.
const SERVICES_ACK: &str = "services.ack";

impl Delivery {
    pub(crate) fn open(state_dir: &Path) -> Self {
        let ack_file = state_dir.join(SERVICES_ACK);
        let acked = std::fs::read_to_string(&ack_file)
            .ok()
            .and_then(|text| parse_ack(&text));
        Self {
            acked,
            ack_file,
            ..Self::default()
        }
    }

    /// `Some(cut)` when the pending report's cut differs from the last one
    /// logged.
    pub(crate) fn truncation_change(&mut self) -> Option<bool> {
        let truncated = self.pending.as_ref()?.truncated;
        (truncated != self.logged_truncated).then(|| {
            self.logged_truncated = truncated;
            truncated
        })
    }

    /// The report to send now, if any.
    pub(crate) fn due(&self, agent_id: &Identifier, now_unix_ms: i64) -> Option<HostServices> {
        let pending = self.pending.as_ref()?;
        if self.unsupported
            || self.refused.as_deref() == Some(pending.sha256.as_str())
            || self.failed == Some(pending.collected_at_unix_ms)
        {
            return None;
        }
        let fresh = self.acked.as_ref().is_some_and(|(digest, at)| {
            *digest == pending.sha256 && (0..RESEND_MS).contains(&(now_unix_ms - at))
        });
        (!fresh).then(|| HostServices {
            schema_version: SchemaVersion::V1,
            agent_id: agent_id.clone(),
            collected_at_unix_ms: pending.collected_at_unix_ms,
            sha256: pending.sha256.clone(),
            owners: pending.owners,
            truncated: pending.truncated,
            listeners: pending.listeners.clone(),
            services: pending.services.clone(),
        })
    }

    /// Records how sending `report` went; returns the error to report.
    pub(crate) fn sent(
        &mut self,
        report: &HostServices,
        result: Result<(), TransportError>,
        now_unix_ms: i64,
    ) -> Option<TransportError> {
        match result {
            Ok(()) => {
                // ponytail: a failed write costs one resend after a restart.
                let _ = crate::service::write_private(
                    &self.ack_file,
                    format!("{} {now_unix_ms}", report.sha256).as_bytes(),
                );
                self.acked = Some((report.sha256.clone(), now_unix_ms));
                self.failed = None;
                None
            }
            Err(TransportError::NotFound) => {
                self.unsupported = true;
                None
            }
            Err(error @ (TransportError::Rejected | TransportError::InvalidRequest)) => {
                self.refused = Some(report.sha256.clone());
                Some(error)
            }
            Err(error) => {
                self.failed = Some(report.collected_at_unix_ms);
                Some(error)
            }
        }
    }

    /// Sends the pending report if due.
    pub(crate) fn report(
        &mut self,
        client: &PlatformClient,
        agent_id: &Identifier,
        now_unix_ms: i64,
    ) -> Option<TransportError> {
        let report = self.due(agent_id, now_unix_ms)?;
        let result = client.report_services(&report);
        self.sent(&report, result, now_unix_ms)
    }
}

fn parse_ack(text: &str) -> Option<(String, i64)> {
    let (digest, at) = text.trim().split_once(' ')?;
    openvibes_core::digest_from_hex(digest)?;
    Some((digest.to_owned(), at.parse().ok()?))
}

#[cfg(test)]
mod tests;
