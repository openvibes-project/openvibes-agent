use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

use openvibes_core::{
    CollectorError, CollectorErrorCode, DeliveryAcknowledgement, FindingExport, Heartbeat,
    Identifier, InventoryExport, ResourceLimits, SchemaVersion, Validate,
};
use openvibes_rules::RuleLoader;
use openvibes_storage::{
    DeliveryError, IdentityStore, RuleStore, SqliteQueue, install_id, prepare_state_dir,
};
use openvibes_transport::{PlatformClient, TransportConfig, TransportError};
use serde::Serialize;

use crate::{
    AgentConfig, AgentError, Enrollment, ExportFailure, ScanReport, forget_if_revoked,
    load_or_enroll, read_enrollment_token, renew_if_due,
};

/// What one [`Service::export`] wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReport {
    /// Findings exported and removed from the queue.
    pub findings: usize,
    /// Packages in the inventory file, or why no inventory was written.
    pub packages: Result<usize, CollectorError>,
}

/// What one [`Service::tick`] accomplished.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TickReport {
    /// The identity was rotated this tick.
    pub renewed: bool,
    /// A due renewal failed; the current, still valid identity was kept and
    /// renewal is retried next tick.
    pub renewal_error: Option<AgentError>,
    /// Findings the platform acknowledged this tick, rejected ones included.
    pub delivered: usize,
    /// Of those, the ones the platform refused permanently, counted by
    /// reason; they left the queue and are not retried.
    pub rejected: BTreeMap<String, usize>,
}

/// The agent's durable state and the platform lifecycle driven over it.
pub struct Service {
    config: AgentConfig,
    install_id: Identifier,
    identities: IdentityStore,
    queue: SqliteQueue,
    rules: RuleStore,
    loader: RuleLoader,
    last_scan_unix_ms: Option<i64>,
    enrollment: Option<Enrollment>,
}

impl Service {
    /// Prepares the state directory and opens the identity store and queue.
    /// An invalid platform URL, CA bundle, or proxy fails here, at startup.
    pub fn open(config: AgentConfig) -> Result<Self, AgentError> {
        for transport in config.transport.iter().chain(&config.distribution) {
            PlatformClient::new(transport, None)?;
        }
        prepare_state_dir(&config.state_dir)?;
        let limits = ResourceLimits::V1;
        Ok(Self {
            install_id: install_id(&config.state_dir.join("install.sqlite"))?,
            identities: IdentityStore::open(&config.state_dir.join("identity.sqlite"), limits)?,
            queue: SqliteQueue::open(&config.state_dir.join("queue.sqlite"), limits)?,
            rules: RuleStore::open(&config.state_dir.join("rules.sqlite"), limits)?,
            loader: RuleLoader::new(config.scan.trusted_keys.clone(), limits)
                .map_err(|_| AgentError::Config)?,
            last_scan_unix_ms: None,
            config,
            enrollment: None,
        })
    }

    /// The durable finding queue; scans enqueue their findings here.
    pub fn queue(&mut self) -> &mut SqliteQueue {
        &mut self.queue
    }

    /// Scans once the scan interval has passed since the last scan in this
    /// process (so right after start, and after the clock steps backwards),
    /// and returns `None` otherwise or when no rule set is configured. Needs
    /// no platform and no enrollment; an enrolled agent with a distribution
    /// service first asks it for newer rule bundles.
    pub fn scan_if_due(&mut self, now_unix_ms: i64) -> Result<Option<ScanReport>, AgentError> {
        let scan = &self.config.scan;
        let due = self.last_scan_unix_ms.is_none_or(|last| {
            now_unix_ms < last || now_unix_ms.saturating_sub(last) >= scan.interval_ms
        });
        if scan.rule_sets.is_empty() || !due {
            return Ok(None);
        }
        self.last_scan_unix_ms = Some(now_unix_ms);
        let client = self.distribution_client(now_unix_ms)?;
        let report = crate::scan::scan(
            &self.config.scan.rule_sets,
            client.as_ref(),
            &self.loader,
            &mut self.rules,
            &mut self.queue,
            &self.install_id,
            now_unix_ms,
        )?;
        let revoked = report
            .rule_set_errors
            .iter()
            .any(|(_, error)| *error == AgentError::Transport(TransportError::IdentityRevoked));
        if revoked && forget_if_revoked(&mut self.identities, TransportError::IdentityRevoked)? {
            self.enrollment = None;
        }
        Ok(Some(report))
    }

    /// An mTLS client for the distribution service, if one is configured and
    /// the agent holds an identity. Loading the stored identity never uses
    /// the network.
    fn distribution_client(
        &mut self,
        now_unix_ms: i64,
    ) -> Result<Option<PlatformClient>, AgentError> {
        let (Some(distribution), Some(platform)) =
            (&self.config.distribution, &self.config.transport)
        else {
            return Ok(None);
        };
        if self.enrollment.is_none() {
            match load_or_enroll(&mut self.identities, platform, None, now_unix_ms) {
                Ok(enrollment) => self.enrollment = Some(enrollment),
                Err(AgentError::NotEnrolled) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let identity = self
            .enrollment
            .as_ref()
            .map(|enrollment| &enrollment.identity);
        Ok(Some(PlatformClient::new(distribution, identity)?))
    }

    /// One pass of the platform lifecycle: load or enroll the identity, renew
    /// it if due, send a heartbeat, and deliver one batch of due findings.
    /// A local-only agent does nothing here and never uses the network.
    ///
    /// A failed renewal does not stop the tick while the current certificate
    /// is still usable. An expired certificate is dropped and the agent
    /// enrolls again with its token file. An explicit revocation deletes the
    /// identity and ends the tick; the next tick re-enrolls once a new token
    /// is supplied.
    pub fn tick(&mut self, now_unix_ms: i64) -> Result<TickReport, AgentError> {
        let Some(transport) = &self.config.transport else {
            return Ok(TickReport::default());
        };
        let token_file = self.config.enrollment_token_file.as_deref();
        let token = || match token_file {
            Some(path) => read_enrollment_token(path),
            None => Ok(None),
        };
        let mut enrollment = match self.enrollment.take() {
            Some(enrollment) => enrollment,
            None => load_or_enroll(
                &mut self.identities,
                transport,
                token()?.as_ref(),
                now_unix_ms,
            )?,
        };
        // An expired certificate can no longer renew (renewal needs a valid
        // one), so drop the identity, keeping the queue, and enroll again
        // with the token file. Its token is not refused: this is not a
        // revocation.
        if now_unix_ms >= enrollment.expires_at_unix_ms {
            self.identities.clear()?;
            enrollment = load_or_enroll(
                &mut self.identities,
                transport,
                token()?.as_ref(),
                now_unix_ms,
            )?;
        }
        let mut report = TickReport::default();
        match renew_if_due(&mut self.identities, transport, &enrollment, now_unix_ms) {
            Ok(Some(renewed)) => {
                enrollment = renewed;
                report.renewed = true;
            }
            Ok(None) => {}
            Err(AgentError::Transport(error))
                if forget_if_revoked(&mut self.identities, error)? =>
            {
                return Err(AgentError::Transport(error));
            }
            Err(error) => report.renewal_error = Some(error),
        }

        let result = exchange(&mut self.queue, transport, &enrollment, now_unix_ms);
        if let Err(AgentError::Transport(error)) = result
            && forget_if_revoked(&mut self.identities, error)?
        {
            return Err(AgentError::Transport(error));
        }
        self.enrollment = Some(enrollment);
        (report.delivered, report.rejected) = result?;
        Ok(report)
    }

    /// Writes a fresh `InventoryExport` of the installed packages to `dir`,
    /// then every due queued finding as `FindingExport` files of up to one
    /// delivery batch each. Each findings file is flushed to disk before its
    /// findings leave the queue, and no existing file is overwritten. A failed
    /// package collection, or an inventory over the document limit, is
    /// reported and skips only the inventory file. Only
    /// a local-only agent exports, so export never races platform delivery.
    ///
    // ponytail: rides the queue's delivery path, so findings still in backoff
    // from an earlier online configuration wait until due, and a failed write
    // backs its batch off. Add a queue export method if operators hit that.
    pub fn export(&mut self, dir: &Path, now_unix_ms: i64) -> Result<ExportReport, AgentError> {
        if self.config.transport.is_some() {
            return Err(AgentError::NotLocalOnly);
        }
        let agent_id = self.identities.get()?.map(|stored| stored.agent_id);
        let hostname = openvibes_collectors::hostname();
        let limits = ResourceLimits::V1;
        let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
        let packages = match openvibes_collectors::collect_packages(deadline, limits) {
            Ok(packages) => {
                let count = packages.len();
                let name = format!(
                    "openvibes-inventory-{}-{now_unix_ms}.json",
                    self.install_id.as_str()
                );
                let document = InventoryExport {
                    schema_version: SchemaVersion::V1,
                    install_id: self.install_id.clone(),
                    agent_id: agent_id.clone(),
                    hostname: hostname.clone(),
                    scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
                    collected_at_unix_ms: now_unix_ms,
                    packages,
                };
                inventory_outcome(write_export(&dir.join(name), &document).map(|()| count))?
            }
            Err(error) => Err(error),
        };
        let mut exported = 0;
        for sequence in 0.. {
            let name = format!(
                "openvibes-export-{}-{now_unix_ms}-{sequence}.json",
                self.install_id.as_str()
            );
            let written = self
                .queue
                .deliver(now_unix_ms, |findings| {
                    let document = FindingExport {
                        schema_version: SchemaVersion::V1,
                        install_id: self.install_id.clone(),
                        agent_id: agent_id.clone(),
                        hostname: hostname.clone(),
                        scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
                        exported_at_unix_ms: now_unix_ms,
                        findings: findings.to_vec(),
                    };
                    write_export(&dir.join(&name), &document)?;
                    Ok(DeliveryAcknowledgement {
                        schema_version: SchemaVersion::V1,
                        accepted_finding_ids: findings
                            .iter()
                            .map(|finding| finding.finding_id.clone())
                            .collect(),
                        acknowledged_at_unix_ms: now_unix_ms,
                        rejected_findings: Vec::new(),
                    })
                })
                .map_err(|error| match error {
                    DeliveryError::Transport(error) => error,
                    DeliveryError::InvalidAcknowledgement => {
                        AgentError::Export(ExportFailure::Invalid)
                    }
                    DeliveryError::Queue(error) => AgentError::Storage(error),
                })?;
            if written == 0 {
                break;
            }
            exported += written;
        }
        Ok(ExportReport {
            findings: exported,
            packages,
        })
    }
}

/// An inventory the document limits refuse is reported and skipped, so the
/// findings are still exported; any other failure to write it stops the
/// export (the findings could not be written there either).
fn inventory_outcome(
    written: Result<usize, AgentError>,
) -> Result<Result<usize, CollectorError>, AgentError> {
    match written {
        Ok(count) => Ok(Ok(count)),
        Err(AgentError::Export(ExportFailure::TooLarge | ExportFailure::Invalid)) => {
            Ok(Err(CollectorError {
                collector: Identifier::new("packages").map_err(|_| AgentError::Config)?,
                code: CollectorErrorCode::InvalidData,
                message: "the inventory exceeds the 1 MiB document limit; not written".into(),
                retryable: false,
            }))
        }
        Err(error) => Err(error),
    }
}

/// Heartbeat, then one delivery batch, over mTLS.
fn exchange(
    queue: &mut SqliteQueue,
    transport: &TransportConfig,
    enrollment: &Enrollment,
    now_unix_ms: i64,
) -> Result<(usize, BTreeMap<String, usize>), AgentError> {
    let client = PlatformClient::new(transport, Some(&enrollment.identity))?;
    client.heartbeat(&Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: enrollment.agent_id.clone(),
        scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
        hostname: openvibes_collectors::hostname(),
        observed_at_unix_ms: now_unix_ms,
        capabilities: Vec::new(),
    })?;
    let mut rejected = BTreeMap::new();
    let delivered = queue
        .deliver(now_unix_ms, |batch| {
            client.deliver(batch).inspect(|ack| {
                for refused in &ack.rejected_findings {
                    *rejected
                        .entry(refused.reason.as_str().to_owned())
                        .or_insert(0) += 1;
                }
            })
        })
        .map_err(|error| match error {
            DeliveryError::Transport(error) => AgentError::Transport(error),
            DeliveryError::InvalidAcknowledgement => {
                AgentError::Transport(TransportError::InvalidResponse)
            }
            DeliveryError::Queue(error) => AgentError::Storage(error),
        })?;
    Ok((delivered, rejected))
}

/// Validates and durably writes one export document, refusing to replace
/// any existing file or link at `path`. On Unix it is readable by the owner
/// only.
// ponytail: a batch of 500 maximum-size findings exceeds the 1 MiB document
// limit and is refused, here and in online delivery alike; size batches by
// bytes if real findings get that large.
fn write_export(path: &Path, document: &(impl Serialize + Validate)) -> Result<(), AgentError> {
    let limits = ResourceLimits::V1;
    let failed = |failure| AgentError::Export(failure);
    document
        .validate(limits)
        .map_err(|_| failed(ExportFailure::Invalid))?;
    let body = serde_json::to_vec(document).map_err(|_| failed(ExportFailure::Invalid))?;
    if body.len() > limits.document_bytes {
        return Err(failed(ExportFailure::TooLarge));
    }
    let write = || -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path)?;
        file.write_all(&body)?;
        file.sync_all()?;
        // Persist the new directory entry too, before findings leave the queue.
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    write().map_err(|error| {
        failed(match error.kind() {
            io::ErrorKind::NotFound => ExportFailure::NoDirectory,
            io::ErrorKind::AlreadyExists => ExportFailure::Exists,
            io::ErrorKind::PermissionDenied => ExportFailure::PermissionDenied,
            _ => ExportFailure::Io,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{AgentError, ExportFailure, inventory_outcome};

    #[test]
    fn an_oversized_inventory_is_skipped_not_fatal() {
        let skipped = inventory_outcome(Err(AgentError::Export(ExportFailure::TooLarge)))
            .expect("findings are still exported");
        let reason = skipped.expect_err("no inventory file");
        assert!(reason.message.contains("1 MiB"), "{}", reason.message);
        assert_eq!(inventory_outcome(Ok(3)), Ok(Ok(3)));
        // Any other write failure (for example a missing directory) still
        // stops the export: the findings could not be written either.
        assert_eq!(
            inventory_outcome(Err(AgentError::Export(ExportFailure::NoDirectory))),
            Err(AgentError::Export(ExportFailure::NoDirectory))
        );
    }
}
