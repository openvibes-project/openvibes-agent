use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};

use openvibes_core::{
    DeliveryAcknowledgement, FindingExport, Heartbeat, Identifier, ResourceLimits, SchemaVersion,
    Validate,
};
use openvibes_storage::{DeliveryError, IdentityStore, SqliteQueue, install_id, prepare_state_dir};
use openvibes_transport::{PlatformClient, TransportConfig, TransportError};

use crate::{
    AgentConfig, AgentError, Enrollment, forget_if_revoked, load_or_enroll, read_enrollment_token,
    renew_if_due,
};

/// What one [`Service::tick`] accomplished.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickReport {
    /// The identity was rotated this tick.
    pub renewed: bool,
    /// A due renewal failed; the current, still valid identity was kept and
    /// renewal is retried next tick.
    pub renewal_error: Option<AgentError>,
    /// Findings the platform acknowledged this tick.
    pub delivered: usize,
}

/// The agent's durable state and the platform lifecycle driven over it.
pub struct Service {
    config: AgentConfig,
    install_id: Identifier,
    identities: IdentityStore,
    queue: SqliteQueue,
    enrollment: Option<Enrollment>,
}

impl Service {
    /// Prepares the state directory and opens the identity store and queue.
    /// An invalid platform URL, CA bundle, or proxy fails here, at startup.
    pub fn open(config: AgentConfig) -> Result<Self, AgentError> {
        if let Some(transport) = &config.transport {
            PlatformClient::new(transport, None)?;
        }
        prepare_state_dir(&config.state_dir)?;
        let limits = ResourceLimits::V1;
        Ok(Self {
            install_id: install_id(&config.state_dir.join("install.sqlite"))?,
            identities: IdentityStore::open(&config.state_dir.join("identity.sqlite"), limits)?,
            queue: SqliteQueue::open(&config.state_dir.join("queue.sqlite"), limits)?,
            config,
            enrollment: None,
        })
    }

    /// The durable finding queue; scans enqueue their findings here.
    pub fn queue(&mut self) -> &mut SqliteQueue {
        &mut self.queue
    }

    /// One pass of the platform lifecycle: load or enroll the identity, renew
    /// it if due, send a heartbeat, and deliver one batch of due findings.
    /// A local-only agent does nothing here and never uses the network.
    ///
    /// A failed renewal does not stop the tick while the current certificate
    /// is still usable. An explicit revocation deletes the identity and ends
    /// the tick; the next tick re-enrolls once a new token is supplied.
    pub fn tick(&mut self, now_unix_ms: i64) -> Result<TickReport, AgentError> {
        let Some(transport) = &self.config.transport else {
            return Ok(TickReport::default());
        };
        let mut enrollment = match self.enrollment.take() {
            Some(enrollment) => enrollment,
            None => {
                let token = match &self.config.enrollment_token_file {
                    Some(path) => read_enrollment_token(path)?,
                    None => None,
                };
                load_or_enroll(&mut self.identities, transport, token.as_ref(), now_unix_ms)?
            }
        };
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
        report.delivered = result?;
        Ok(report)
    }

    /// Writes every due queued finding to `dir` as `FindingExport` files of up
    /// to one delivery batch each, and returns how many were exported. Each
    /// file is flushed to disk before its findings leave the queue, and no
    /// existing file is overwritten. Only a local-only agent exports, so
    /// export never races platform delivery.
    ///
    // ponytail: rides the queue's delivery path, so findings still in backoff
    // from an earlier online configuration wait until due, and a failed write
    // backs its batch off. Add a queue export method if operators hit that.
    pub fn export(&mut self, dir: &Path, now_unix_ms: i64) -> Result<usize, AgentError> {
        if self.config.transport.is_some() {
            return Err(AgentError::NotLocalOnly);
        }
        let agent_id = self.identities.get()?.map(|stored| stored.agent_id);
        let hostname = openvibes_collectors::hostname();
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
                    })
                })
                .map_err(|error| match error {
                    DeliveryError::Transport(error) => error,
                    DeliveryError::InvalidAcknowledgement => AgentError::Export,
                    DeliveryError::Queue(error) => AgentError::Storage(error),
                })?;
            if written == 0 {
                break;
            }
            exported += written;
        }
        Ok(exported)
    }
}

/// Heartbeat, then one delivery batch, over mTLS.
fn exchange(
    queue: &mut SqliteQueue,
    transport: &TransportConfig,
    enrollment: &Enrollment,
    now_unix_ms: i64,
) -> Result<usize, AgentError> {
    let client = PlatformClient::new(transport, Some(&enrollment.identity))?;
    client.heartbeat(&Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: enrollment.agent_id.clone(),
        scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
        observed_at_unix_ms: now_unix_ms,
        capabilities: Vec::new(),
    })?;
    queue
        .deliver(now_unix_ms, |batch| client.deliver(batch))
        .map_err(|error| match error {
            DeliveryError::Transport(error) => AgentError::Transport(error),
            DeliveryError::InvalidAcknowledgement => {
                AgentError::Transport(TransportError::InvalidResponse)
            }
            DeliveryError::Queue(error) => AgentError::Storage(error),
        })
}

/// Validates and durably writes one export file, refusing to replace any
/// existing file or link at `path`. On Unix it is readable by the owner only.
// ponytail: a batch of 500 maximum-size findings exceeds the 1 MiB document
// limit and is refused, here and in online delivery alike; size batches by
// bytes if real findings get that large.
fn write_export(path: &Path, document: &FindingExport) -> Result<(), AgentError> {
    let limits = ResourceLimits::V1;
    document.validate(limits).map_err(|_| AgentError::Export)?;
    let body = serde_json::to_vec(document).map_err(|_| AgentError::Export)?;
    if body.len() > limits.document_bytes {
        return Err(AgentError::Export);
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
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    write().map_err(|_| AgentError::Export)
}
