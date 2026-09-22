use openvibes_core::{Heartbeat, ResourceLimits, SchemaVersion};
use openvibes_storage::{DeliveryError, IdentityStore, SqliteQueue, prepare_state_dir};
use openvibes_transport::{PlatformClient, TransportError};

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
    identities: IdentityStore,
    queue: SqliteQueue,
    enrollment: Option<Enrollment>,
}

impl Service {
    /// Prepares the state directory and opens the identity store and queue.
    /// An invalid platform URL, CA bundle, or proxy fails here, at startup.
    pub fn open(config: AgentConfig) -> Result<Self, AgentError> {
        PlatformClient::new(&config.transport, None)?;
        prepare_state_dir(&config.state_dir)?;
        let limits = ResourceLimits::V1;
        Ok(Self {
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
    ///
    /// A failed renewal does not stop the tick while the current certificate
    /// is still usable. An explicit revocation deletes the identity and ends
    /// the tick; the next tick re-enrolls once a new token is supplied.
    pub fn tick(&mut self, now_unix_ms: i64) -> Result<TickReport, AgentError> {
        let transport = &self.config.transport;
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

        let result = self.exchange(&enrollment, now_unix_ms);
        if let Err(AgentError::Transport(error)) = result
            && forget_if_revoked(&mut self.identities, error)?
        {
            return Err(AgentError::Transport(error));
        }
        self.enrollment = Some(enrollment);
        report.delivered = result?;
        Ok(report)
    }

    /// Heartbeat, then one delivery batch, over mTLS.
    fn exchange(&mut self, enrollment: &Enrollment, now_unix_ms: i64) -> Result<usize, AgentError> {
        let client = PlatformClient::new(&self.config.transport, Some(&enrollment.identity))?;
        client.heartbeat(&Heartbeat {
            schema_version: SchemaVersion::V1,
            agent_id: enrollment.agent_id.clone(),
            scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
            observed_at_unix_ms: now_unix_ms,
            capabilities: Vec::new(),
        })?;
        self.queue
            .deliver(now_unix_ms, |batch| client.deliver(batch))
            .map_err(|error| match error {
                DeliveryError::Transport(error) => AgentError::Transport(error),
                DeliveryError::InvalidAcknowledgement => {
                    AgentError::Transport(TransportError::InvalidResponse)
                }
                DeliveryError::Queue(error) => AgentError::Storage(error),
            })
    }
}
