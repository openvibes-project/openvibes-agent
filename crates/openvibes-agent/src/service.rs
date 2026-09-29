use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openvibes_core::{
    CollectorError, CollectorErrorCode, DeliveryAcknowledgement, FindingExport, Heartbeat,
    Identifier, InventoryExport, InventoryReport, ResourceLimits, SchemaVersion, Validate,
};
use openvibes_rules::RuleLoader;
use openvibes_storage::{
    DeliveryError, IdentityStore, RuleStore, SqliteQueue, StorageError, check_output_dir,
    install_id, prepare_state_dir,
};
use openvibes_transport::{PlatformClient, TransportConfig, TransportError};
use serde::Serialize;

use crate::{
    AgentConfig, AgentError, Enrollment, ExportFailure, ScanReport,
    clock::ClockGuard,
    forget_if_revoked,
    inventory::{
        InventoryBase, PendingInventory, changes_to_send, fingerprint, read_inventory_base,
    },
    load_or_enroll,
    matches::{EvaluatedScan, MatchState},
    read_enrollment_token, renew_if_due,
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
    /// The agent enrolled this tick, as this id (main logs it; the install
    /// script waits for that line).
    pub enrolled_as: Option<String>,
    /// The identity was rotated this tick.
    pub renewed: bool,
    /// A due renewal failed; the current, still valid identity was kept and
    /// renewal is retried next tick.
    pub renewal_error: Option<AgentError>,
    /// The wall clock jumped by this much (milliseconds, positive: forward)
    /// since the last scan or tick, beyond what the monotonic clock
    /// witnessed. Pruning and identity expiry ignore the jump.
    pub clock_jump_ms: Option<i64>,
    /// The heartbeat failed (other than by revocation); delivery went ahead.
    pub heartbeat_error: Option<AgentError>,
    /// Sending the changed inventory failed; it is retried next tick.
    pub inventory_error: Option<AgentError>,
    /// Sending finding changes failed or was refused (P13); retried after a
    /// backoff.
    pub matches_error: Option<AgentError>,
    /// The heartbeat was answered 409 `findings_resync` (P13): stored, and
    /// the platform asks for the whole match set.
    pub findings_resync: bool,
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
    recovered_queue: Option<PathBuf>,
    /// The last scan ran without the distribution service (not enrolled
    /// yet); the first enrollment makes a scan due at once.
    scanned_without_distribution: bool,
    clock: ClockGuard,
    pending_clock_jump: Option<i64>,
    /// The inventory collected at the last due scan (protocol P8).
    inventory: Option<PendingInventory>,
    /// SHA-256 (hex) of the last inventory the platform accepted, kept in
    /// the state directory across restarts.
    inventory_acked: Option<String>,
    /// Digest of an inventory the platform refused (or that is over the
    /// limits): not sent again until the inventory changes or the agent
    /// restarts (M1 limits review).
    inventory_refused: Option<String>,
    /// Retry pacing for an inventory that failed on the network or with a
    /// retryable status: (digest, next attempt in Unix ms, current delay).
    inventory_backoff: Option<(String, i64, i64)>,
    /// The last scan, for the health report (P12).
    last_scan: Option<openvibes_core::ScanHealth>,
    /// Each configured rule set's state after the last scan (P12).
    rule_sets: Vec<openvibes_core::RuleSetHealth>,
    /// Local storage failures since start (P12).
    storage_errors: u64,
    /// The last wall-clock jump seen and when (Unix ms), for an hour (P12).
    last_clock_jump: Option<(i64, i64)>,
    /// The last inventory the platform acknowledged (protocol P11), kept in
    /// the state directory; change sets are computed against it.
    inventory_base: Option<InventoryBase>,
    /// The platform answered 404 to the changes endpoint, or refused a gzip
    /// full report that it accepted uncompressed (a platform before P11):
    /// full reports until the agent restarts.
    changes_unsupported: bool,
    /// The platform refused a gzip body and accepted it uncompressed (before
    /// P11): full reports go uncompressed until the agent restarts.
    gzip_unsupported: bool,
    /// Rule matches for finding changes (protocol P13), kept in the state
    /// directory.
    matches: MatchState,
    /// The platform answered 404 to the finding changes endpoint (before
    /// P13): per-scan findings until the agent restarts.
    finding_changes_unsupported: bool,
    /// Retry pacing for finding changes: (next attempt in Unix ms, delay).
    matches_backoff: Option<(i64, i64)>,
}

/// File in the state directory holding the accepted inventory's digest.
const INVENTORY_ACK: &str = "inventory.sha256";
/// File in the state directory holding the accepted inventory (P11).
const INVENTORY_BASE: &str = "inventory-base.json";
/// File in the state directory holding the match state (P13).
const MATCHES: &str = "matches.json";
/// Largest match state file read: 500 findings, 100 transients and slack.
const MATCHES_BYTES: u64 = 16 * 1024 * 1024;
/// First wait before re-sending an inventory that failed to send.
const INVENTORY_RETRY_FIRST_MS: i64 = 60_000;
/// Longest wait between inventory send attempts.
const INVENTORY_RETRY_MAX_MS: i64 = 3_600_000;
/// Largest digest file read: 64 hex characters and some whitespace.
const INVENTORY_ACK_BYTES: u64 = 128;

impl Service {
    /// Prepares the state directory and opens the identity store and queue.
    /// An invalid platform URL, CA bundle, or proxy fails here, at startup.
    pub fn open(config: AgentConfig) -> Result<Self, AgentError> {
        for transport in config.transport.iter().chain(&config.distribution) {
            PlatformClient::new(transport, None)?;
        }
        prepare_state_dir(&config.state_dir)?;
        let limits = ResourceLimits::V1;
        let (queue, recovered_queue) = open_queue(&config.state_dir, limits)?;
        let inventory_acked = read_inventory_ack(&config.state_dir.join(INVENTORY_ACK));
        let inventory_base = read_inventory_base(
            &config.state_dir.join(INVENTORY_BASE),
            inventory_acked.as_deref(),
        );
        let matches = read_matches(&config.state_dir.join(MATCHES));
        Ok(Self {
            install_id: install_id(&config.state_dir.join("install.sqlite"))?,
            identities: IdentityStore::open(&config.state_dir.join("identity.sqlite"), limits)?,
            queue,
            rules: RuleStore::open(&config.state_dir.join("rules.sqlite"), limits)?,
            loader: RuleLoader::new(config.scan.trusted_keys.clone(), limits)
                .map_err(|_| AgentError::Config)?,
            last_scan_unix_ms: None,
            config,
            enrollment: None,
            recovered_queue,
            scanned_without_distribution: false,
            clock: ClockGuard::default(),
            pending_clock_jump: None,
            inventory: None,
            inventory_acked,
            inventory_refused: None,
            inventory_backoff: None,
            last_scan: None,
            rule_sets: Vec::new(),
            storage_errors: 0,
            last_clock_jump: None,
            inventory_base,
            changes_unsupported: false,
            gzip_unsupported: false,
            matches,
            finding_changes_unsupported: false,
            matches_backoff: None,
        })
    }

    /// Records a clock jump for the next tick report and keeps the queue's
    /// pruning on witnessed time.
    fn observe_clock(&mut self, now_unix_ms: i64) {
        if let Some(jump) = self.clock.observe(now_unix_ms, Instant::now()) {
            self.pending_clock_jump = Some(jump);
            self.last_clock_jump = Some((jump, now_unix_ms));
        }
        self.queue.set_clock_skew(self.clock.skew_ms());
    }

    /// Where a corrupt queue was moved at startup (ADR-0003); a fresh queue
    /// replaced it and its findings are lost. `None` when the queue was fine.
    #[must_use]
    pub fn recovered_queue(&self) -> Option<&Path> {
        self.recovered_queue.as_deref()
    }

    /// The validated configuration this service runs with.
    #[must_use]
    pub fn config(&self) -> &AgentConfig {
        &self.config
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
        self.observe_clock(now_unix_ms);
        let scan = &self.config.scan;
        let due = self.last_scan_unix_ms.is_none_or(|last| {
            now_unix_ms < last || now_unix_ms.saturating_sub(last) >= scan.interval_ms
        });
        if !due {
            return Ok(None);
        }
        self.refresh_inventory(now_unix_ms);
        let scan = &self.config.scan;
        if scan.rule_sets.is_empty() {
            self.last_scan_unix_ms = Some(now_unix_ms);
            // Every rule set was removed: their matches end (P13). An agent
            // that never had matches keeps sending nothing.
            if self.changes_mode() && !self.matches.current().is_empty() {
                self.matches.observe(&EvaluatedScan {
                    scanned_at_unix_ms: now_unix_ms,
                    configured: std::collections::BTreeSet::new(),
                    evaluated: Vec::new(),
                });
                self.save_matches();
            }
            return Ok(None);
        }
        self.last_scan_unix_ms = Some(now_unix_ms);
        // A damaged identity must not stop file-provisioned rule sets: the
        // failure is reported for each rule set and the scan goes ahead.
        let (client, client_error) = match self.distribution_client(now_unix_ms) {
            Ok(client) => (client, None),
            Err(error) => (None, Some(error)),
        };
        self.scanned_without_distribution = self.config.distribution.is_some() && client.is_none();
        let per_scan = !self.changes_mode();
        let report = crate::scan::scan(
            &self.config.scan,
            client.as_ref(),
            &self.loader,
            &mut self.rules,
            per_scan.then_some(&mut self.queue),
            &self.install_id,
            now_unix_ms,
        );
        if matches!(report, Err(AgentError::Storage(_))) {
            self.storage_errors += 1;
        }
        let mut report = report?;
        self.last_scan = Some(openvibes_core::ScanHealth {
            finished_at_unix_ms: now_unix_ms,
            interval_s: (self.config.scan.interval_ms / 1000).max(0).unsigned_abs(),
            rules_evaluated: report.rules_evaluated as u64,
            rules_unavailable: report.unavailable_rules as u64,
            rules_failed: report.failed_rules as u64,
            collectors: report
                .collectors
                .iter()
                .filter_map(|(name, outcome)| Some((Identifier::new(name).ok()?, *outcome)))
                .collect(),
        });
        self.rule_sets = report.rule_sets.clone();
        if self.changes_mode() {
            self.matches.observe(&EvaluatedScan {
                scanned_at_unix_ms: now_unix_ms,
                configured: self
                    .config
                    .scan
                    .rule_sets
                    .iter()
                    .map(|set| set.id.clone())
                    .collect(),
                evaluated: std::mem::take(&mut report.evaluated),
            });
            self.save_matches();
        }
        if let Some(error) = client_error {
            report.rule_set_errors.extend(
                self.config
                    .scan
                    .rule_sets
                    .iter()
                    .filter(|set| set.bundle_file.is_none())
                    .map(|set| (set.id.clone(), error)),
            );
        }
        let revoked = report
            .rule_set_errors
            .iter()
            .any(|(_, error)| *error == AgentError::Transport(TransportError::IdentityRevoked));
        if revoked && forget_if_revoked(&mut self.identities, TransportError::IdentityRevoked)? {
            self.enrollment = None;
        }
        Ok(Some(report))
    }

    /// Collects the operating system and packages for the next inventory
    /// report (protocol P8), only with a platform and the packages
    /// collector. A failed collection keeps the previous inventory.
    // ponytail: the packages are read here and again by the rule scan in the
    // same pass (a few tens of ms per interval); share one read if scans
    // ever run far more often.
    fn refresh_inventory(&mut self, now_unix_ms: i64) {
        if self.config.transport.is_none() || !self.config.scan.collectors.packages {
            return;
        }
        let Some(os) = openvibes_collectors::os_release() else {
            self.inventory = None;
            return;
        };
        let limits = ResourceLimits::V1;
        let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
        let Ok(mut packages) = openvibes_collectors::collect_packages(deadline, limits) else {
            return;
        };
        packages.sort_by_cached_key(|package| serde_json::to_string(package).unwrap_or_default());
        // The kernel is part of the fingerprint, so a reboot into another one
        // is reported (protocol P9); the fingerprint is the contract's (P11).
        let running_kernel = openvibes_collectors::running_kernel();
        let digest = fingerprint(&os, running_kernel.as_deref(), &packages);
        self.inventory = Some(PendingInventory {
            os,
            running_kernel,
            packages,
            collected_at_unix_ms: now_unix_ms,
            sha256: digest,
        });
    }

    /// Finding changes (P13) apply with a platform, until it answers 404.
    fn changes_mode(&self) -> bool {
        self.config.transport.is_some() && !self.finding_changes_unsupported
    }

    /// Writes the match state; a failure is counted, and costs at most a
    /// replace after a restart.
    fn save_matches(&mut self) {
        let written = serde_json::to_vec(&self.matches)
            .map_err(io::Error::other)
            .and_then(|bytes| write_private(&self.config.state_dir.join(MATCHES), &bytes));
        if written.is_err() {
            self.storage_errors += 1;
        }
    }

    /// Sends the next finding changes, if any (protocol P13): a replace
    /// after a 409 on a diff; a backoff after any other refusal or failure;
    /// per-scan findings after a 404.
    fn report_matches(
        &mut self,
        transport: &TransportConfig,
        enrollment: &Enrollment,
        now_unix_ms: i64,
    ) -> Option<AgentError> {
        if !self.changes_mode()
            || self
                .matches_backoff
                .is_some_and(|(next, _)| now_unix_ms < next)
        {
            return None;
        }
        let client = match PlatformClient::new(transport, Some(&enrollment.identity)) {
            Ok(client) => client,
            Err(error) => return Some(AgentError::Transport(error)),
        };
        // At most two attempts: a diff, then the replace a 409 asks for.
        for _ in 0..2 {
            let changes = self.matches.changes(&enrollment.agent_id)?;
            match client.report_finding_changes(&changes) {
                Ok(()) => {
                    self.matches.acknowledged(&changes);
                    self.matches_backoff = None;
                    self.save_matches();
                    return None;
                }
                Err(TransportError::NotFound) => {
                    self.finding_changes_unsupported = true;
                    for finding in self.matches.current() {
                        if matches!(self.queue.enqueue(finding, now_unix_ms), Err(error) if error != StorageError::Full)
                        {
                            self.storage_errors += 1;
                        }
                    }
                    return None;
                }
                Err(TransportError::FindingsResync) if !changes.replace => {
                    self.matches.request_replace();
                }
                Err(error) => {
                    // 1, 2, 4 … minutes, up to an hour.
                    let delay = self
                        .matches_backoff
                        .map_or(INVENTORY_RETRY_FIRST_MS, |(_, delay)| {
                            (delay * 2).min(INVENTORY_RETRY_MAX_MS)
                        });
                    self.matches_backoff = Some((now_unix_ms + delay, delay));
                    return Some(AgentError::Transport(error));
                }
            }
        }
        None
    }

    /// Sends the pending inventory if the platform does not have it yet; on
    /// success records its digest in the state directory.
    fn report_inventory(
        &mut self,
        transport: &TransportConfig,
        enrollment: &Enrollment,
        now_unix_ms: i64,
    ) -> Option<AgentError> {
        let pending = self.inventory.as_ref()?;
        if self.inventory_acked.as_deref() == Some(pending.sha256.as_str())
            || self.inventory_refused.as_deref() == Some(pending.sha256.as_str())
        {
            return None;
        }
        // An unstable link or a busy platform: wait before re-uploading the
        // same inventory; a changed inventory is sent at once.
        if let Some((digest, next, _)) = &self.inventory_backoff
            && *digest == pending.sha256
            && now_unix_ms < *next
        {
            return None;
        }
        let report = InventoryReport {
            schema_version: SchemaVersion::V1,
            agent_id: enrollment.agent_id.clone(),
            os: pending.os.clone(),
            running_kernel: pending.running_kernel.clone(),
            collected_at_unix_ms: pending.collected_at_unix_ms,
            packages: pending.packages.clone(),
        };
        let digest = pending.sha256.clone();
        let changes = changes_to_send(
            self.changes_unsupported,
            self.inventory_base.as_ref(),
            self.inventory_acked.as_deref(),
            pending,
            &report,
        );
        let mut unsupported = false;
        let mut plain = self.gzip_unsupported;
        let full = |client: &PlatformClient, plain: &mut bool| {
            if *plain {
                return client.report_inventory_uncompressed(&report);
            }
            match client.report_inventory(&report) {
                // A platform before P11 reads the body as plain JSON, so a
                // gzip body is a 400 there: send it again uncompressed.
                Err(TransportError::Rejected) => {
                    let sent = client.report_inventory_uncompressed(&report);
                    *plain = sent.is_ok();
                    sent
                }
                other => other,
            }
        };
        let sent = PlatformClient::new(transport, Some(&enrollment.identity)).and_then(|client| {
            match changes {
                Some(changes) => match client.report_inventory_changes(&changes) {
                    // A platform before P11.
                    Err(TransportError::NotFound) => {
                        unsupported = true;
                        full(&client, &mut plain)
                    }
                    // The platform holds something else (409), or refused the
                    // change set (a 400, a proxy's 413): the full list, so its
                    // inventory is not stale until the next change.
                    Err(TransportError::InventoryResync | TransportError::Rejected) => {
                        full(&client, &mut plain)
                    }
                    other => other,
                },
                None => full(&client, &mut plain),
            }
        });
        self.changes_unsupported |= unsupported || plain;
        self.gzip_unsupported = plain;
        match sent {
            Ok(()) => {
                // The base first, then its digest: a crash between the two
                // leaves a base that no longer matches, so a full report.
                // ponytail: a failed write only means one full report later.
                let base = InventoryBase::from(pending);
                if let Ok(bytes) = serde_json::to_vec(&base) {
                    let _ = write_private(&self.config.state_dir.join(INVENTORY_BASE), &bytes);
                }
                let _ = write_private(
                    &self.config.state_dir.join(INVENTORY_ACK),
                    digest.as_bytes(),
                );
                self.inventory_base = Some(base);
                self.inventory_acked = Some(digest);
                self.inventory_backoff = None;
                None
            }
            // Refused, or over the limits locally: the same inventory will be
            // refused again, so report it once and wait for a change.
            Err(error @ (TransportError::Rejected | TransportError::InvalidRequest)) => {
                self.inventory_refused = Some(digest);
                self.inventory_backoff = None;
                Some(AgentError::Transport(error))
            }
            Err(error) => {
                // 1, 2, 4 … minutes, up to an hour, per inventory.
                let delay = match &self.inventory_backoff {
                    Some((previous, _, delay)) if *previous == digest => {
                        (delay * 2).min(INVENTORY_RETRY_MAX_MS)
                    }
                    _ => INVENTORY_RETRY_FIRST_MS,
                };
                self.inventory_backoff = Some((digest, now_unix_ms + delay, delay));
                Some(AgentError::Transport(error))
            }
        }
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
        self.observe_clock(now_unix_ms);
        let Some(transport) = &self.config.transport else {
            return Ok(TickReport::default());
        };
        let token_file = self.config.enrollment_token_file.as_deref();
        let token = || match token_file {
            Some(path) => read_enrollment_token(path),
            None => Ok(None),
        };
        let mut enrolled_now = self.enrollment.is_none() && self.identities.get()?.is_none();
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
        // By witnessed time: a forward clock jump must not throw the
        // identity away.
        if now_unix_ms.saturating_sub(self.clock.skew_ms()) >= enrollment.expires_at_unix_ms {
            self.identities.clear()?;
            enrolled_now = true;
            enrollment = load_or_enroll(
                &mut self.identities,
                transport,
                token()?.as_ref(),
                now_unix_ms,
            )?;
        }
        if enrolled_now {
            // A new identity: the platform holds nothing for it (P13).
            self.matches.request_replace();
        }
        let mut report = TickReport {
            clock_jump_ms: self.pending_clock_jump.take(),
            enrolled_as: enrolled_now.then(|| enrollment.agent_id.as_str().to_owned()),
            ..TickReport::default()
        };
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

        let mut capabilities = self.config.scan.collectors.capabilities();
        if self.inventory.is_some() {
            capabilities.push("inventory.packages");
        }
        let health = match self.queue.stats() {
            Ok(stats) => crate::health::assemble(
                &stats,
                ResourceLimits::V1.queue_bytes,
                self.last_scan.as_ref(),
                &self.rule_sets,
                self.storage_errors,
                self.last_clock_jump,
                now_unix_ms,
            )
            .map(|mut health| {
                health.matches_truncated = self.changes_mode().then(|| self.matches.truncated());
                health
            }),
            Err(_) => {
                self.storage_errors += 1;
                None
            }
        };
        // Before the heartbeat and delivery: a 404 moves the current matches
        // into the queue, delivered in this same tick.
        let transport_config = transport.clone();
        report.matches_error = self.report_matches(&transport_config, &enrollment, now_unix_ms);
        let match_sha256 = self
            .changes_mode()
            .then(|| {
                self.matches
                    .heartbeat_sha256(&enrollment.agent_id)
                    .map(str::to_owned)
            })
            .flatten();
        let heartbeat = Heartbeat {
            schema_version: SchemaVersion::V1,
            agent_id: enrollment.agent_id.clone(),
            scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
            hostname: openvibes_collectors::hostname(),
            observed_at_unix_ms: now_unix_ms,
            // Protocol P7: the enabled collectors (fixed, valid identifiers).
            capabilities: capabilities
                .iter()
                .filter_map(|name| Identifier::new(*name).ok())
                .collect(),
            health,
            match_sha256,
        };
        let result = exchange(
            &mut self.queue,
            &transport_config,
            &enrollment,
            &heartbeat,
            now_unix_ms,
            &mut report,
        );
        if report.findings_resync && self.matches_backoff.is_none() {
            self.matches.request_replace();
        }
        if matches!(result, Err(AgentError::Storage(_))) {
            self.storage_errors += 1;
        }
        if let Err(AgentError::Transport(error)) = result
            && forget_if_revoked(&mut self.identities, error)?
        {
            return Err(AgentError::Transport(error));
        }
        report.inventory_error = self.report_inventory(&transport_config, &enrollment, now_unix_ms);
        self.enrollment = Some(enrollment);
        if self.scanned_without_distribution {
            // Now enrolled: fetch distribution-only rule sets at the next
            // scan instead of a whole interval later.
            self.scanned_without_distribution = false;
            self.last_scan_unix_ms = None;
        }
        result?;
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
        check_output_dir(dir).map_err(|error| {
            AgentError::Export(match error {
                StorageError::InsecurePath => ExportFailure::Insecure,
                _ => ExportFailure::NoDirectory,
            })
        })?;
        let agent_id = self.identities.get()?.map(|stored| stored.agent_id);
        let hostname = openvibes_collectors::hostname();
        let limits = ResourceLimits::V1;
        let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
        let collected = if self.config.scan.collectors.packages {
            openvibes_collectors::collect_packages(deadline, limits)
        } else {
            Err(CollectorError {
                collector: Identifier::new("packages").map_err(|_| AgentError::Config)?,
                code: CollectorErrorCode::Unsupported,
                message:
                    "the packages collector is disabled in the configuration; no inventory written"
                        .into(),
                retryable: false,
            })
        };
        let packages = match collected {
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
                    os: openvibes_collectors::os_release(),
                    running_kernel: openvibes_collectors::running_kernel(),
                    scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
                    collected_at_unix_ms: now_unix_ms,
                    packages,
                };
                inventory_outcome(
                    write_export(&dir.join(name), &document, limits.inventory_document_bytes)
                        .map(|()| count),
                )?
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
                    write_export(&dir.join(&name), &document, limits.document_bytes)?;
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

/// Opens the queue; a corrupt one is moved aside inside the state directory
/// (with its journal) and replaced by a fresh queue, as ADR-0003 specifies.
/// Its findings are lost; the next scan regenerates current findings.
fn open_queue(
    state_dir: &Path,
    limits: ResourceLimits,
) -> Result<(SqliteQueue, Option<PathBuf>), AgentError> {
    let path = state_dir.join("queue.sqlite");
    match SqliteQueue::open(&path, limits) {
        Ok(queue) => Ok((queue, None)),
        Err(StorageError::Corrupt) => {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis());
            let moved = state_dir.join(format!("queue.sqlite.corrupt-{stamp}"));
            fs::rename(&path, &moved).map_err(|_| AgentError::Storage(StorageError::Corrupt))?;
            let journal = state_dir.join("queue.sqlite-journal");
            if journal.exists() {
                let _ = fs::rename(
                    &journal,
                    state_dir.join(format!("queue.sqlite-journal.corrupt-{stamp}")),
                );
            }
            Ok((SqliteQueue::open(&path, limits)?, Some(moved)))
        }
        Err(error) => Err(error.into()),
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
                message: "the inventory exceeds the inventory limits (50,000 packages, 8 MiB); not written".into(),
                retryable: false,
            }))
        }
        Err(error) => Err(error),
    }
}

/// Heartbeat, then one delivery batch, over mTLS. A failed heartbeat does not
/// hold up delivery.
fn exchange(
    queue: &mut SqliteQueue,
    transport: &TransportConfig,
    enrollment: &Enrollment,
    heartbeat: &Heartbeat,
    now_unix_ms: i64,
    report: &mut TickReport,
) -> Result<(), AgentError> {
    let client = PlatformClient::new(transport, Some(&enrollment.identity))?;
    let heartbeat = client.heartbeat(heartbeat);
    // A revocation ends the tick (the caller deletes the identity); any
    // other heartbeat failure is reported and delivery goes ahead.
    report.heartbeat_error = match heartbeat {
        Ok(()) => None,
        Err(TransportError::IdentityRevoked) => {
            return Err(AgentError::Transport(TransportError::IdentityRevoked));
        }
        // Stored; the platform asks for the whole match set (P13).
        Err(TransportError::FindingsResync) => {
            report.findings_resync = true;
            None
        }
        Err(error) => Some(AgentError::Transport(error)),
    };
    let rejected = &mut report.rejected;
    report.delivered = queue
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
    Ok(())
}

/// Validates and durably writes one export document, refusing to replace
/// any existing file or link at `path`. On Unix it is readable by the owner
/// only.
fn write_export(
    path: &Path,
    document: &(impl Serialize + Validate),
    max_bytes: usize,
) -> Result<(), AgentError> {
    let limits = ResourceLimits::V1;
    let failed = |failure| AgentError::Export(failure);
    document
        .validate(limits)
        .map_err(|_| failed(ExportFailure::Invalid))?;
    let body = serde_json::to_vec(document).map_err(|_| failed(ExportFailure::Invalid))?;
    if body.len() > max_bytes {
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

/// The accepted inventory digest, if the file holds one. Read bounded: a
/// digest is 64 hex characters.
/// The stored match state; missing, oversized or unreadable means none
/// acknowledged, so the next finding changes are a replace.
fn read_matches(path: &Path) -> MatchState {
    let mut bytes = Vec::new();
    let read =
        fs::File::open(path).and_then(|file| file.take(MATCHES_BYTES + 1).read_to_end(&mut bytes));
    if read.is_err() || u64::try_from(bytes.len()).map_or(true, |len| len > MATCHES_BYTES) {
        return MatchState::default();
    }
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn read_inventory_ack(path: &Path) -> Option<String> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(INVENTORY_ACK_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    let digest = text.trim();
    (u64::try_from(text.len()).ok()? <= INVENTORY_ACK_BYTES
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| digest.to_owned())
}

/// Writes a small file readable only by the agent (0600 on Unix).
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::{AgentError, ExportFailure, inventory_outcome, read_inventory_ack};

    #[test]
    fn an_oversized_inventory_is_skipped_not_fatal() {
        let skipped = inventory_outcome(Err(AgentError::Export(ExportFailure::TooLarge)))
            .expect("findings are still exported");
        let reason = skipped.expect_err("no inventory file");
        assert!(reason.message.contains("8 MiB"), "{}", reason.message);
        assert_eq!(inventory_outcome(Ok(3)), Ok(Ok(3)));
        // Any other write failure (for example a missing directory) still
        // stops the export: the findings could not be written either.
        assert_eq!(
            inventory_outcome(Err(AgentError::Export(ExportFailure::NoDirectory))),
            Err(AgentError::Export(ExportFailure::NoDirectory))
        );
    }

    #[test]
    fn only_a_well_formed_inventory_digest_is_read() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/unit-tmp")
            .join(format!("inventory-ack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("inventory.sha256");
        let digest = "ab".repeat(32);
        std::fs::write(&path, format!("{digest}\n")).unwrap();
        assert_eq!(read_inventory_ack(&path), Some(digest));
        // Oversized, malformed, or missing: treated as never acknowledged,
        // so the inventory is simply sent again.
        for bad in ["ab".repeat(1_000_000), "zz".repeat(32), "ab".repeat(31)] {
            std::fs::write(&path, bad).unwrap();
            assert_eq!(read_inventory_ack(&path), None);
        }
        assert_eq!(read_inventory_ack(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
