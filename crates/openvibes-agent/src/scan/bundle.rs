//! Choosing the bundle a rule set runs this scan: candidates from the
//! distribution service and the provisioned file, the rollback floor, and
//! what a project set's 404, 410 or unreachable derived URL means (P20).

use std::collections::BTreeSet;

use openvibes_core::{Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion};
use openvibes_rules::{AcceptedVersion, LoadContext, LoadError, RuleLoader, VerifiedRuleSet};
use openvibes_storage::{RuleStore, StorageError, StoredRuleBundle};
use openvibes_transport::{PlatformClient, TransportError};

use crate::{
    AgentError, RuleSetConfig, RuleSetSource,
    config::read_bounded,
    project_sets::{Withdrawn, withdrawn},
};

/// Where one candidate envelope for a rule set came from this scan: `Ok(None)`
/// means the source had nothing (no file configured, or nothing newer).
type Candidate = Result<Option<Vec<u8>>, AgentError>;

/// This scan's candidates for `set`, each marked `true` when it is the
/// provisioned file: the distribution service's newer envelope, if a client
/// is given, then the provisioned file.
fn candidates(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    current_version: Option<u64>,
) -> Vec<(bool, Candidate)> {
    let mut candidates = Vec::new();
    if let Some(client) = client {
        let request = RuleBundleRequest {
            schema_version: SchemaVersion::V1,
            rule_set_id: set.id.clone(),
            current_version,
        };
        candidates.push((
            false,
            client
                .fetch_rule_bundle(&request)
                .map_err(AgentError::Transport),
        ));
    }
    if let Some(path) = &set.bundle_file {
        let limit = u64::try_from(ResourceLimits::V1.document_bytes).unwrap_or(u64::MAX);
        candidates.push((
            true,
            match read_bounded(path, limit, false) {
                Ok(Some(bytes)) => Ok(Some(bytes)),
                Ok(None) => Err(AgentError::Config),
                Err(error) => Err(error),
            },
        ));
    }
    candidates
}

/// A value with this scan's refusals.
type Refusals<T> = (T, Vec<AgentError>);

/// The bundle to evaluate for `set`, and why candidates were refused. Each
/// valid candidate is accepted into `store` and raises the floor for the next;
/// if none is accepted, the last accepted bundle is re-verified and used, so a
/// bad or rolled-back candidate never replaces good rules. A damaged store
/// record is an error, never first use. `Err` when a project set is not
/// offered (or, `derived`, not reachable before its first bundle) or not
/// assigned (P20), with this scan's refusals.
pub(super) fn current_bundle(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    derived: bool,
    loader: &RuleLoader,
    store: &mut RuleStore,
    gone: &BTreeSet<Identifier>,
    now_unix_ms: i64,
) -> Result<(Option<VerifiedRuleSet>, Vec<AgentError>), Refusals<Withdrawn>> {
    let stored = match store.get(&set.id) {
        Ok(stored) => stored,
        Err(error) => return Ok((None, vec![AgentError::Storage(error)])),
    };
    let mut floor = match &stored {
        Some(stored) => {
            match AcceptedVersion::restore(set.id.clone(), stored.version, stored.preimage_sha256) {
                Ok(floor) => Some(floor),
                Err(_) => return Ok((None, vec![AgentError::Storage(StorageError::Corrupt)])),
            }
        }
        None => None,
    };
    // Withdrawn (P20: the stored mark, or last answered 410 in this process
    // when nothing was stored): ask without current_version, so a platform holding
    // the same version answers 200 rather than 204; the floor still
    // applies to whatever comes back (the loader's and `accept`'s checks).
    // A set the configuration names now is never withdrawn.
    let was_withdrawn = match set.source {
        RuleSetSource::Configured => false,
        RuleSetSource::Project { .. } => match store.is_withdrawn(&set.id) {
            Ok(withdrawn) => withdrawn || gone.contains(&set.id),
            Err(error) => return Ok((None, vec![AgentError::Storage(error)])),
        },
    };
    // A derived URL before enrolling (no client yet): nothing to ask, so a
    // project set never stored is quiet as when unreachable (§3).
    if derived
        && client.is_none()
        && set.source != RuleSetSource::Configured
        && stored.is_none()
        && !was_withdrawn
    {
        return Err((Withdrawn::NotOffered, Vec::new()));
    }
    let mut errors = Vec::new();
    let mut accepted = None;
    let current_version = if was_withdrawn {
        None
    } else {
        floor.as_ref().map(AcceptedVersion::version)
    };
    for (from_file, candidate) in candidates(set, client, current_version) {
        let bytes = match candidate {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(AgentError::Transport(
                error @ (TransportError::NotFound | TransportError::NotAssigned),
            )) => {
                if let Some(withdrawn) =
                    withdrawn(set.source, error, stored.is_some(), was_withdrawn)
                {
                    return Err((withdrawn, errors));
                }
                // Refused like any other 4xx: the last accepted bundle
                // keeps running.
                errors.push(AgentError::Transport(TransportError::Rejected));
                continue;
            }
            // A derived URL nobody answers on (no distribution service, or
            // another port) is quiet until the set has a bundle (§3).
            Err(AgentError::Transport(
                TransportError::Connect | TransportError::Timeout | TransportError::Tls,
            )) if derived && stored.is_none() && !was_withdrawn => {
                return Err((Withdrawn::NotOffered, errors));
            }
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let context = LoadContext {
            expected_rule_set_id: &set.id,
            now_unix_ms,
            last_accepted: floor.as_ref(),
        };
        let bundle = match loader.load_json(&bytes, context) {
            Ok(bundle) => bundle,
            // With a distribution service, an older provisioned file is
            // expected once a newer bundle was fetched: not a rollback
            // attempt worth reporting on every scan.
            Err(LoadError::Rollback) if from_file && client.is_some() => continue,
            Err(error) => {
                errors.push(AgentError::Rules(error));
                continue;
            }
        };
        let version = bundle.accepted_version().clone();
        let record = StoredRuleBundle {
            version: version.version(),
            preimage_sha256: *version.preimage_sha256(),
            envelope: bytes,
        };
        match store.accept(&set.id, &record) {
            Ok(()) => {
                floor = Some(version);
                accepted = Some(bundle);
            }
            Err(error) => errors.push(AgentError::Storage(error)),
        }
    }
    // A withdrawn set never falls back to its stored bundle: it runs again
    // only once a fetched bundle is accepted, which clears the mark.
    if accepted.is_none() && was_withdrawn {
        return Err((Withdrawn::NotAssigned, errors));
    }
    if accepted.is_none() {
        let context = LoadContext {
            expected_rule_set_id: &set.id,
            now_unix_ms,
            last_accepted: floor.as_ref(),
        };
        accepted = stored.and_then(|stored| loader.load_json(&stored.envelope, context).ok());
    }
    Ok((accepted, errors))
}
