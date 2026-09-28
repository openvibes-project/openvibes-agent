//! Finding changes (protocol P13): the agent's current rule matches, what
//! the platform acknowledged, and the next `FindingChanges` between them.

use std::collections::{BTreeMap, BTreeSet};

use openvibes_core::{
    EndedMatch, Finding, FindingChanges, Identifier, MAX_CHANGE_ENTRIES, MAX_MATCHES,
    MAX_TRANSIENT, SchemaVersion, TransientMatch, hex, match_digest, materially_differs,
};
use serde::{Deserialize, Serialize};

/// Serialized findings the current set may hold, so that with the
/// transients and the envelope a document fits 8 MiB (P13).
const MATCH_BYTES: usize = 6 * 1024 * 1024;
/// Serialized findings the transients may hold.
const TRANSIENT_BYTES: usize = 3 * 512 * 1024;

/// (rule set, rule).
type Key = (String, String);

fn key(finding: &Finding) -> Key {
    (
        finding
            .rule_set_id
            .as_ref()
            .map_or_else(String::new, |set| set.as_str().to_owned()),
        finding.rule_id.as_str().to_owned(),
    )
}

fn size(finding: &Finding) -> usize {
    serde_json::to_vec(finding).map_or(usize::MAX, |bytes| bytes.len())
}

/// One rule's outcome, as the match state needs it.
#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    /// The rule matched.
    Match(Finding),
    /// The rule was evaluated and did not match: its match ends.
    NoMatch,
    /// The rule could not be evaluated (unavailable facts, a failure): its
    /// match, if any, stays open.
    Kept,
}

/// One scan's rule outcomes, as `scan` hands them over.
pub(crate) struct EvaluatedScan {
    /// When the scan ran.
    pub scanned_at_unix_ms: i64,
    /// Every configured rule set.
    pub configured: BTreeSet<Identifier>,
    /// Rule sets evaluated without error, with every rule's outcome.
    pub evaluated: Vec<(Identifier, Vec<(Identifier, Outcome)>)>,
}

/// Current and acknowledged matches, kept in the state directory.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct MatchState {
    /// The current set; each finding keeps the time its match started.
    current: Vec<Finding>,
    /// The set the platform acknowledged and its digest (`None`: nothing
    /// acknowledged yet, so the next document is a replace).
    acked: Vec<Finding>,
    acked_sha256: Option<String>,
    /// When each acknowledged match that left the current set ended.
    ended_at: Vec<(Key, i64)>,
    transient: Vec<TransientMatch>,
    transient_dropped: u64,
    /// New matches the last scan left out (`matches_truncated`).
    truncated: u64,
    /// A 409 asked for the whole set.
    replace: bool,
    /// When the last observed scan ran; 0 before the first.
    scanned_at_unix_ms: i64,
}

impl MatchState {
    /// Applies one scan. A match ends only on `NoMatch`, a rule gone from
    /// its evaluated set, or its set no longer configured; an acknowledged
    /// match always keeps its place, a new one past the bounds is left out.
    pub(crate) fn observe(&mut self, scan: &EvaluatedScan) {
        self.scanned_at_unix_ms = scan.scanned_at_unix_ms;
        self.truncated = 0;
        let acked: BTreeSet<Key> = self.acked.iter().map(key).collect();
        let mut current: BTreeMap<Key, Finding> =
            self.current.drain(..).map(|f| (key(&f), f)).collect();
        let mut gone: Vec<Finding> = Vec::new();
        let configured: BTreeSet<&str> = scan.configured.iter().map(Identifier::as_str).collect();
        let unconfigured: Vec<Key> = current
            .keys()
            .filter(|(set, _)| !configured.contains(set.as_str()))
            .cloned()
            .collect();
        for k in unconfigured {
            gone.extend(current.remove(&k));
        }
        for (set, results) in &scan.evaluated {
            let present: BTreeSet<&str> = results.iter().map(|(rule, _)| rule.as_str()).collect();
            let removed: Vec<Key> = current
                .keys()
                .filter(|(s, r)| s == set.as_str() && !present.contains(r.as_str()))
                .cloned()
                .collect();
            for k in removed {
                gone.extend(current.remove(&k));
            }
            for (rule, outcome) in results {
                let k = (set.as_str().to_owned(), rule.as_str().to_owned());
                match outcome {
                    Outcome::Match(finding) => {
                        if let Some(existing) = current.get_mut(&k) {
                            if materially_differs(existing, finding) {
                                let started = existing.observed_at_unix_ms;
                                *existing = finding.clone();
                                existing.observed_at_unix_ms = started;
                            }
                        } else {
                            let bytes: usize = current.values().map(size).sum();
                            let fits = current.len() < MAX_MATCHES
                                && bytes.saturating_add(size(finding)) <= MATCH_BYTES;
                            if fits || acked.contains(&k) {
                                current.insert(k, finding.clone());
                            } else {
                                self.truncated += 1;
                            }
                        }
                    }
                    Outcome::NoMatch => gone.extend(current.remove(&k)),
                    Outcome::Kept => {}
                }
            }
        }
        for finding in gone {
            let k = key(&finding);
            if acked.contains(&k) {
                self.ended_at.retain(|(e, _)| *e != k);
                self.ended_at.push((k, scan.scanned_at_unix_ms));
            } else {
                self.add_transient(finding, scan.scanned_at_unix_ms);
            }
        }
        self.current = current.into_values().collect();
    }

    fn add_transient(&mut self, finding: Finding, ended_at_unix_ms: i64) {
        let bytes: usize = self.transient.iter().map(|t| size(&t.finding)).sum();
        if self.transient.len() < MAX_TRANSIENT
            && bytes.saturating_add(size(&finding)) <= TRANSIENT_BYTES
        {
            self.transient.push(TransientMatch {
                finding,
                ended_at_unix_ms,
            });
        } else {
            self.transient_dropped += 1;
        }
    }

    /// The next document, or `None` when the platform already has it all
    /// (or before the first scan).
    pub(crate) fn changes(&self, agent_id: &Identifier) -> Option<FindingChanges> {
        if self.scanned_at_unix_ms == 0 {
            return None;
        }
        let mut doc = FindingChanges {
            schema_version: SchemaVersion::V1,
            agent_id: agent_id.clone(),
            base_sha256: self
                .acked_sha256
                .clone()
                .unwrap_or_else(|| hex(&match_digest(&[]))),
            sha256: hex(&match_digest(&self.current)),
            replace: false,
            scanned_at_unix_ms: self.scanned_at_unix_ms,
            started: Vec::new(),
            changed: Vec::new(),
            ended: Vec::new(),
            transient: self.transient.clone(),
            transient_dropped: self.transient_dropped,
        };
        let whole = |mut doc: FindingChanges| {
            doc.replace = true;
            doc.started = self.current.clone();
            doc.changed.clear();
            doc.ended.clear();
            Some(doc)
        };
        if self.acked_sha256.is_none() || self.replace {
            return whole(doc);
        }
        let acked: BTreeMap<Key, &Finding> = self.acked.iter().map(|f| (key(f), f)).collect();
        let current: BTreeMap<Key, &Finding> = self.current.iter().map(|f| (key(f), f)).collect();
        for (k, finding) in &current {
            match acked.get(k) {
                None => doc.started.push((*finding).clone()),
                Some(old) if materially_differs(old, finding) => {
                    doc.changed.push((*finding).clone());
                }
                Some(_) => {}
            }
        }
        for (k, old) in &acked {
            if !current.contains_key(k) {
                let at = self
                    .ended_at
                    .iter()
                    .find(|(e, _)| e == k)
                    .map_or(self.scanned_at_unix_ms, |(_, at)| *at);
                doc.ended.push(EndedMatch {
                    rule_set_id: old.rule_set_id.clone()?,
                    rule_id: old.rule_id.clone(),
                    ended_at_unix_ms: at,
                });
            }
        }
        if doc.started.len() + doc.changed.len() + doc.ended.len() > MAX_CHANGE_ENTRIES {
            return whole(doc);
        }
        let nothing = doc.started.is_empty()
            && doc.changed.is_empty()
            && doc.ended.is_empty()
            && doc.transient.is_empty()
            && doc.transient_dropped == 0;
        (!nothing).then_some(doc)
    }

    /// The platform stored `sent` (a 2xx): it now holds exactly the set
    /// `sent` describes.
    pub(crate) fn acknowledged(&mut self, sent: &FindingChanges) {
        let mut acked: BTreeMap<Key, Finding> = if sent.replace {
            BTreeMap::new()
        } else {
            self.acked.drain(..).map(|f| (key(&f), f)).collect()
        };
        for finding in sent.started.iter().chain(&sent.changed) {
            acked.insert(key(finding), finding.clone());
        }
        for ended in &sent.ended {
            acked.remove(&(
                ended.rule_set_id.as_str().to_owned(),
                ended.rule_id.as_str().to_owned(),
            ));
        }
        self.ended_at.retain(|(k, _)| acked.contains_key(k));
        self.acked = acked.into_values().collect();
        self.acked_sha256 = Some(sent.sha256.clone());
        let delivered = sent.transient.len().min(self.transient.len());
        self.transient.drain(..delivered);
        self.transient_dropped = self
            .transient_dropped
            .saturating_sub(sent.transient_dropped);
        self.replace = false;
    }

    /// A 409 `findings_resync`: the next document is a replace.
    pub(crate) fn request_replace(&mut self) {
        self.replace = true;
    }

    /// Whether the next document will be a replace.
    pub(crate) fn replace_pending(&self) -> bool {
        self.replace || self.acked_sha256.is_none()
    }

    /// The digest the platform acknowledged, for heartbeats.
    pub(crate) fn acked_sha256(&self) -> Option<&str> {
        self.acked_sha256.as_deref()
    }

    /// The current matches (per-scan fallback after a 404).
    pub(crate) fn current(&self) -> &[Finding] {
        &self.current
    }

    /// New matches the last scan left out.
    pub(crate) fn truncated(&self) -> u64 {
        self.truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvibes_core::{Confidence, SchemaVersion, Severity, hex, match_digest};

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    fn finding(rule: &str, version: u64, at: i64) -> Finding {
        Finding {
            schema_version: SchemaVersion::V1,
            finding_id: id(&format!("finding.{rule}.{at}")),
            scan_id: id(&format!("scan.{at}")),
            rule_set_id: Some(id("base")),
            rule_id: id(rule),
            rule_version: version,
            observed_at_unix_ms: at,
            severity: Severity::High,
            confidence: Confidence::new(100).unwrap(),
            message: format!("{rule} matched"),
            evidence: vec![id("port.tcp.exposed")],
        }
    }

    fn hit(rule: &str, version: u64, at: i64) -> (Identifier, Outcome) {
        (id(rule), Outcome::Match(finding(rule, version, at)))
    }

    fn miss(rule: &str) -> (Identifier, Outcome) {
        (id(rule), Outcome::NoMatch)
    }

    fn scan(at: i64, results: Vec<(Identifier, Outcome)>) -> EvaluatedScan {
        EvaluatedScan {
            scanned_at_unix_ms: at,
            configured: [id("base")].into(),
            evaluated: vec![(id("base"), results)],
        }
    }

    fn rules(list: &[Finding]) -> Vec<&str> {
        list.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn agent() -> Identifier {
        id("agent.1")
    }

    #[test]
    fn nothing_acknowledged_means_a_replace_even_when_empty() {
        let mut state = MatchState::default();
        assert_eq!(
            state.changes(&agent()),
            None,
            "nothing before the first scan"
        );
        state.observe(&scan(1, vec![miss("a")]));
        let changes = state.changes(&agent()).unwrap();
        assert!(changes.replace && changes.started.is_empty());
        assert_eq!(changes.sha256, hex(&match_digest(&[])));
    }

    #[test]
    fn started_changed_ended_then_nothing() {
        let mut state = MatchState::default();
        state.observe(&scan(1, vec![hit("a", 1, 1), hit("b", 1, 1)]));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        assert_eq!(state.acked_sha256(), Some(first.sha256.as_str()));
        state.observe(&scan(2, vec![hit("a", 1, 2), hit("b", 1, 2)]));
        assert_eq!(state.changes(&agent()), None, "nothing changed");
        state.observe(&scan(3, vec![hit("a", 2, 3), miss("b"), hit("c", 1, 3)]));
        let second = state.changes(&agent()).unwrap();
        assert!(!second.replace);
        assert_eq!(second.base_sha256, first.sha256);
        assert_eq!(rules(&second.started), ["c"]);
        assert_eq!(rules(&second.changed), ["a"]);
        assert_eq!(
            second.changed[0].observed_at_unix_ms, 1,
            "a changed match keeps its start"
        );
        assert_eq!(second.ended.len(), 1);
        assert_eq!(
            (
                second.ended[0].rule_id.as_str(),
                second.ended[0].ended_at_unix_ms
            ),
            ("b", 3)
        );
        state.acknowledged(&second);
        assert_eq!(state.changes(&agent()), None);
    }

    #[test]
    fn unavailable_failed_and_unevaluated_sets_keep_matches_open() {
        let mut state = MatchState::default();
        state.observe(&scan(1, vec![hit("a", 1, 1), hit("b", 1, 1)]));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        state.observe(&scan(
            2,
            vec![(id("a"), Outcome::Kept), (id("b"), Outcome::Kept)],
        ));
        assert_eq!(state.changes(&agent()), None);
        // The bundle expired: the set is configured but not evaluated.
        state.observe(&EvaluatedScan {
            scanned_at_unix_ms: 3,
            configured: [id("base")].into(),
            evaluated: vec![],
        });
        assert_eq!(state.changes(&agent()), None);
    }

    #[test]
    fn a_removed_rule_or_rule_set_ends_its_matches() {
        let mut state = MatchState::default();
        state.observe(&scan(1, vec![hit("a", 1, 1), hit("b", 1, 1)]));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        // A new bundle without rule b.
        state.observe(&scan(2, vec![hit("a", 1, 2)]));
        assert_eq!(
            state.changes(&agent()).unwrap().ended[0].rule_id.as_str(),
            "b"
        );
        // The rule set is no longer configured.
        state.observe(&EvaluatedScan {
            scanned_at_unix_ms: 3,
            configured: BTreeSet::new(),
            evaluated: vec![],
        });
        let changes = state.changes(&agent()).unwrap();
        assert_eq!(changes.ended.len(), 2);
        assert_eq!(changes.sha256, hex(&match_digest(&[])));
    }

    #[test]
    fn a_match_that_comes_back_before_acknowledgement_is_not_ended() {
        let mut state = MatchState::default();
        state.observe(&scan(1, vec![hit("a", 1, 1)]));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        state.observe(&scan(2, vec![miss("a")]));
        state.observe(&scan(3, vec![hit("a", 1, 3)]));
        assert_eq!(state.changes(&agent()), None);
    }

    #[test]
    fn transients_are_capped_and_counted() {
        let mut state = MatchState::default();
        state.observe(&scan(1, vec![]));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        let over = 3;
        for at in 2..(2 + i64::try_from(MAX_TRANSIENT).unwrap() + over) {
            let rule = format!("t{at}");
            state.observe(&scan(at, vec![hit(&rule, 1, at)]));
            state.observe(&scan(at, vec![miss(&rule)]));
        }
        let changes = state.changes(&agent()).unwrap();
        assert_eq!(changes.transient.len(), MAX_TRANSIENT);
        assert_eq!(changes.transient_dropped, 3);
        assert!(changes.started.is_empty() && changes.ended.is_empty());
        state.acknowledged(&changes);
        assert_eq!(
            state.changes(&agent()),
            None,
            "transients leave on acknowledgement"
        );
    }

    #[test]
    fn the_cap_never_displaces_an_acknowledged_match() {
        let mut state = MatchState::default();
        let many: Vec<(Identifier, Outcome)> = (0..MAX_MATCHES)
            .map(|n| hit(&format!("r{n:03}"), 1, 1))
            .collect();
        state.observe(&scan(1, many));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        let mut more: Vec<(Identifier, Outcome)> = (0..MAX_MATCHES)
            .map(|n| hit(&format!("r{n:03}"), 1, 2))
            .collect();
        more.push(hit("zz", 1, 2));
        state.observe(&scan(2, more));
        assert_eq!(state.changes(&agent()), None, "the new match is left out");
        assert_eq!(state.truncated(), 1);
    }

    #[test]
    fn more_than_500_entries_or_a_request_become_a_replace() {
        let mut state = MatchState::default();
        state.observe(&scan(
            1,
            (0..300).map(|n| hit(&format!("a{n:03}"), 1, 1)).collect(),
        ));
        let first = state.changes(&agent()).unwrap();
        state.acknowledged(&first);
        // 300 ended and 300 started: 600 entries.
        state.observe(&scan(
            2,
            (0..300).map(|n| hit(&format!("b{n:03}"), 1, 2)).collect(),
        ));
        let big = state.changes(&agent()).unwrap();
        assert!(big.replace && big.started.len() == 300 && big.ended.is_empty());
        state.acknowledged(&big);
        assert_eq!(state.changes(&agent()), None);
        state.request_replace();
        assert!(
            state.changes(&agent()).unwrap().replace,
            "a 409 asks for a replace"
        );
    }
}
