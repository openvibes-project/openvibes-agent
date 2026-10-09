use std::{time::Duration, time::Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_collectors::process_events::{ProcessStart, Seeded};
use openvibes_core::{
    ALARM_BYTES, Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleKind, RuleSet,
    SchemaVersion, Severity, SignedRuleEnvelope, Validate,
};
use openvibes_rules::{EvaluationClock, LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use sha2::{Digest, Sha256};

use super::engine::{Engine, RulePair};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

struct Clock(u64);
impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0)
    }
    fn unix_ms(&self) -> i64 {
        2_000
    }
}

/// One signed `process_event` rule (test-only key, as in the rules tests).
fn rules(expression: &str) -> Vec<RulePair> {
    rules_in("baseline-alarms", &[expression])
}

/// One signed rule set `set` with a rule per expression (the first is
/// `shell-from-web`, the rest `rule.N`).
/// The rules of `set`, compiled as the agent does: `baseline-alarms` is
/// unrestricted, any other test set restricted, so its rules carry the
/// required `programs` (the shell the tests start).
fn rules_in(set: &str, expressions: &[&str]) -> Vec<RulePair> {
    let programs = (set != "baseline-alarms").then(|| vec!["sh"]);
    let rules: Vec<(&str, Option<Vec<&str>>)> = expressions
        .iter()
        .map(|expression| (*expression, programs.clone()))
        .collect();
    let (pairs, accepted, refused, _) = compile_set(set, &rules);
    assert_eq!((accepted, refused), (expressions.len() as u64, 0));
    pairs
}

/// `rules` (expression, `programs`) signed as `set` and compiled through
/// [`super::compile`]: (pairs, accepted, refused, without a prefilter).
fn compile_set(set: &str, rules: &[(&str, Option<Vec<&str>>)]) -> (Vec<RulePair>, u64, u64, u64) {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: rules
            .iter()
            .enumerate()
            .map(|(n, (expression, programs))| Rule {
                id: if n == 0 {
                    id("shell-from-web")
                } else {
                    id(&format!("rule.{n}"))
                },
                version: 1,
                title: "Shell from a web server".into(),
                severity: Severity::High,
                confidence: Confidence::new(80).unwrap(),
                expression: (*expression).to_owned(),
                finding_message: "A web server started a shell".into(),
                kind: RuleKind::ProcessEvent,
                programs: programs
                    .as_ref()
                    .map(|names| names.iter().map(|name| (*name).to_owned()).collect()),
                attack: None,
            })
            .collect(),
    })
    .unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id(set),
        rule_set_version: 3,
        issuer_key_id: id("test.key"),
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 3_000,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload_encoding: PayloadEncoding::Json,
        payload,
        signature_base64url: String::new(),
    };
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(
        key.sign(&signing_preimage(&envelope, ResourceLimits::V1).unwrap())
            .to_bytes(),
    );
    let loader = RuleLoader::new(
        vec![TrustedRuleKey::new(id(set), id("test.key"), key.verifying_key().to_bytes()).unwrap()],
        ResourceLimits::V1,
    )
    .unwrap();
    let bundle = loader
        .load_json(
            &serde_json::to_vec(&envelope).unwrap(),
            LoadContext {
                expected_rule_set_id: &id(set),
                now_unix_ms: 2_000,
                last_accepted: None,
            },
        )
        .unwrap();
    super::compile(vec![bundle], |id| id.as_str() != "baseline-alarms")
}

const WEB_SHELL: &str = "event['parent.name'] == 'nginx' && event['process.name'] == 'sh'";
const MINUTE: i64 = 60_000;

fn start(pid: u32, ppid: u32, exe: &str, args: &[&str], at: i64) -> ProcessStart {
    ProcessStart {
        pid,
        ppid,
        uid: 33,
        euid: 33,
        exe: exe.as_bytes().to_vec(),
        exe_from_filename: false,
        args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        args_truncated: false,
        cwd: None,
        at_unix_ms: at,
        parent: None,
    }
}

struct Host {
    engine: Engine,
    rules: Vec<RulePair>,
    ids: u32,
}

impl Host {
    fn new(expression: &str) -> Self {
        let mut engine = Engine::default();
        let nginx = start(10, 1, "/usr/sbin/nginx", &["nginx"], 0);
        engine.on_start(&nginx, &[], &Clock(0), Instant::now(), none, || {
            Some(id("x"))
        });
        Self {
            engine,
            rules: rules(expression),
            ids: 0,
        }
    }

    fn run(&mut self, start: &ProcessStart) -> Vec<openvibes_core::Alarm> {
        let ids = &mut self.ids;
        self.engine
            .on_start(start, &self.rules, &Clock(0), Instant::now(), none, || {
                *ids += 1;
                Some(id(&format!("alarm.{ids:032x}")))
            })
    }
}

fn none(_: u32) -> Option<Seeded> {
    None
}

fn shell(pid: u32, script: &str, at: i64) -> ProcessStart {
    start(pid, 10, "/usr/bin/sh", &["sh", "-c", script], at)
}

#[test]
fn the_same_command_collapses_into_one_alarm() {
    let mut host = Host::new(WEB_SHELL);
    let t = 1_790_000_000_000;
    let a = host.run(&shell(20, "id", t));
    let b = host.run(&shell(21, "id", t + MINUTE));
    let c = host.run(&shell(22, "id", t + 2 * MINUTE));
    assert_eq!((a.len(), b.len(), c.len()), (1, 1, 1));
    assert_eq!(a[0].alarm_id, c[0].alarm_id);
    assert_eq!(c[0].count, 3);
    assert_eq!(c[0].first_seen_unix_ms, t);
    assert_eq!(c[0].last_seen_unix_ms, t + 2 * MINUTE);
    assert_eq!(c[0].rule_set_version, 3);
    assert_eq!(c[0].ancestors[0].exe, "/usr/sbin/nginx");
    assert!(c[0].validate(ResourceLimits::V1).is_ok());
}

#[test]
fn a_different_command_line_is_a_different_alarm() {
    let mut host = Host::new(WEB_SHELL);
    let t = 1_790_000_000_000;
    let a = host.run(&shell(20, "id", t));
    let b = host.run(&shell(21, "curl x | sh", t + 1));
    assert_ne!(a[0].alarm_id, b[0].alarm_id);
    assert_eq!(b[0].count, 1);
}

#[test]
fn a_repeat_after_the_window_is_a_new_alarm() {
    let mut host = Host::new(WEB_SHELL);
    let t = 1_790_000_000_000;
    let a = host.run(&shell(20, "id", t));
    let b = host.run(&shell(21, "id", t + 11 * MINUTE));
    assert_ne!(a[0].alarm_id, b[0].alarm_id);
    assert_eq!(b[0].count, 1);
}

#[test]
fn rules_match_unmasked_and_alarms_are_masked() {
    let mut host = Host::new("event['process.cmdline'].contains('-psecret')");
    let alarms = host.run(&start(
        30,
        10,
        "/usr/bin/mysql",
        &["mysql", "-uroot", "-psecret"],
        1_790_000_000_000,
    ));
    assert_eq!(alarms[0].process.args, ["mysql", "-uroot", "-p***"]);
}

#[test]
fn an_oversized_alarm_is_cut_farthest_ancestor_first() {
    let mut host = Host::new("event['process.name'] == 'sh'");
    // Five ancestors and the process, each with 4 KiB of control bytes
    // (six bytes each once escaped in JSON).
    let noisy = "\u{1}".repeat(4_000);
    for pid in 100..105 {
        let parent = if pid == 100 { 1 } else { pid - 1 };
        host.run(&start(pid, parent, "/usr/bin/bash", &[&noisy], 0));
    }
    let alarms = host.run(&start(
        105,
        104,
        "/usr/bin/sh",
        &[&noisy],
        1_790_000_000_000,
    ));
    let alarm = &alarms[0];
    assert!(serde_json::to_vec(alarm).unwrap().len() <= ALARM_BYTES);
    assert!(alarm.validate(ResourceLimits::V1).is_ok());
    assert_eq!(alarm.ancestors.len(), 5);
    assert!(alarm.ancestors[4].args.is_empty() && alarm.ancestors[4].truncated);
    assert!(!alarm.ancestors[0].args.is_empty());
}

#[test]
fn a_failing_rule_never_raises_and_is_counted() {
    let mut host = Host::new(WEB_SHELL);
    // A clock that jumps a minute on every read: past the deadline.
    struct Slow(std::cell::Cell<u64>);
    impl EvaluationClock for Slow {
        fn elapsed(&self) -> Duration {
            self.0.set(self.0.get() + 60_000);
            Duration::from_millis(self.0.get())
        }
        fn unix_ms(&self) -> i64 {
            2_000
        }
    }
    let alarms = host.engine.on_start(
        &shell(20, "id", 1_790_000_000_000),
        &host.rules,
        &Slow(std::cell::Cell::new(0)),
        Instant::now(),
        none,
        || Some(id("alarm.x")),
    );
    assert!(alarms.is_empty());
    assert_eq!(host.engine.failures, 1);
}

#[test]
fn a_missing_parent_is_unavailable_not_a_match() {
    let mut host = Host::new(WEB_SHELL);
    let alarms = host.run(&start(40, 999, "/usr/bin/sh", &["sh"], 1_790_000_000_000));
    assert!(alarms.is_empty());
    assert_eq!(host.engine.unavailable, 1);
}

#[test]
fn the_collapse_map_is_bounded() {
    use super::engine::COLLAPSE_ENTRIES;
    let mut host = Host::new(WEB_SHELL);
    let t = 1_790_000_000_000;
    let first = host.run(&shell(20, "echo 0", t));
    for i in 1..=COLLAPSE_ENTRIES as i64 {
        host.run(&shell(21, &format!("echo {i}"), t + i));
    }
    // The oldest was pushed out, so its repeat is a new alarm.
    let again = host.run(&shell(22, "echo 0", t + MINUTE));
    assert_ne!(first[0].alarm_id, again[0].alarm_id);
}

#[test]
fn no_alarm_id_loses_the_match_and_counts_it() {
    let mut host = Host::new(WEB_SHELL);
    let alarms = host.engine.on_start(
        &shell(20, "id", 1_790_000_000_000),
        &host.rules,
        &Clock(0),
        Instant::now(),
        none,
        || None,
    );
    assert!(alarms.is_empty());
    assert_eq!(host.engine.lost, 1);
}

/// Board #105: restricted rule sets share one CEL budget per start and run
/// after the unrestricted ones. Heavy rules in a restricted set
/// (`site-alarms`) are cut on a start with a long command line, counted
/// once, and raise the agent's own `evaluation.cut` alarm; the unrestricted
/// baseline rule, listed after them in the configuration, still runs first
/// and fires. A normal start runs everything and cuts nothing.
#[test]
fn restricted_rules_are_cut_per_start_and_the_baseline_still_fires() {
    let heavy = (0..11)
        .map(|n| format!("event['process.cmdline'].contains('zz{n}')"))
        .collect::<Vec<_>>()
        .join(" || ");
    // The restricted set first in the list: the agent still runs it last.
    let mut host = Host::new(WEB_SHELL);
    let baseline = std::mem::take(&mut host.rules);
    host.rules = rules_in("site-alarms", &["false", &heavy, &heavy]);
    host.rules.extend(baseline);

    let alarms = host.run(&shell(20, "id", MINUTE));
    assert_eq!(alarms.len(), 1, "the baseline rule fires on a normal start");
    assert_eq!(host.engine.budget_cuts, 0);

    let long = "a".repeat(200 * 1024);
    let alarms = host.run(&shell(21, &long, 2 * MINUTE));
    let sets: Vec<&str> = alarms.iter().map(|a| a.rule_set_id.as_str()).collect();
    assert_eq!(
        sets,
        ["baseline-alarms", "openvibes-agent"],
        "baseline first, then the cut"
    );
    let cut = &alarms[1];
    assert_eq!(cut.rule_id.as_str(), "evaluation.cut");
    assert_eq!((cut.rule_set_version, cut.rule_version), (1, 1));
    assert_eq!(cut.severity, Severity::Low);
    assert_eq!(cut.process.exe, "/usr/bin/sh");
    assert_eq!(host.engine.budget_cuts, 1, "the start is cut once");
    assert_eq!(host.engine.failures, 0, "a cut is not a rule failure");
}

/// The cut alarm collapses on exe and parent exe only: a loop that varies
/// its padding is one alarm whose count rises, not one per start.
#[test]
fn evaluation_cut_alarms_collapse_whatever_the_padding() {
    let heavy = (0..11)
        .map(|n| format!("event['process.cmdline'].contains('zz{n}')"))
        .collect::<Vec<_>>()
        .join(" || ");
    let mut host = Host::new(WEB_SHELL);
    host.rules = rules_in("site-alarms", &["false", &heavy, &heavy]);
    let mut ids = std::collections::BTreeSet::new();
    let mut last_count = 0;
    for n in 0..5 {
        let padded = format!("{}{n}", "b".repeat(200 * 1024));
        let alarms = host.run(&shell(30 + n, &padded, MINUTE + i64::from(n)));
        let cut = alarms
            .iter()
            .find(|a| a.rule_id.as_str() == "evaluation.cut")
            .unwrap();
        ids.insert(cut.alarm_id.clone());
        last_count = cut.count;
    }
    assert_eq!(ids.len(), 1, "one alarm for the whole loop");
    assert_eq!(last_count, 5);
    assert_eq!(host.engine.budget_cuts, 5);
}

/// Contract P14 "Restricted rule sets": a restricted set's rule needs a
/// `programs` prefilter of 1 to 8 names, and the set at most 32
/// distinct; the rest of the set still loads. `baseline-alarms` is exempt.
#[test]
fn restricted_sets_need_a_capped_programs_prefilter() {
    let nine: Vec<String> = (0..9).map(|n| format!("p{n}")).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    let rules = [
        ("true", Some(vec!["sh"])),
        ("true", None),
        ("true", Some(nine.clone())),
        // A repeated name counts once: 9 entries, 1 distinct.
        ("true", Some(vec!["sh"; 9])),
    ];
    // (An empty name never gets here: the loader refuses it in any set.)
    let (pairs, accepted, refused, _) = compile_set("site-alarms", &rules);
    assert_eq!((accepted, refused), (2, 2), "only the capped rules load");
    assert_eq!(pairs[0].1.rules(), 2);
    assert!(pairs[0].2, "restricted");

    // The baseline keeps rules without `programs`, and long lists.
    let (_, accepted, refused, unfiltered) = compile_set("baseline-alarms", &rules);
    assert_eq!((accepted, refused, unfiltered), (4, 0, 1));

    // 33 distinct names over rules of 8 or fewer: every rule is refused.
    let names: Vec<String> = (0..33).map(|n| format!("p{n}")).collect();
    let chunks: Vec<Vec<&str>> = names
        .chunks(8)
        .map(|chunk| chunk.iter().map(String::as_str).collect())
        .collect();
    let rules: Vec<(&str, Option<Vec<&str>>)> = chunks
        .into_iter()
        .map(|programs| ("true", Some(programs)))
        .collect();
    let (pairs, accepted, refused, _) = compile_set("site-alarms", &rules);
    assert_eq!((accepted, refused), (0, 5));
    assert!(pairs.is_empty());
    // 32 is still fine.
    let (_, accepted, _, _) = compile_set("site-alarms", &rules[..4]);
    assert_eq!(accepted, 4);
}

/// Restricted sets see `process.cmdline` and `parent.cmdline` masked, as an
/// alarm carries them; the baseline sees the full form.
#[test]
fn restricted_sets_see_masked_command_lines() {
    const SECRET: &str = "event['process.cmdline'].contains('hunter2')";
    const PARENT_SECRET: &str = "event['parent.cmdline'].contains('s3cret')";
    let mut host = Host::new("false");
    host.rules = rules_in("baseline-alarms", &[SECRET]);
    host.rules
        .extend(rules_in("site-alarms", &[SECRET, PARENT_SECRET]));
    host.run(&start(
        10,
        1,
        "/usr/sbin/nginx",
        &["nginx", "--password=s3cret"],
        0,
    ));

    let alarms = host.run(&shell(20, "mysql -phunter2", MINUTE));
    let sets: Vec<&str> = alarms.iter().map(|a| a.rule_set_id.as_str()).collect();
    assert_eq!(
        sets,
        ["baseline-alarms"],
        "only the unrestricted set sees the secret"
    );
    assert_eq!(host.engine.failures, 0);
}

/// A restricted set's prefilter still gates it: a start no rule names
/// isn't evaluated (or masked) for it.
#[test]
fn restricted_sets_skip_starts_their_programs_do_not_name() {
    let mut host = Host::new("false");
    host.rules = rules_in("site-alarms", &["true"]);
    assert_eq!(
        host.run(&start(20, 10, "/usr/bin/id", &["id"], MINUTE))
            .len(),
        0
    );
    assert_eq!(host.run(&shell(21, "id", MINUTE)).len(), 1);
}
