use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, SchemaVersion, SignedRuleEnvelope,
};
use openvibes_rules::{
    AcceptedVersion, LoadContext, LoadError, RuleLoader, TrustedRuleKey, VerifiedRuleSet,
    signing_preimage,
};
use sha2::{Digest, Sha256};

const JSON: &str = include_str!("../../openvibes-core/tests/fixtures/rule-set-v1.json");
const YAML: &str = include_str!("../../openvibes-core/tests/fixtures/rule-set-v1.yaml");
// Test-only deterministic signing seed; never a deployment credential.
const SEED: [u8; 32] = [7; 32];

fn digest_hex(payload: &str) -> String {
    Sha256::digest(payload.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn loader_with(limits: ResourceLimits) -> RuleLoader {
    let key = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    RuleLoader::new(
        vec![TrustedRuleKey::new(id("baseline"), id("key.1"), key).unwrap()],
        limits,
    )
    .unwrap()
}

fn resign(envelope: &mut SignedRuleEnvelope) {
    envelope.payload_sha256_hex = digest_hex(&envelope.payload);
    let bytes = signing_preimage(envelope, ResourceLimits::V1).unwrap();
    envelope.signature_base64url =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&SEED).sign(&bytes).to_bytes());
}

fn bundle(payload: &str, encoding: PayloadEncoding) -> SignedRuleEnvelope {
    let mut result = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("baseline"),
        rule_set_version: 7,
        issuer_key_id: id("key.1"),
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 3_000,
        payload_encoding: encoding,
        payload: payload.to_owned(),
        payload_sha256_hex: String::new(),
        signature_base64url: String::new(),
    };
    resign(&mut result);
    result
}

fn load(
    loader: &RuleLoader,
    envelope: &SignedRuleEnvelope,
    last: Option<&AcceptedVersion>,
) -> Result<VerifiedRuleSet, LoadError> {
    loader.load_json(
        &serde_json::to_vec(envelope).unwrap(),
        LoadContext {
            expected_rule_set_id: &id("baseline"),
            now_unix_ms: 2_000,
            last_accepted: last,
        },
    )
}

fn rejects(envelope: &SignedRuleEnvelope, expected: LoadError) {
    assert_eq!(
        load(&loader_with(ResourceLimits::V1), envelope, None).unwrap_err(),
        expected
    );
}

#[test]
fn authenticated_json_and_yaml_have_identical_rules() {
    let loader = loader_with(ResourceLimits::V1);
    let json = load(&loader, &bundle(JSON, PayloadEncoding::Json), None).unwrap();
    let yaml = load(&loader, &bundle(YAML, PayloadEncoding::Yaml), None).unwrap();
    assert_eq!(json.rules(), yaml.rules());
    assert_eq!(json.accepted_version().rule_set_id(), &id("baseline"));
    assert_eq!(json.accepted_version().version(), 7);
    assert_eq!(json.issuer_key_id(), &id("key.1"));
    assert_eq!(json.expires_at_unix_ms(), 3_000);
}

#[test]
fn signing_bytes_match_the_documented_binary_format() {
    let mut envelope = bundle("{}", PayloadEncoding::Json);
    envelope.rule_set_id = id("a");
    envelope.issuer_key_id = id("k");
    envelope.rule_set_version = 1;
    envelope.created_at_unix_ms = 1;
    envelope.expires_at_unix_ms = 2;
    // A fixed vector catches endian, field-order, encoding and length-prefix drift.
    let expected = concat!(
        "4f50454e56494245532d52554c452d454e56454c4f50452d563100",
        "0001",
        "0000000161",
        "0000000000000001",
        "000000016b",
        "0000000000000001",
        "0000000000000002",
        "01",
        "0000000000000002",
        "7b7d",
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    let actual: String = signing_preimage(&envelope, ResourceLimits::V1)
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(actual, expected);
    envelope.signature_base64url = "ignored while constructing signing bytes".into();
    assert!(signing_preimage(&envelope, ResourceLimits::V1).is_ok());
}

#[test]
fn independent_ed25519_vector_matches_the_signing_format() {
    // Produced independently using Python cryptography's Ed25519 implementation
    // and struct.pack of the documented field sequence (test-only seed [7; 32]).
    let mut envelope = bundle("{}", PayloadEncoding::Json);
    envelope.rule_set_id = id("a");
    envelope.issuer_key_id = id("k");
    envelope.rule_set_version = 1;
    envelope.created_at_unix_ms = 1;
    envelope.expires_at_unix_ms = 2;
    envelope.signature_base64url =
        "J0-Xlxv8LfJ5zAzIMBfoGaE5djK_9QafR2FNZi9RJCvMTnV2xBtER5azzjJZgW2y0Iom01eWjUDRfyzBAJoACw"
            .into();
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    let hash: String = Sha256::digest(&preimage)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hash,
        "a5eb8333a0ba5c782069ea5fd7c32588844f5e1d2a3195f8541dab33a5346a72"
    );
    let loader = RuleLoader::new(
        vec![
            TrustedRuleKey::new(
                id("a"),
                id("k"),
                SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
        ResourceLimits::V1,
    )
    .unwrap();
    let result = loader.load_json(
        &serde_json::to_vec(&envelope).unwrap(),
        LoadContext {
            expected_rule_set_id: &id("a"),
            now_unix_ms: 1,
            last_accepted: None,
        },
    );
    // Signature verification passed and reached contract checking: {} has no rules.
    assert_eq!(result.unwrap_err(), LoadError::InvalidRules);
}

#[test]
fn document_limit_accepts_exact_size_and_rejects_one_extra_byte() {
    let envelope = bundle(JSON, PayloadEncoding::Json);
    let mut bytes = serde_json::to_vec(&envelope).unwrap();
    let limits = ResourceLimits {
        document_bytes: bytes.len(),
        ..ResourceLimits::V1
    };
    let loader = loader_with(limits);
    assert!(
        loader
            .load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id("baseline"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .is_ok()
    );
    bytes.push(b' ');
    assert_eq!(
        loader
            .load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id("baseline"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .unwrap_err(),
        LoadError::DocumentTooLarge
    );
}

#[test]
fn field_and_collection_limits_apply_at_the_boundary_in_both_formats() {
    let limits = ResourceLimits {
        string_bytes: 128,
        expression_bytes: 160,
        rules_per_set: 1,
        list_items: 16,
        ..ResourceLimits::V1
    };
    let loader = loader_with(limits);
    let mut value: serde_json::Value = serde_json::from_str(JSON).unwrap();
    value["rules"][0]["title"] = "x".repeat(128).into();
    value["rules"][0]["expression"] = "x".repeat(160).into();
    value["optional"] = serde_json::json!(vec![0; 16]);
    for encoding in [PayloadEncoding::Json, PayloadEncoding::Yaml] {
        let encode = |value: &serde_json::Value| match encoding {
            PayloadEncoding::Json => serde_json::to_string(value).unwrap(),
            PayloadEncoding::Yaml => serde_saphyr::to_string(value).unwrap(),
        };
        assert!(load(&loader, &bundle(&encode(&value), encoding), None).is_ok());
        for mutate in [
            (|v: &mut serde_json::Value| v["rules"][0]["title"] = "x".repeat(129).into())
                as fn(&mut serde_json::Value),
            |v| v["rules"][0]["expression"] = "x".repeat(161).into(),
            |v| v["optional"] = serde_json::json!(vec![0; 17]),
            |v| {
                let mut second = v["rules"][0].clone();
                second["id"] = "another".into();
                v["rules"].as_array_mut().unwrap().push(second);
            },
        ] {
            let mut invalid = value.clone();
            mutate(&mut invalid);
            assert_eq!(
                load(&loader, &bundle(&encode(&invalid), encoding), None).unwrap_err(),
                LoadError::InvalidPayload
            );
        }
    }
}

#[test]
fn node_and_nesting_limits_cover_unknown_payload_fields() {
    let loader = loader_with(ResourceLimits {
        document_nodes: 50,
        document_nesting_depth: 4,
        ..ResourceLimits::V1
    });
    let base = bundle(JSON, PayloadEncoding::Json);
    assert!(load(&loader, &base, None).is_ok());
    for nested in ["[[[0]]]", "[[[[0]]]]"] {
        let payload = JSON.replacen('{', &format!("{{\"optional\":{nested},"), 1);
        let result = load(&loader, &bundle(&payload, PayloadEncoding::Json), None);
        assert_eq!(result.is_ok(), nested == "[[[0]]]");
    }
    let payload = JSON.replacen(
        '{',
        &format!("{{\"optional\":[{}],", vec!["0"; 51].join(",")),
        1,
    );
    assert_eq!(
        load(&loader, &bundle(&payload, PayloadEncoding::Json), None).unwrap_err(),
        LoadError::InvalidPayload
    );
}

#[test]
fn changed_payload_requires_both_new_digest_and_signature() {
    let mut envelope = bundle(JSON, PayloadEncoding::Json);
    envelope.payload.push(' ');
    rejects(&envelope, LoadError::DigestMismatch);
    envelope.payload_sha256_hex = digest_hex(&envelope.payload);
    rejects(&envelope, LoadError::InvalidSignature);
}

#[test]
fn every_signed_metadata_field_is_authenticated() {
    let base = bundle(JSON, PayloadEncoding::Json);
    for mutate in [
        (|e: &mut SignedRuleEnvelope| e.rule_set_version += 1) as fn(&mut SignedRuleEnvelope),
        |e| e.created_at_unix_ms -= 1,
        |e| e.expires_at_unix_ms += 1,
        |e| e.payload_encoding = PayloadEncoding::Yaml,
    ] {
        let mut changed = base.clone();
        mutate(&mut changed);
        rejects(&changed, LoadError::InvalidSignature);
    }
    let mut changed = base.clone();
    changed.issuer_key_id = id("key.2");
    let key = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let loader = RuleLoader::new(
        vec![TrustedRuleKey::new(id("baseline"), id("key.2"), key).unwrap()],
        ResourceLimits::V1,
    )
    .unwrap();
    assert_eq!(
        load(&loader, &changed, None).unwrap_err(),
        LoadError::InvalidSignature
    );
    changed = base;
    changed.rule_set_id = id("other");
    let loader = RuleLoader::new(
        vec![TrustedRuleKey::new(id("other"), id("key.1"), key).unwrap()],
        ResourceLimits::V1,
    )
    .unwrap();
    assert_eq!(
        loader
            .load_json(
                &serde_json::to_vec(&changed).unwrap(),
                LoadContext {
                    expected_rule_set_id: &id("other"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .unwrap_err(),
        LoadError::InvalidSignature
    );
}

#[test]
fn untrusted_wrong_and_weak_keys_are_rejected() {
    let envelope = bundle(JSON, PayloadEncoding::Json);
    let empty = RuleLoader::new(vec![], ResourceLimits::V1).unwrap();
    assert_eq!(
        load(&empty, &envelope, None).unwrap_err(),
        LoadError::UntrustedIssuer
    );
    let wrong = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let loader = RuleLoader::new(
        vec![TrustedRuleKey::new(id("baseline"), id("key.1"), wrong).unwrap()],
        ResourceLimits::V1,
    )
    .unwrap();
    assert_eq!(
        load(&loader, &envelope, None).unwrap_err(),
        LoadError::InvalidSignature
    );
    let mut identity_point = [0; 32];
    identity_point[0] = 1;
    assert!(TrustedRuleKey::new(id("baseline"), id("weak"), identity_point).is_err());
}

#[test]
fn keys_are_scoped_and_duplicate_trust_entries_rejected() {
    let key = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let entry = TrustedRuleKey::new(id("other"), id("key.1"), key).unwrap();
    assert!(RuleLoader::new(vec![entry.clone(), entry.clone()], ResourceLimits::V1).is_err());
    let loader = RuleLoader::new(vec![entry], ResourceLimits::V1).unwrap();
    assert_eq!(
        load(&loader, &bundle(JSON, PayloadEncoding::Json), None).unwrap_err(),
        LoadError::UntrustedIssuer
    );
}

#[test]
fn signature_encoding_is_strict() {
    for signature in [
        "A".repeat(85),
        "A".repeat(87),
        format!("{}=", "A".repeat(85)),
        "A".repeat(86),
    ] {
        let mut envelope = bundle(JSON, PayloadEncoding::Json);
        envelope.signature_base64url = signature;
        assert!(load(&loader_with(ResourceLimits::V1), &envelope, None).is_err());
    }
    // Invalid unused trailing bits: A encodes zeros; B is non-canonical.
    let mut envelope = bundle(JSON, PayloadEncoding::Json);
    envelope.signature_base64url = format!("{}B", "A".repeat(85));
    rejects(&envelope, LoadError::InvalidSignature);
}

#[test]
fn malformed_payload_is_never_parsed_before_signature_checks() {
    let mut envelope = bundle("not json", PayloadEncoding::Json);
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode([0; 64]);
    rejects(&envelope, LoadError::InvalidSignature);
    resign(&mut envelope);
    rejects(&envelope, LoadError::InvalidPayload);
}

#[test]
fn validity_interval_is_start_inclusive_end_exclusive() {
    let loader = loader_with(ResourceLimits::V1);
    let bytes = serde_json::to_vec(&bundle(JSON, PayloadEncoding::Json)).unwrap();
    for (now, expected) in [
        (999, Some(LoadError::NotYetValid)),
        (1_000, None),
        (2_999, None),
        (3_000, Some(LoadError::Expired)),
        (-1, Some(LoadError::InvalidContext)),
    ] {
        let result = loader.load_json(
            &bytes,
            LoadContext {
                expected_rule_set_id: &id("baseline"),
                now_unix_ms: now,
                last_accepted: None,
            },
        );
        assert_eq!(result.err(), expected);
    }
}

#[test]
fn accepted_version_supports_identical_reload_and_rejects_rollback_or_equivocation() {
    let loader = loader_with(ResourceLimits::V1);
    let mut envelope = bundle(JSON, PayloadEncoding::Json);
    let first = load(&loader, &envelope, None).unwrap();
    let record = first.accepted_version();
    let restored = AcceptedVersion::restore(
        record.rule_set_id().clone(),
        record.version(),
        *record.preimage_sha256(),
    )
    .unwrap();
    assert!(load(&loader, &envelope, Some(&restored)).is_ok());
    envelope.rule_set_version = 6;
    resign(&mut envelope);
    assert_eq!(
        load(&loader, &envelope, Some(&restored)).unwrap_err(),
        LoadError::Rollback
    );
    envelope.rule_set_version = 7;
    envelope.expires_at_unix_ms += 1;
    resign(&mut envelope);
    assert_eq!(
        load(&loader, &envelope, Some(&restored)).unwrap_err(),
        LoadError::VersionConflict
    );
    envelope.rule_set_version = 8;
    resign(&mut envelope);
    assert!(load(&loader, &envelope, Some(&restored)).is_ok());
}

#[test]
fn state_and_bundle_identity_must_match_requested_identity() {
    let loader = loader_with(ResourceLimits::V1);
    let envelope = bundle(JSON, PayloadEncoding::Json);
    let last = AcceptedVersion::restore(id("other"), 1, [0; 32]).unwrap();
    assert_eq!(
        load(&loader, &envelope, Some(&last)).unwrap_err(),
        LoadError::InvalidContext
    );
    assert_eq!(
        loader
            .load_json(
                &serde_json::to_vec(&envelope).unwrap(),
                LoadContext {
                    expected_rule_set_id: &id("other"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .unwrap_err(),
        LoadError::WrongRuleSet
    );
    assert!(AcceptedVersion::restore(id("baseline"), 0, [0; 32]).is_err());
}

#[test]
fn invalid_rules_do_not_advance_acceptance_state() {
    let loader = loader_with(ResourceLimits::V1);
    let accepted = load(&loader, &bundle(JSON, PayloadEncoding::Json), None).unwrap();
    let mut invalid = bundle("{\"schema_version\":1,\"rules\":[]}", PayloadEncoding::Json);
    invalid.rule_set_version = 8;
    resign(&mut invalid);
    assert_eq!(
        load(&loader, &invalid, Some(accepted.accepted_version())).unwrap_err(),
        LoadError::InvalidRules
    );
    assert_eq!(accepted.accepted_version().version(), 7);
}

#[test]
fn unknown_payload_fields_are_bounded_but_envelope_extensions_are_rejected() {
    let payload = JSON.replacen('{', "{\"optional\":true,", 1);
    assert!(
        load(
            &loader_with(ResourceLimits::V1),
            &bundle(&payload, PayloadEncoding::Json),
            None
        )
        .is_ok()
    );
    let mut envelope = serde_json::to_value(bundle(JSON, PayloadEncoding::Json)).unwrap();
    envelope["unsigned_extension"] = true.into();
    assert_eq!(
        loader_with(ResourceLimits::V1)
            .load_json(
                &serde_json::to_vec(&envelope).unwrap(),
                LoadContext {
                    expected_rule_set_id: &id("baseline"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .unwrap_err(),
        LoadError::InvalidEnvelope
    );
}

#[test]
fn unknown_fields_cannot_hide_deep_structures_or_oversized_strings() {
    let nested = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    let long = format!("\"{}\"", "x".repeat(ResourceLimits::V1.string_bytes + 1));
    for value in [nested, long] {
        let payload = JSON.replacen('{', &format!("{{\"optional\":{value},"), 1);
        rejects(
            &bundle(&payload, PayloadEncoding::Json),
            LoadError::InvalidPayload,
        );
    }
}

#[test]
fn duplicate_keys_and_trailing_documents_are_rejected() {
    for payload in [
        JSON.replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"schema_version\": 1,",
        ),
        format!("{JSON} {{}}"),
        JSON.replacen('{', "{\"optional\":{\"x\":1,\"x\":2},", 1),
    ] {
        rejects(
            &bundle(&payload, PayloadEncoding::Json),
            LoadError::InvalidPayload,
        );
    }
    for payload in [
        format!("{YAML}\nschema_version: 1"),
        format!("{YAML}\n---\nx: 1"),
        format!("{YAML}\n...\n["),
        format!("{YAML}\noptional: !include /etc/passwd"),
        format!("{YAML}\noptional: {{<<: {{x: 1}}}}"),
        format!("{YAML}\noptional: &loop [*loop]"),
    ] {
        rejects(
            &bundle(&payload, PayloadEncoding::Yaml),
            LoadError::InvalidPayload,
        );
    }
}

#[test]
fn yaml_depth_and_alias_budgets_are_enforced() {
    let deep = format!("{YAML}\noptional: {}0{}", "[".repeat(33), "]".repeat(33));
    rejects(
        &bundle(&deep, PayloadEncoding::Yaml),
        LoadError::InvalidPayload,
    );
    let alias = format!("{YAML}\nfirst: &a test\nsecond: *a\n");
    let limits = ResourceLimits {
        yaml_alias_replay_events: 0,
        ..ResourceLimits::V1
    };
    assert_eq!(
        load(
            &loader_with(limits),
            &bundle(&alias, PayloadEncoding::Yaml),
            None
        )
        .unwrap_err(),
        LoadError::InvalidPayload
    );
    assert!(
        load(
            &loader_with(ResourceLimits::V1),
            &bundle(&alias, PayloadEncoding::Yaml),
            None
        )
        .is_ok()
    );
    let expanded = format!(
        "{YAML}\nfirst: &a [{}]\nsecond: [{}]\n",
        (0..100).map(|_| "0").collect::<Vec<_>>().join(","),
        (0..64).map(|_| "*a").collect::<Vec<_>>().join(",")
    );
    let limits = ResourceLimits {
        yaml_alias_replay_events: 100,
        ..ResourceLimits::V1
    };
    assert_eq!(
        load(
            &loader_with(limits),
            &bundle(&expanded, PayloadEncoding::Yaml),
            None
        )
        .unwrap_err(),
        LoadError::InvalidPayload
    );
}

#[test]
fn envelope_byte_budget_is_enforced_before_decode() {
    let bytes = vec![b' '; ResourceLimits::V1.document_bytes + 1];
    assert_eq!(
        loader_with(ResourceLimits::V1)
            .load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id("baseline"),
                    now_unix_ms: 2_000,
                    last_accepted: None,
                }
            )
            .unwrap_err(),
        LoadError::DocumentTooLarge
    );
}

#[test]
fn unsafe_limit_configurations_are_rejected() {
    for limits in [
        ResourceLimits {
            document_nesting_depth: 0,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            document_nesting_depth: usize::MAX,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            document_bytes: usize::MAX,
            ..ResourceLimits::V1
        },
    ] {
        assert!(matches!(
            RuleLoader::new(vec![], limits),
            Err(LoadError::InvalidLimits)
        ));
    }
}

#[test]
fn payload_semantics_and_identifiers_are_checked() {
    for payload in [
        JSON.replace("\"schema_version\": 1", "\"schema_version\": 2"),
        JSON.replace("\"confidence\": 100", "\"confidence\": 101"),
        JSON.replace("\"version\": 1", "\"version\": 0"),
        JSON.replace("process.ssh.running", "../../bad"),
    ] {
        rejects(
            &bundle(&payload, PayloadEncoding::Json),
            LoadError::InvalidRules,
        );
    }
    let mut value: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let rule = value["rules"][0].clone();
    value["rules"].as_array_mut().unwrap().push(rule);
    rejects(
        &bundle(&value.to_string(), PayloadEncoding::Json),
        LoadError::InvalidRules,
    );
}

#[test]
fn errors_do_not_echo_payload_text() {
    let envelope = bundle("sensitive-input-marker", PayloadEncoding::Json);
    let error = load(&loader_with(ResourceLimits::V1), &envelope, None).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("sensitive-input-marker"));
}
