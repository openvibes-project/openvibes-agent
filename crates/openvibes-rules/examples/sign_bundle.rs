//! Offline rule-signing tool for development and local testing; never part
//! of the agent. The private key stays in `KEY_FILE` (owner-only, 0600).
//!
//! Unix only (keys come from `/dev/urandom`).
//!
//! ```text
//! cargo run --example sign_bundle -- keygen KEY_FILE
//! cargo run --example sign_bundle -- sign KEY_FILE RULES.json RULE_SET_ID VERSION ISSUER_KEY_ID VALID_DAYS OUT.json
//! ```
//!
//! `keygen` prints the public key in the form the agent's `trusted_keys`
//! expect. `sign` wraps the exact bytes of `RULES.json` (a version 1 rule set)
//! in a signed envelope valid from now for `VALID_DAYS`, and checks it loads.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, RuleSet, SchemaVersion, SignedRuleEnvelope,
    Validate,
};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", key_file] => keygen(key_file),
        ["sign", key, rules, id, version, issuer, days, out] => {
            sign(key, rules, id, version, issuer, days, out)
        }
        _ => Err("usage: keygen KEY_FILE | sign KEY_FILE RULES.json RULE_SET_ID VERSION ISSUER_KEY_ID VALID_DAYS OUT.json".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sign_bundle: {message}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(path: &str) -> Result<(), String> {
    let mut seed = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut seed))
        .map_err(|e| format!("no randomness: {e}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut file| file.write_all(&seed))
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    println!("{}", URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()));
    Ok(())
}

fn sign(
    key_file: &str,
    rules_file: &str,
    rule_set_id: &str,
    version: &str,
    issuer: &str,
    days: &str,
    out: &str,
) -> Result<(), String> {
    let seed: [u8; 32] = fs::read(key_file)
        .map_err(|e| format!("cannot read {key_file}: {e}"))?
        .try_into()
        .map_err(|_| "key file must hold exactly 32 bytes".to_owned())?;
    let key = SigningKey::from_bytes(&seed);
    let payload =
        fs::read_to_string(rules_file).map_err(|e| format!("cannot read {rules_file}: {e}"))?;
    let rules: RuleSet =
        serde_json::from_str(&payload).map_err(|e| format!("invalid rule set: {e}"))?;
    rules
        .validate(ResourceLimits::V1)
        .map_err(|e| format!("invalid rule set: {e}"))?;
    let id = Identifier::new(rule_set_id).map_err(|e| format!("rule set id: {e}"))?;
    let issuer = Identifier::new(issuer).map_err(|e| format!("issuer key id: {e}"))?;
    let version: u64 = version
        .parse()
        .map_err(|_| "VERSION must be a positive integer")?;
    let days: i64 = days.parse().map_err(|_| "VALID_DAYS must be an integer")?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock before 1970")?
            .as_millis(),
    )
    .map_err(|_| "clock out of range")?;
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id.clone(),
        rule_set_version: version,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now,
        expires_at_unix_ms: now + days * 86_400_000,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|e| e.to_string())?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;

    // Prove the agent will accept it before writing it.
    let trusted = TrustedRuleKey::new(id.clone(), issuer, key.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id,
                    now_unix_ms: now,
                    last_accepted: None,
                },
            )
        })
        .map_err(|e| format!("the signed bundle does not load: {e}"))?;
    fs::write(out, bytes).map_err(|e| format!("cannot write {out}: {e}"))?;
    eprintln!("signed {rule_set_id} v{version}, valid for {days} days");
    Ok(())
}
