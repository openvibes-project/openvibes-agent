//! `auditd.*` and `audit.rules.*`: auditd's settings and the keys of the
//! persistent audit rules. Without `/etc/audit` (auditd not installed)
//! they are unavailable.

use super::{CollectorErrorCode, Out, dir_files, plain_int};

const ACTIONS: [&str; 5] = [
    "max_log_file_action",
    "space_left_action",
    "admin_space_left_action",
    "disk_full_action",
    "disk_error_action",
];

pub(super) fn collect(out: &mut Out) {
    let config = match out.read("/etc/audit/auditd.conf") {
        Ok(text) => text,
        Err(code) => {
            out.error("auditd", code, "cannot read /etc/audit/auditd.conf");
            return;
        }
    };
    let value = |key: &str| {
        config
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(key))
            .map(|(_, v)| v.trim().to_ascii_lowercase())
            .next_back()
            .unwrap_or_default()
    };
    for key in ACTIONS {
        out.string(&format!("auditd.{key}"), &value(key));
    }
    out.int("auditd.max_log_file", plain_int(&value("max_log_file")));
    let rules: Vec<String> = dir_files(&out.path("/etc/audit/rules.d"), ".rules")
        .iter()
        .filter_map(|f| super::read_bounded(f).ok())
        .collect();
    if rules.is_empty() && !out.path("/etc/audit/rules.d").is_dir() {
        out.error(
            "audit_rules",
            CollectorErrorCode::NotFound,
            "no /etc/audit/rules.d",
        );
        return;
    }
    out.list(
        "audit.rules.keys",
        rules.iter().flat_map(|t| t.lines()).flat_map(keys),
    );
    out.bool(
        "audit.rules.immutable",
        rules
            .iter()
            .flat_map(|t| t.lines())
            .any(|l| l.split_whitespace().eq(["-e", "2"])),
    );
}

/// The keys one rule line sets: `-k key` and `-F key=key`.
fn keys(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut found = Vec::new();
    for (i, word) in words.iter().enumerate() {
        if *word == "-k" {
            found.extend(words.get(i + 1).map(|k| (*k).to_owned()));
        } else if let Some(key) = word.strip_prefix("key=") {
            found.push(key.to_owned());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::keys;

    #[test]
    fn rule_keys_are_found_both_ways() {
        assert_eq!(keys("-w /etc/passwd -p wa -k identity"), ["identity"]);
        assert_eq!(
            keys("-a always,exit -F arch=b64 -S execve -F key=exec"),
            ["exec"]
        );
        assert!(keys("-D").is_empty());
    }
}
