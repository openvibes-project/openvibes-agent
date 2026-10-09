//! `sshd.*`: the settings in `/etc/ssh/sshd_config` as sshd reads them.
//! Keywords are case-insensitive; the **first** value of a keyword wins;
//! `Include` is followed where it stands (relative paths below `/etc/ssh`,
//! a `*` in the last component, matches sorted by name); settings inside
//! `Match` blocks are not merged, only counted.

use super::{Out, plain_int};

const CONFIG: &str = "/etc/ssh/sshd_config";
/// Include nesting followed at most (sshd allows 16).
const MAX_DEPTH: usize = 8;

/// The keywords emitted as strings, as written ("" when not set).
const STRINGS: [&str; 24] = [
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "pubkeyauthentication",
    "kbdinteractiveauthentication",
    "hostbasedauthentication",
    "ignorerhosts",
    "usepam",
    "x11forwarding",
    "allowtcpforwarding",
    "allowagentforwarding",
    "permituserenvironment",
    "permittunnel",
    "gssapiauthentication",
    "loglevel",
    "banner",
    "ciphers",
    "macs",
    "kexalgorithms",
    "maxstartups",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
];
/// The keywords emitted as integers (-1 when not set or not plain).
const INTS: [&str; 5] = [
    "maxauthtries",
    "maxsessions",
    "logingracetime",
    "clientaliveinterval",
    "clientalivecountmax",
];

#[derive(Default)]
struct Config {
    /// keyword (lowercase) → first value, in the global section.
    values: std::collections::HashMap<String, String>,
    match_blocks: i64,
    in_match: bool,
}

pub(super) fn collect(out: &mut Out) {
    let text = match out.read(CONFIG) {
        Ok(text) => text,
        Err(code) => {
            out.error("sshd", code, "cannot read /etc/ssh/sshd_config");
            return;
        }
    };
    let mut config = Config::default();
    parse(out, &text, &mut config, 0);
    for key in STRINGS {
        let value = config.values.get(key).cloned().unwrap_or_default();
        out.string(&format!("sshd.{key}"), &value);
    }
    for key in INTS {
        let value = config.values.get(key).map_or(-1, |v| plain_int(v));
        out.int(&format!("sshd.{key}"), value);
    }
    out.int("sshd.match_blocks", config.match_blocks);
}

fn parse(out: &Out, text: &str, config: &mut Config, depth: usize) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "Keyword value" or "Keyword=value".
        let split = line
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(line.len());
        let keyword = line[..split].to_ascii_lowercase();
        let value = line[split..]
            .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
            .trim();
        match keyword.as_str() {
            "match" => {
                config.match_blocks += 1;
                config.in_match = true;
            }
            "include" if depth < MAX_DEPTH => {
                for pattern in value.split_whitespace() {
                    for file in included(out, pattern) {
                        if let Ok(text) = super::read_bounded(&file) {
                            parse(out, &text, config, depth + 1);
                        }
                    }
                }
            }
            _ if config.in_match => {}
            _ => {
                config
                    .values
                    .entry(keyword)
                    .or_insert_with(|| value.to_owned());
            }
        }
    }
}

/// The files an `Include` pattern names: relative to `/etc/ssh`, with `*`
/// (and `?`) allowed in the last component only.
fn included(out: &Out, pattern: &str) -> Vec<std::path::PathBuf> {
    let absolute = if pattern.starts_with('/') {
        pattern.to_owned()
    } else {
        format!("/etc/ssh/{pattern}")
    };
    let path = out.path(&absolute);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    if !name.contains(['*', '?']) {
        return vec![path.clone()];
    }
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| glob(name, n)))
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

/// `*` and `?` matching within one path component (the usual greedy
/// matcher with one backtrack point).
fn glob(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn globs_match_like_sshd() {
        assert!(glob("*.conf", "50-redhat.conf"));
        assert!(glob("*", "x"));
        assert!(!glob("*.conf", "50-redhat.conf.rpmnew"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "abbc"));
        assert!(glob("50-*.conf", "50-cloud-init.conf"));
    }
}
