//! `login_defs.*`, `pam.pwquality.*`, `pam.faillock.*` and `pam.modules`:
//! password and login policy as configured.

use super::{CollectorErrorCode, Out, dir_files, plain_int};

const LOGIN_INTS: [&str; 5] = [
    "pass_max_days",
    "pass_min_days",
    "pass_warn_age",
    "sha_crypt_min_rounds",
    "sha_crypt_max_rounds",
];
const LOGIN_STRINGS: [&str; 2] = ["encrypt_method", "umask"];
const PWQUALITY: [&str; 10] = [
    "minlen",
    "minclass",
    "dcredit",
    "ucredit",
    "lcredit",
    "ocredit",
    "maxrepeat",
    "maxsequence",
    "difok",
    "dictcheck",
];
const FAILLOCK: [&str; 3] = ["deny", "unlock_time", "fail_interval"];
/// The PAM stacks whose modules are listed (Fedora/RHEL and Debian names).
const PAM_STACKS: [&str; 7] = [
    "system-auth",
    "password-auth",
    "common-auth",
    "common-password",
    "common-account",
    "login",
    "sshd",
];

pub(super) fn collect(out: &mut Out) {
    match out.read("/etc/login.defs") {
        Ok(text) => {
            // "KEY VALUE"; the last occurrence wins, as shadow-utils reads it.
            let value = |key: &str| {
                text.lines()
                    .filter_map(|l| {
                        let mut words = l.split_whitespace();
                        let k = words.next()?;
                        (!k.starts_with('#') && k.eq_ignore_ascii_case(key))
                            .then(|| words.next())?
                    })
                    .next_back()
                    .unwrap_or_default()
                    .to_owned()
            };
            for key in LOGIN_INTS {
                out.int(&format!("login_defs.{key}"), plain_int(&value(key)));
            }
            for key in LOGIN_STRINGS {
                out.string(&format!("login_defs.{key}"), &value(key));
            }
        }
        Err(code) => out.error("login_defs", code, "cannot read /etc/login.defs"),
    }

    // pwquality.conf, then pwquality.conf.d/*.conf: "key = value", last wins.
    let mut texts: Vec<String> = out
        .read("/etc/security/pwquality.conf")
        .into_iter()
        .collect();
    for file in dir_files(&out.path("/etc/security/pwquality.conf.d"), ".conf") {
        texts.extend(super::read_bounded(&file));
    }
    if texts.is_empty() {
        out.error(
            "pwquality",
            CollectorErrorCode::NotFound,
            "no pwquality.conf",
        );
    } else {
        for key in PWQUALITY {
            let value = texts
                .iter()
                .flat_map(|t| settings(t))
                .filter(|(k, _)| k == key)
                .last();
            out.int(
                &format!("pam.pwquality.{key}"),
                value.map_or(-1, |(_, v)| signed(&v)),
            );
        }
    }

    match out.read("/etc/security/faillock.conf") {
        Ok(text) => {
            let pairs: Vec<(String, String)> = settings(&text).collect();
            for key in FAILLOCK {
                let value = pairs.iter().rfind(|(k, _)| k == key);
                out.int(
                    &format!("pam.faillock.{key}"),
                    value.map_or(-1, |(_, v)| plain_int(v)),
                );
            }
            out.bool(
                "pam.faillock.even_deny_root",
                pairs.iter().any(|(k, _)| k == "even_deny_root"),
            );
        }
        Err(code) => out.error("faillock", code, "cannot read /etc/security/faillock.conf"),
    }

    let mut modules = Vec::new();
    let mut read_any = false;
    for stack in PAM_STACKS {
        if let Ok(text) = out.read(&format!("/etc/pam.d/{stack}")) {
            read_any = true;
            modules.extend(text.lines().filter_map(pam_module));
        }
    }
    if read_any {
        out.list("pam.modules", modules);
    } else {
        out.error("pam", CollectorErrorCode::NotFound, "no PAM stack found");
    }
}

/// `key = value` and bare `flag` lines, comments dropped, keys lowercase.
fn settings(text: &str) -> impl Iterator<Item = (String, String)> + '_ {
    text.lines().filter_map(|line| {
        let line = line.split('#').next()?.trim();
        if line.is_empty() {
            return None;
        }
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        Some((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
    })
}

/// pwquality's credits may be negative ("dcredit = -1").
fn signed(value: &str) -> i64 {
    match value.strip_prefix('-') {
        Some(rest) if plain_int(rest) >= 0 => -plain_int(rest),
        _ => plain_int(value),
    }
}

/// The module of one PAM line: `type control module [args]`, where control
/// may be `[...]` with spaces inside; `@include` and comments have none.
fn pam_module(line: &str) -> Option<String> {
    let line = line.trim().trim_start_matches('-');
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let after_type = line.split_once(char::is_whitespace)?.1.trim_start();
    let after_control = if let Some(rest) = after_type.strip_prefix('[') {
        rest.split_once(']')?.1
    } else {
        after_type.split_once(char::is_whitespace)?.1
    };
    let module = after_control.split_whitespace().next()?;
    let name = module.rsplit('/').next()?;
    name.ends_with(".so").then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{pam_module, signed};

    #[test]
    fn pam_lines_name_their_module() {
        assert_eq!(
            pam_module("auth required pam_faillock.so preauth silent").as_deref(),
            Some("pam_faillock.so")
        );
        assert_eq!(
            pam_module("auth [default=die] pam_faillock.so authfail").as_deref(),
            Some("pam_faillock.so")
        );
        assert_eq!(
            pam_module("-session optional /usr/lib64/security/pam_systemd.so").as_deref(),
            Some("pam_systemd.so")
        );
        assert_eq!(pam_module("@include common-auth"), None);
        assert_eq!(pam_module("# auth sufficient pam_rootok.so"), None);
    }

    #[test]
    fn credits_may_be_negative() {
        assert_eq!(signed("-1"), -1);
        assert_eq!(signed("14"), 14);
        assert_eq!(signed("x"), -1);
    }
}
