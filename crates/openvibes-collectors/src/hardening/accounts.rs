//! `accounts.*`: account **names** only, never password hashes: uid 0,
//! empty password fields, and system accounts (uid 1 to 999) with a login
//! shell (uid 0 has its own fact). Each list has its `.count`.

use super::Out;

/// Shells that do not allow a login.
const NO_LOGIN: [&str; 6] = ["nologin", "false", "sync", "shutdown", "halt", "true"];

pub(super) fn collect(out: &mut Out) {
    match out.read("/etc/passwd") {
        Ok(text) => {
            let entries: Vec<Vec<&str>> = text
                .lines()
                .map(|l| l.split(':').collect())
                .filter(|f: &Vec<&str>| f.len() >= 7)
                .collect();
            let uid = |f: &Vec<&str>| f[2].parse::<u64>().ok();
            out.counted_list(
                "accounts.uid0",
                entries
                    .iter()
                    .filter(|f| uid(f) == Some(0))
                    .map(|f| f[0].to_owned()),
            );
            out.counted_list(
                "accounts.shell_users",
                entries
                    .iter()
                    .filter(|f| uid(f).is_some_and(|u| (1..1000).contains(&u)))
                    .filter(|f| {
                        let shell = f[6].trim().rsplit('/').next().unwrap_or("");
                        !shell.is_empty() && !NO_LOGIN.contains(&shell)
                    })
                    .map(|f| f[0].to_owned()),
            );
        }
        Err(code) => out.error("passwd", code, "cannot read /etc/passwd"),
    }
    match out.read("/etc/shadow") {
        Ok(text) => out.counted_list(
            "accounts.empty_password",
            text.lines().filter_map(|l| {
                let mut fields = l.split(':');
                let name = fields.next()?;
                fields.next()?.is_empty().then(|| name.to_owned())
            }),
        ),
        Err(code) => out.error("shadow", code, "cannot read /etc/shadow"),
    }
}
