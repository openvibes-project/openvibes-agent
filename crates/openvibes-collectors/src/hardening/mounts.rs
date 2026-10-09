//! `mount.<name>.*`: whether a path is its own mount point, and the
//! per-mount options of the filesystem holding it, from init's
//! `/proc/1/mountinfo`: the helper's own sandbox (`PrivateTmp`,
//! `ProtectSystem`) has a mount namespace of its own, which is not the
//! host's.

use super::{CollectorErrorCode, Out};

/// Catalog name → path.
const MOUNTS: [(&str, &str); 8] = [
    ("tmp", "/tmp"),
    ("var", "/var"),
    ("var_tmp", "/var/tmp"),
    ("var_log", "/var/log"),
    ("var_log_audit", "/var/log/audit"),
    ("home", "/home"),
    ("dev_shm", "/dev/shm"),
    ("boot", "/boot"),
];

pub(super) fn collect(out: &mut Out) {
    let text = match out.read("/proc/1/mountinfo") {
        Ok(text) => text,
        Err(code) => {
            out.error("mounts", code, "cannot read /proc/1/mountinfo");
            return;
        }
    };
    // (mount point, per-mount options), in mount order: a later mount on
    // the same point hides an earlier one.
    let mounts: Vec<(String, Vec<String>)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let point = fields.nth(4)?;
            let options = fields.next()?;
            Some((
                unescape(point),
                options.split(',').map(str::to_owned).collect(),
            ))
        })
        .collect();
    if mounts.is_empty() {
        out.error(
            "mounts",
            CollectorErrorCode::InvalidData,
            "no mounts listed",
        );
        return;
    }
    for (name, path) in MOUNTS {
        let separate = mounts.iter().any(|(point, _)| point == path);
        let holder = mounts
            .iter()
            .rev()
            .filter(|(point, _)| holds(point, path))
            .max_by_key(|(point, _)| point.len());
        out.bool(&format!("mount.{name}.separate"), separate);
        out.list(
            &format!("mount.{name}.options"),
            holder.map(|(_, o)| o.clone()).unwrap_or_default(),
        );
    }
}

/// Whether mount point `point` holds `path`.
fn holds(point: &str, path: &str) -> bool {
    point == "/" || path == point || path.starts_with(&format!("{point}/"))
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape(field: &str) -> String {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::holds;

    #[test]
    fn the_longest_mount_point_holds_a_path() {
        assert!(holds("/", "/var/tmp"));
        assert!(holds("/var", "/var/tmp"));
        assert!(!holds("/var/t", "/var/tmp"));
        assert!(holds("/var/tmp", "/var/tmp"));
    }
}
