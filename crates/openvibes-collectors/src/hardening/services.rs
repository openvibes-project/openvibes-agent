//! `service.*`: enabled units (the `*.wants` links systemd follows) and
//! running services (a `*.service` cgroup with a process), read without
//! asking systemd.

use super::{CollectorErrorCode, Out};

const WANTS: [&str; 2] = ["/etc/systemd/system", "/usr/lib/systemd/system"];
const CGROUP: &str = "/sys/fs/cgroup/system.slice";

pub(super) fn collect(out: &mut Out) {
    let mut enabled = Vec::new();
    for dir in WANTS {
        for wants in std::fs::read_dir(out.path(dir))
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = wants.path();
            if path.extension().is_some_and(|e| e == "wants") {
                enabled.extend(names(&path));
            }
        }
    }
    out.list("service.enabled", enabled);
    let root = out.path(CGROUP);
    if !root.is_dir() {
        out.error(
            "services",
            CollectorErrorCode::NotFound,
            "no system.slice cgroup",
        );
        return;
    }
    let mut active = Vec::new();
    // system.slice/x.service and one level of nested slices
    // (system.slice/system-getty.slice/getty@tty1.service).
    for entry in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".slice") {
            for inner in std::fs::read_dir(entry.path())
                .into_iter()
                .flatten()
                .flatten()
            {
                let inner_name = inner.file_name().to_string_lossy().into_owned();
                if running(&inner.path(), &inner_name) {
                    active.push(inner_name);
                }
            }
        } else if running(&entry.path(), &name) {
            active.push(name);
        }
    }
    out.list("service.active", active);
}

fn names(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

fn running(dir: &std::path::Path, name: &str) -> bool {
    name.ends_with(".service")
        && super::read_bounded(&dir.join("cgroup.procs")).is_ok_and(|p| !p.trim().is_empty())
}
