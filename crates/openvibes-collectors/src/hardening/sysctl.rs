//! `sysctl.*`: kernel settings as running, from `/proc/sys`. A name the
//! kernel does not have is left out (its rules are unavailable).

use super::{CollectorErrorCode, Out};

/// The integer settings in the catalog.
const NAMES: [&str; 37] = [
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.log_martians",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.tcp_syncookies",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
    "net.ipv6.conf.all.disable_ipv6",
    "kernel.randomize_va_space",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.yama.ptrace_scope",
    "kernel.unprivileged_bpf_disabled",
    "kernel.perf_event_paranoid",
    "kernel.sysrq",
    "net.core.bpf_jit_harden",
    "fs.suid_dumpable",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "fs.protected_fifos",
    "fs.protected_regular",
];

pub(super) fn collect(out: &mut Out) {
    if !out.path("/proc/sys/kernel").is_dir() {
        out.error("sysctl", CollectorErrorCode::NotFound, "no /proc/sys");
        return;
    }
    for name in NAMES {
        let file = format!("/proc/sys/{}", name.replace('.', "/"));
        if let Ok(value) = out.read(&file)
            && let Ok(value) = value.trim().parse::<i64>()
        {
            out.int(&format!("sysctl.{name}"), value);
        }
    }
    if let Ok(pattern) = out.read("/proc/sys/kernel/core_pattern") {
        out.bool(
            "sysctl.kernel.core_pattern_pipe",
            pattern.trim_start().starts_with('|'),
        );
    }
}
