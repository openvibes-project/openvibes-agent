//! `file.<name>.*`: existence, permission bits and owner of a fixed list
//! of system files and directories (links are not followed). Metadata
//! only, never contents.

use std::os::unix::fs::MetadataExt;

use super::Out;

/// Catalog name → path.
const FILES: [(&str, &str); 25] = [
    ("etc_passwd", "/etc/passwd"),
    ("etc_passwd_backup", "/etc/passwd-"),
    ("etc_shadow", "/etc/shadow"),
    ("etc_shadow_backup", "/etc/shadow-"),
    ("etc_group", "/etc/group"),
    ("etc_group_backup", "/etc/group-"),
    ("etc_gshadow", "/etc/gshadow"),
    ("etc_gshadow_backup", "/etc/gshadow-"),
    ("etc_sshd_config", "/etc/ssh/sshd_config"),
    ("etc_crontab", "/etc/crontab"),
    ("etc_cron_d", "/etc/cron.d"),
    ("etc_cron_hourly", "/etc/cron.hourly"),
    ("etc_cron_daily", "/etc/cron.daily"),
    ("etc_cron_weekly", "/etc/cron.weekly"),
    ("etc_cron_monthly", "/etc/cron.monthly"),
    ("etc_cron_allow", "/etc/cron.allow"),
    ("etc_at_allow", "/etc/at.allow"),
    ("etc_cron_deny", "/etc/cron.deny"),
    ("etc_at_deny", "/etc/at.deny"),
    ("boot_grub2_grub_cfg", "/boot/grub2/grub.cfg"),
    ("boot_grub_grub_cfg", "/boot/grub/grub.cfg"),
    ("etc_issue", "/etc/issue"),
    ("etc_issue_net", "/etc/issue.net"),
    ("etc_motd", "/etc/motd"),
    ("etc_security_opasswd", "/etc/security/opasswd"),
];

pub(super) fn collect(out: &mut Out) {
    for (name, path) in FILES {
        let metadata = std::fs::symlink_metadata(out.path(path)).ok();
        out.bool(&format!("file.{name}.exists"), metadata.is_some());
        let (mode, owner) = metadata.map_or((String::new(), String::new()), |m| {
            (
                format!("{:04o}", m.mode() & 0o7777),
                format!("{}:{}", m.uid(), m.gid()),
            )
        });
        out.string(&format!("file.{name}.mode"), &mode);
        out.string(&format!("file.{name}.owner"), &owner);
    }
}
