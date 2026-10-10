//! The collector against a whole fake host, checked against the protocol's
//! fact catalog (`vectors/fact-catalog.json`, P19).

use std::{collections::BTreeMap, fs, path::Path};

use openvibes_core::FactValue;

use super::collect_hardening;

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// A host with every source present.
fn host(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("hardening-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    write(
        &root,
        "/etc/os-release",
        "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.6\"\n",
    );
    write(
        &root,
        "/etc/ssh/sshd_config",
        "# comment\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMaxAuthTries 4\nLoginGraceTime 1m\nMatch User backup\n  PasswordAuthentication yes\n",
    );
    write(
        &root,
        "/etc/ssh/sshd_config.d/50-site.conf",
        "PermitRootLogin=no\nX11Forwarding no\n",
    );
    write(
        &root,
        "/etc/ssh/sshd_config.d/50-site.conf.rpmnew",
        "PermitRootLogin yes\n",
    );
    for (name, value) in [("ipv4/ip_forward", "0"), ("ipv4/tcp_syncookies", "1")] {
        write(
            &root,
            &format!("/proc/sys/net/{name}"),
            &format!("{value}\n"),
        );
    }
    // Path, contents.
    for (path, contents) in [
        ("/proc/sys/kernel/randomize_va_space", "2\n"),
        (
            "/proc/sys/kernel/core_pattern",
            "|/usr/lib/systemd/systemd-coredump %P\n",
        ),
        (
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\ngames:x:12:100::/usr/games:/bin/bash\nola:x:1000:1000::/home/ola:/bin/bash\n",
        ),
        (
            "/etc/shadow",
            "root:$6$hash:20000::::::\nnopass::20000::::::\nlocked:!:20000::::::\n",
        ),
        (
            "/proc/1/mountinfo",
            "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/vda rw\n40 22 0:30 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw\n",
        ),
        (
            "/etc/systemd/system/multi-user.target.wants/sshd.service",
            "",
        ),
        (
            "/sys/fs/cgroup/system.slice/sshd.service/cgroup.procs",
            "812\n",
        ),
        ("/sys/fs/cgroup/system.slice/idle.service/cgroup.procs", ""),
        (
            "/etc/login.defs",
            "PASS_MAX_DAYS 99999\n#PASS_MIN_DAYS 7\nENCRYPT_METHOD SHA512\nUMASK 022\n",
        ),
        (
            "/etc/security/pwquality.conf",
            "# minlen = 9\nminlen = 12\ndcredit = -1\n",
        ),
        (
            "/etc/security/pwquality.conf.d/50-site.conf",
            "minlen = 14\n",
        ),
        ("/etc/security/faillock.conf", "deny = 5\neven_deny_root\n"),
        (
            "/etc/pam.d/system-auth",
            "auth required pam_faillock.so preauth\npassword requisite pam_pwquality.so\n",
        ),
        (
            "/proc/modules",
            "xfs 2101248 1 - Live 0x0\ncramfs 40960 0 - Live 0x0\n",
        ),
        (
            "/etc/modprobe.d/cis.conf",
            "install cramfs /bin/false\nblacklist usb-storage\n",
        ),
        (
            "/proc/cmdline",
            "BOOT_IMAGE=/vmlinuz root=/dev/vda audit=1 rd.luks.key=/secret.key ds=nocloud;s=http://x/?token=abc\n",
        ),
        (
            "/etc/audit/auditd.conf",
            "max_log_file = 8\nmax_log_file_action = ROTATE\n",
        ),
        (
            "/etc/audit/rules.d/audit.rules",
            "-D\n-w /etc/passwd -p wa -k identity\n-e 2\n",
        ),
        ("/sys/fs/selinux/enforce", "1"),
        ("/etc/crontab", ""),
    ] {
        write(&root, path, contents);
    }
    root
}

fn facts(root: &Path) -> BTreeMap<String, FactValue> {
    collect_hardening(root)
        .facts
        .into_iter()
        .map(|f| (f.key.as_str().to_owned(), f.value))
        .collect()
}

#[test]
fn a_full_host_gives_exactly_the_catalog_with_its_types() {
    let catalog: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/vectors/fact-catalog.json"
        ))
        .expect("the protocol submodule holds the fact catalog (P19)"),
    )
    .unwrap();
    let expected: BTreeMap<String, String> = catalog["facts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["collector"] == "hardening")
        .map(|f| {
            (
                f["key"].as_str().unwrap().to_owned(),
                f["type"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let root = host("full");
    let got = facts(&root);
    for (key, value) in &got {
        let kind = match value {
            FactValue::Boolean(_) => "bool",
            FactValue::Integer(_) => "int",
            FactValue::String(_) => "string",
            FactValue::StringList(_) => "string_list",
        };
        assert_eq!(
            expected.get(key).map(String::as_str),
            Some(kind),
            "{key} is not in the catalog as {kind}"
        );
    }
    // sysctls a kernel lacks are left out; everything else is always there.
    let missing: Vec<_> = expected
        .keys()
        .filter(|k| !got.contains_key(*k) && !k.starts_with("sysctl."))
        .collect();
    assert!(missing.is_empty(), "not emitted: {missing:?}");
    assert!(
        collect_hardening(&root).errors.is_empty(),
        "{:?}",
        collect_hardening(&root).errors
    );
}

#[test]
fn values_are_read_as_the_daemons_read_them() {
    let got = facts(&host("values"));
    let s = |k: &str| match &got[k] {
        FactValue::String(v) => v.clone(),
        other => panic!("{k}: {other:?}"),
    };
    let i = |k: &str| match &got[k] {
        FactValue::Integer(v) => *v,
        other => panic!("{k}: {other:?}"),
    };
    let l = |k: &str| match &got[k] {
        FactValue::StringList(v) => v.clone(),
        other => panic!("{k}: {other:?}"),
    };
    // sshd: the include comes first and its value wins; *.rpmnew is not
    // matched; Match settings are not merged; "1m" is not a plain number.
    assert_eq!(s("sshd.permitrootlogin"), "no");
    assert_eq!(s("sshd.x11forwarding"), "no");
    assert_eq!(s("sshd.passwordauthentication"), "");
    assert_eq!(i("sshd.maxauthtries"), 4);
    assert_eq!(i("sshd.logingracetime"), -1);
    assert_eq!(i("sshd.clientaliveinterval"), -1);
    assert_eq!(i("sshd.match_blocks"), 1);
    assert_eq!(s("os.id"), "almalinux");
    assert_eq!(l("os.id_like"), ["almalinux", "centos", "fedora", "rhel"]);
    assert_eq!(i("sysctl.net.ipv4.ip_forward"), 0);
    assert!(
        !got.contains_key("sysctl.kernel.kptr_restrict"),
        "absent setting left out"
    );
    assert_eq!(
        got["sysctl.kernel.core_pattern_pipe"],
        FactValue::Boolean(true)
    );
    assert_eq!(l("accounts.uid0"), ["root", "toor"]);
    assert_eq!(l("accounts.shell_users"), ["games"]);
    assert_eq!(l("accounts.empty_password"), ["nopass"]);
    assert_eq!(i("accounts.uid0.count"), 2);
    assert_eq!(i("accounts.shell_users.count"), 1);
    assert_eq!(i("accounts.empty_password.count"), 1);
    assert_eq!(got["mount.tmp.separate"], FactValue::Boolean(true));
    assert_eq!(l("mount.tmp.options"), ["nodev", "nosuid", "rw"]);
    assert_eq!(l("mount.var_tmp.options"), ["relatime", "rw"], "held by /");
    assert_eq!(got["file.etc_crontab.exists"], FactValue::Boolean(true));
    assert_eq!(s("file.etc_motd.mode"), "");
    assert_eq!(l("service.enabled"), ["sshd.service"]);
    assert_eq!(l("service.active"), ["sshd.service"]);
    assert_eq!(i("login_defs.pass_max_days"), 99999);
    assert_eq!(i("login_defs.pass_min_days"), -1, "commented out");
    assert_eq!(s("login_defs.encrypt_method"), "SHA512");
    assert_eq!(i("pam.pwquality.minlen"), 14, "conf.d wins");
    assert_eq!(i("pam.pwquality.dcredit"), -1);
    assert_eq!(i("pam.faillock.deny"), 5);
    assert_eq!(got["pam.faillock.even_deny_root"], FactValue::Boolean(true));
    assert_eq!(l("pam.modules"), ["pam_faillock.so", "pam_pwquality.so"]);
    assert_eq!(l("kernel.modules.disabled"), ["cramfs", "usb_storage"]);
    assert_eq!(
        l("kernel.cmdline.args"),
        ["audit=1"],
        "only listed security parameters, never keys or tokens"
    );
    assert_eq!(s("auditd.max_log_file_action"), "rotate");
    assert_eq!(i("auditd.max_log_file"), 8);
    assert_eq!(l("audit.rules.keys"), ["identity"]);
    assert_eq!(got["audit.rules.immutable"], FactValue::Boolean(true));
    assert_eq!(s("lsm.selinux"), "enforcing");
    assert_eq!(s("lsm.apparmor"), "disabled");
}

#[test]
fn an_unreadable_source_gives_no_facts_and_one_error() {
    let root = host("missing");
    fs::remove_file(root.join("etc/ssh/sshd_config")).unwrap();
    fs::remove_dir_all(root.join("etc/audit")).unwrap();
    let hardening = collect_hardening(&root);
    assert!(
        !hardening
            .facts
            .iter()
            .any(|f| f.key.as_str().starts_with("sshd."))
    );
    assert!(
        !hardening
            .facts
            .iter()
            .any(|f| f.key.as_str().starts_with("audit"))
    );
    let sources: Vec<_> = hardening
        .errors
        .iter()
        .map(|e| e.collector.as_str())
        .collect();
    assert_eq!(sources, ["hardening.sshd", "hardening.auditd"]);
}

#[test]
fn sshd_is_all_or_nothing_and_match_ends_with_its_include() {
    let root = host("sshd");
    // An include that opens a Match block: it ends with that file, so the
    // main file's later settings are global again.
    write(
        &root,
        "/etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication \"no\" # quoted, commented\n",
    );
    write(
        &root,
        "/etc/ssh/sshd_config.d/50-site.conf",
        "Match User backup\n  PermitRootLogin yes\n",
    );
    let got = facts(&root);
    assert_eq!(
        got["sshd.passwordauthentication"],
        FactValue::String("no".into())
    );
    assert_eq!(
        got["sshd.permitrootlogin"],
        FactValue::String(String::new())
    );
    assert_eq!(got["sshd.match_blocks"], FactValue::Integer(1));
    // An include that cannot be read: no sshd facts at all, one error.
    // (Skipped when run as root, which reads it anyway.)
    use std::os::unix::fs::PermissionsExt;
    let file = root.join("etc/ssh/sshd_config.d/50-site.conf");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&file).is_err() {
        let hardening = collect_hardening(&root);
        assert!(
            !hardening
                .facts
                .iter()
                .any(|f| f.key.as_str().starts_with("sshd."))
        );
        assert!(
            hardening
                .errors
                .iter()
                .any(|e| e.collector.as_str() == "hardening.sshd")
        );
    }
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn of_stacked_mounts_the_latest_one_counts() {
    let root = host("stacked");
    write(
        &root,
        "/proc/1/mountinfo",
        "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/vda rw\n40 22 0:30 / /tmp rw,nosuid,nodev,noexec shared:2 - tmpfs tmpfs rw\n41 40 0:31 / /tmp rw,relatime shared:3 - tmpfs tmpfs rw\n",
    );
    let got = facts(&root);
    assert_eq!(
        got["mount.tmp.options"],
        FactValue::StringList(vec!["relatime".into(), "rw".into()]),
        "the later /tmp mount hides the noexec one"
    );
}
