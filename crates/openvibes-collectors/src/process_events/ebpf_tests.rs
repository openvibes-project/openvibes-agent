use super::record::{
    ARG_BYTES, ARGS_LEN_AT, ARGS_TRUNCATED_AT, EUID_AT, HEADER_BYTES, KTIME_NS_AT, PATH_BYTES,
    PATH_LEN_AT, PID_AT, PPID_AT, UID_AT,
};
use super::*;
use crate::process_events::EVENT_ARG_BYTES;

#[test]
fn the_object_is_an_ebpf_elf_with_the_exec_program() {
    assert!(OBJECT.starts_with(b"\x7fELF"));
    // e_machine (bytes 18..20, little-endian) is EM_BPF (247).
    assert_eq!(OBJECT.get(18..20), Some(&247u16.to_le_bytes()[..]));
    assert!(
        OBJECT
            .windows(b"tp_btf/sched_process_exec".len())
            .any(|w| w == b"tp_btf/sched_process_exec")
    );
}

// ---- decode ----

/// A record as the program writes it, field by field (no casting).
fn record(pid: u32, ppid: u32, path: &[u8], args: &[u8], truncated: bool) -> Vec<u8> {
    let mut r = vec![0u8; HEADER_BYTES];
    let mut put = |at: usize, v: u32| r[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    put(PID_AT, pid);
    put(PPID_AT, ppid);
    put(UID_AT, 33);
    put(EUID_AT, 0);
    put(PATH_LEN_AT, u32::try_from(path.len()).unwrap());
    put(ARGS_LEN_AT, u32::try_from(args.len()).unwrap());
    r[KTIME_NS_AT..KTIME_NS_AT + 8].copy_from_slice(&1u64.to_ne_bytes());
    r[ARGS_TRUNCATED_AT] = u8::from(truncated);
    r.extend_from_slice(path);
    r.extend_from_slice(args);
    r
}

#[test]
fn decodes_exe_args_and_ids() {
    let s = decode(
        &record(10, 1, b"/usr/bin/sh\0", b"sh\0-c\0sleep 1\0", false),
        5,
    )
    .unwrap();
    assert_eq!((s.pid, s.ppid, s.uid, s.euid), (10, 1, 33, 0));
    assert_eq!(s.exe, b"/usr/bin/sh");
    assert_eq!(
        s.args,
        [b"sh".to_vec(), b"-c".to_vec(), b"sleep 1".to_vec()]
    );
    assert!(!s.args_truncated);
    assert_eq!(s.at_unix_ms, 5);
    assert_eq!((s.cwd, s.parent), (None, None));
}

#[test]
fn empty_argv_is_no_args() {
    assert!(
        decode(&record(10, 1, b"/x\0", b"", false), 5)
            .unwrap()
            .args
            .is_empty()
    );
}

#[test]
fn empty_arguments_inside_argv_are_kept() {
    let s = decode(&record(10, 1, b"/x\0", b"a\0\0b\0", false), 5).unwrap();
    assert_eq!(s.args, [b"a".to_vec(), Vec::new(), b"b".to_vec()]);
}

#[test]
fn truncated_args_keep_the_flag_and_the_last_piece() {
    let long = vec![b'a'; ARG_BYTES];
    let s = decode(&record(10, 1, b"/x\0", &long, true), 5).unwrap();
    assert!(s.args_truncated);
    assert_eq!(s.args, [long]);
}

#[test]
fn lengths_beyond_the_data_are_clamped() {
    // path_len far beyond the record: the path takes what is there, no args.
    let mut b = record(10, 1, b"/x\0", b"a\0", false);
    b[PATH_LEN_AT..PATH_LEN_AT + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
    let s = decode(&b, 5).unwrap();
    assert_eq!(s.exe, b"/x");
    assert!(s.args.is_empty());

    // args_len beyond the record: the args present are kept, marked cut.
    let mut b = record(10, 1, b"/x\0", b"a\0b", false);
    b[ARGS_LEN_AT..ARGS_LEN_AT + 4].copy_from_slice(&1_000u32.to_ne_bytes());
    let s = decode(&b, 5).unwrap();
    assert_eq!(s.args, [b"a".to_vec(), b"b".to_vec()]);
    assert!(s.args_truncated);
}

#[test]
fn lengths_beyond_the_maximums_are_clamped() {
    // A path with no NUL longer than PATH_BYTES: the rest is not path.
    let path = vec![b'p'; PATH_BYTES + 3];
    let s = decode(&record(10, 1, &path, b"", false), 5).unwrap();
    assert_eq!(s.exe.len(), PATH_BYTES);
    let args = vec![b'a'; ARG_BYTES + 3];
    let s = decode(&record(10, 1, b"/x\0", &args, false), 5).unwrap();
    assert_eq!(s.args[0].len(), ARG_BYTES);
    assert!(s.args_truncated);
}

#[test]
fn short_records_are_refused() {
    assert!(decode(&[0; 8], 5).is_none());
    assert!(decode(&[0; HEADER_BYTES - 1], 5).is_none());
    assert!(decode(&[0; HEADER_BYTES], 5).is_some());
}

#[test]
fn arg_limit_matches_the_agent() {
    assert_eq!(ARG_BYTES, EVENT_ARG_BYTES);
}

#[test]
fn the_source_can_move_to_the_forwarder_thread() {
    fn send<T: Send + 'static>() {}
    send::<EbpfStarts>();
}

#[test]
fn ring_overflow_counts_as_overflow() {
    assert!(matches!(lost_since(7, 10), Next::Lost(3)));
    assert!(matches!(lost_since(10, 10), Next::Idle));
    // A counter that went backwards (map recreated) is no loss.
    assert!(matches!(lost_since(10, 2), Next::Idle));
}

// ---- BTF ----

/// Builds a minimal BTF blob: header, type section, string section.
struct Builder {
    types: Vec<u8>,
    strs: Vec<u8>,
    next_id: u32,
}

const INT: u32 = 1;
const STRUCT: u32 = 4;
const UNION: u32 = 5;
const TYPEDEF: u32 = 8;
const PTR: u32 = 2;

impl Builder {
    fn new() -> Self {
        Self {
            types: Vec::new(),
            strs: vec![0],
            next_id: 1,
        }
    }

    fn name(&mut self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let at = u32::try_from(self.strs.len()).unwrap();
        self.strs.extend_from_slice(name.as_bytes());
        self.strs.push(0);
        at
    }

    fn word(&mut self, v: u32) {
        self.types.extend_from_slice(&v.to_ne_bytes());
    }

    fn head(&mut self, name: &str, kind: u32, kflag: bool, vlen: u32, size_or_type: u32) -> u32 {
        let n = self.name(name);
        self.word(n);
        self.word((u32::from(kflag) << 31) | (kind << 24) | vlen);
        self.word(size_or_type);
        self.next_id += 1;
        self.next_id - 1
    }

    fn int(&mut self) -> u32 {
        let id = self.head("unsigned int", INT, false, 0, 4);
        self.word(32);
        id
    }

    fn ptr(&mut self, to: u32) -> u32 {
        self.head("", PTR, false, 0, to)
    }

    /// Struct or union; members are `(name, type, bit offset)`.
    fn aggregate(
        &mut self,
        kind: u32,
        name: &str,
        kflag: bool,
        members: &[(&str, u32, u32)],
    ) -> u32 {
        let vlen = u32::try_from(members.len()).unwrap();
        let id = self.head(name, kind, kflag, vlen, 64);
        for &(m, ty, off) in members {
            let n = self.name(m);
            self.word(n);
            self.word(ty);
            self.word(off);
        }
        id
    }

    fn finish(self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xEB9Fu16.to_ne_bytes());
        b.extend_from_slice(&[1, 0]); // version, flags
        let words = [
            24,
            0,
            u32::try_from(self.types.len()).unwrap(),
            u32::try_from(self.types.len()).unwrap(),
            u32::try_from(self.strs.len()).unwrap(),
        ];
        for w in words {
            b.extend_from_slice(&w.to_ne_bytes());
        }
        b.extend_from_slice(&self.types);
        b.extend_from_slice(&self.strs);
        b
    }
}

/// The kernel shapes the reader must handle: `arg_start` inside an
/// anonymous struct inside an anonymous union, `kuid_t` a typedef of an
/// anonymous struct, a field-less forward duplicate of `task_struct`, a
/// `kind_flag` struct. `with_task` false is the `btf-no-task` case.
fn kernel_like(with_task: bool) -> Vec<u8> {
    let mut b = Builder::new();
    let int = b.int();
    let ptr = b.ptr(int);
    let kuid_inner = b.aggregate(STRUCT, "", false, &[("val", int, 0)]);
    let kuid = b.head("kuid_t", TYPEDEF, false, 0, kuid_inner);
    // A forward declaration first: no members, must be skipped.
    b.aggregate(STRUCT, "task_struct", false, &[]);
    if with_task {
        b.aggregate(
            STRUCT,
            "task_struct",
            false,
            &[
                ("state", int, 0),
                ("tgid", int, 2_432 * 8),
                ("real_parent", ptr, 2_440 * 8),
                ("mm", ptr, 2_048 * 8),
                ("cred", ptr, 3_000 * 8),
            ],
        );
    }
    let args = b.aggregate(
        STRUCT,
        "",
        false,
        &[("arg_start", int, 0), ("arg_end", int, 64)],
    );
    let other = b.aggregate(STRUCT, "", false, &[("unrelated", int, 0)]);
    let u = b.aggregate(UNION, "", false, &[("u_other", other, 0), ("", args, 0)]);
    b.aggregate(
        STRUCT,
        "mm_struct",
        false,
        &[("pgd", ptr, 0), ("", u, 600 * 8)],
    );
    // kind_flag set: bit offsets carry a bitfield size in the top byte.
    b.aggregate(
        STRUCT,
        "cred",
        true,
        &[
            ("usage", int, 32 << 24),
            ("uid", kuid, (32 << 24) | (8 * 8)),
            ("euid", kuid, 24 * 8),
        ],
    );
    b.aggregate(STRUCT, "linux_binprm", false, &[("filename", ptr, 96 * 8)]);
    b.finish()
}

#[test]
fn offsets_add_up_through_anonymous_members() {
    let o = offsets_from_btf(&kernel_like(true)).unwrap();
    assert_eq!(
        (o.task_tgid, o.task_real_parent, o.task_mm, o.task_cred),
        (2_432, 2_440, 2_048, 3_000)
    );
    assert_eq!((o.mm_arg_start, o.mm_arg_end), (600, 608));
    assert_eq!((o.cred_uid, o.cred_euid), (8, 24));
    assert_eq!(o.binprm_filename, 96);
    assert_eq!(o.globals()[0], ("TASK_REAL_PARENT", 2_440));
}

#[test]
fn missing_struct_is_named() {
    assert_eq!(
        offsets_from_btf(&kernel_like(false)).err(),
        Some(MissingField("task_struct"))
    );
}

#[test]
fn missing_field_is_named() {
    let mut b = Builder::new();
    let int = b.int();
    b.aggregate(STRUCT, "task_struct", false, &[("pid", int, 0)]);
    assert_eq!(
        offsets_from_btf(&b.finish()).err(),
        Some(MissingField("task_struct.real_parent"))
    );
}

#[test]
fn malformed_btf_is_refused_without_panic() {
    let good = kernel_like(true);
    assert_eq!(offsets_from_btf(&[]).err(), Some(MissingField("BTF")));
    assert_eq!(
        offsets_from_btf(&good[..30]).err(),
        Some(MissingField("BTF"))
    );
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xff;
    assert_eq!(
        offsets_from_btf(&bad_magic).err(),
        Some(MissingField("BTF"))
    );
    // Every cut of the blob either fails cleanly or parses; never panics.
    for cut in 0..good.len() {
        let _ = offsets_from_btf(&good[..cut]);
    }
    // A member pointing at itself as an anonymous struct must not recurse forever.
    let mut b = Builder::new();
    b.aggregate(STRUCT, "task_struct", false, &[("", 1, 0)]);
    assert!(offsets_from_btf(&b.finish()).is_err());
}

/// The running kernel's own BTF, when there is one (CI runners and the lab
/// have it): every offset is found and the pairs sit where the kernel puts them.
#[test]
fn offsets_from_the_running_kernel() {
    let Ok(btf) = std::fs::read("/sys/kernel/btf/vmlinux") else {
        return;
    };
    let o = offsets_from_btf(&btf).unwrap();
    assert_eq!(o.mm_arg_end, o.mm_arg_start + 8);
    assert!(o.cred_euid > o.cred_uid);
    assert!(o.task_tgid > 0 && o.task_real_parent > o.task_tgid);
}

// ---- error mapping ----

const CAP_ALL: u64 = (1 << 41) - 1;
const NO_CAP_BPF: u64 = CAP_ALL & !(1 << 39);
const LOCKED: &str = "none integrity [confidentiality]\n";
const OPEN: &str = "[none] integrity confidentiality\n";

#[test]
fn eperm_without_cap_bpf_is_capability() {
    assert!(matches!(
        classify(Some(1), "", NO_CAP_BPF, LOCKED, "m".into()),
        EbpfError::Capability
    ));
}

#[test]
fn eperm_under_confidentiality_lockdown_is_lockdown() {
    assert!(matches!(
        classify(Some(1), "", CAP_ALL, LOCKED, "m".into()),
        EbpfError::Lockdown
    ));
}

#[test]
fn other_denials_are_lsm() {
    assert!(matches!(
        classify(Some(1), "", CAP_ALL, OPEN, "m".into()),
        EbpfError::LsmDenied
    ));
    assert!(matches!(
        classify(Some(13), "", CAP_ALL, OPEN, "m".into()),
        EbpfError::LsmDenied
    ));
    // No lockdown file at all.
    assert!(matches!(
        classify(Some(1), "", CAP_ALL, "", "m".into()),
        EbpfError::LsmDenied
    ));
}

#[test]
fn a_verifier_log_is_verifier_with_its_end() {
    let log = format!(
        "{}R2 min value is negative\nprocessed 9 insns\n",
        "0: r1 = r2\n".repeat(2_000)
    );
    let EbpfError::Verifier(kept) = classify(Some(13), &log, CAP_ALL, OPEN, "m".into()) else {
        panic!("not Verifier");
    };
    assert!(kept.contains("R2 min value is negative"));
    assert!(kept.len() <= VERIFIER_KEPT);
}

#[test]
fn anything_else_is_other() {
    let e = classify(Some(7), "", CAP_ALL, OPEN, "E2BIG on SCRATCH".into());
    assert!(matches!(e, EbpfError::Other(m) if m == "E2BIG on SCRATCH"));
    assert!(matches!(
        classify(None, "", CAP_ALL, OPEN, "x".into()),
        EbpfError::Other(_)
    ));
}

#[test]
fn cap_eff_is_read_from_status() {
    assert_eq!(
        cap_eff("Name:\tx\nCapEff:\t000001ffffffffff\n"),
        (1 << 41) - 1
    );
    assert_eq!(cap_eff("Name:\tx\n"), 0);
}

// ---- real kernel (the lab) ----

/// Run as root on a lab machine:
/// `ebpf_tests::lab_starts_match_proc --ignored --nocapture`, while a
/// script runs `sh -c 'sleep 1'`. Prints each start next to `/proc` and
/// fails if a live one disagrees.
#[test]
#[ignore = "needs root and a BTF kernel (the lab)"]
fn lab_starts_match_proc() {
    let mut src = match open_ebpf() {
        Ok(src) => src,
        Err(EbpfError::Verifier(log)) => panic!("open_ebpf: verifier refused:\n{log}"),
        Err(e) => panic!("open_ebpf: {e:?}"),
    };
    println!("loaded and attached");
    let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let (mut seen, mut checked) = (0, 0);
    while std::time::Instant::now() < until {
        let s = match src.next() {
            Next::Start(s) => s,
            Next::Lost(n) => {
                println!("LOST {n}");
                continue;
            }
            _ => continue,
        };
        seen += 1;
        if s.exe.ends_with(b"/sleep") {
            let status =
                std::fs::read_to_string(format!("/proc/{}/status", s.pid)).unwrap_or_default();
            let cmdline = std::fs::read(format!("/proc/{}/cmdline", s.pid)).unwrap_or_default();
            let field = |k: &str| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(|v| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
                    .unwrap_or_default()
            };
            let (ppid, uids) = (field("PPid:"), field("Uid:"));
            let joined: Vec<u8> = s
                .args
                .iter()
                .flat_map(|a| a.iter().copied().chain([0]))
                .collect();
            println!(
                "START pid={} ppid={} uid={} euid={} exe={} args={:?} args_bytes={} truncated={} | proc ppid={ppid:?} uid={uids:?} cmdline_bytes={} cmdline_match={}",
                s.pid,
                s.ppid,
                s.uid,
                s.euid,
                String::from_utf8_lossy(&s.exe),
                s.args
                    .iter()
                    .map(|a| String::from_utf8_lossy(&a[..a.len().min(40)]).into_owned())
                    .collect::<Vec<_>>(),
                joined.len(),
                s.args_truncated,
                cmdline.len(),
                joined == cmdline
            );
            if !cmdline.is_empty() {
                assert_eq!(ppid.first(), Some(&s.ppid.to_string()));
                assert_eq!(uids.first(), Some(&s.uid.to_string()));
                assert_eq!(uids.get(1), Some(&s.euid.to_string()));
                if s.args_truncated {
                    // Cut at ARG_BYTES: a prefix of the real command line.
                    assert!(joined.len() >= ARG_BYTES);
                    assert!(cmdline.starts_with(&joined[..joined.len() - 1]));
                } else {
                    assert_eq!(joined, cmdline);
                }
                checked += 1;
            }
        }
    }
    println!("seen={seen} checked={checked}");
    assert!(checked > 0, "no live sleep start was checked");
}
