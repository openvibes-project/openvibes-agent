//! Struct field offsets from the running kernel's BTF
//! (`/sys/kernel/btf/vmlinux`), for the eBPF program's globals.
//!
//! aya-obj keeps its BTF accessors private, so this is a small reader of
//! the format (docs.kernel.org/bpf/btf.html), bounds-checked throughout:
//! a malformed blob is refused, never a panic. It reads only what the
//! offsets need: type headers, struct/union members, typedefs, strings.
//!
//! It also finds the attach typedef's id ([`typedef_id`]) and writes the
//! small BTF aya needs to attach ([`attach_only`]), so aya never parses the
//! whole kernel BTF (about 50 MB of heap at peak, much of it kept resident
//! by the allocator afterwards).

/// Byte offsets the eBPF program reads at (names as its globals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    /// `task_struct.real_parent`.
    pub task_real_parent: u32,
    /// `task_struct.tgid`.
    pub task_tgid: u32,
    /// `task_struct.mm`.
    pub task_mm: u32,
    /// `task_struct.cred`.
    pub task_cred: u32,
    /// `mm_struct.arg_start` (inside an anonymous struct).
    pub mm_arg_start: u32,
    /// `mm_struct.arg_end`.
    pub mm_arg_end: u32,
    /// `cred.uid` plus `kuid_t.val`.
    pub cred_uid: u32,
    /// `cred.euid` plus `kuid_t.val`.
    pub cred_euid: u32,
    /// `linux_binprm.filename`.
    pub binprm_filename: u32,
}

impl Offsets {
    /// `(global name, value)` for `EbpfLoader::override_global`.
    pub fn globals(&self) -> [(&'static str, u32); 9] {
        [
            ("TASK_REAL_PARENT", self.task_real_parent),
            ("TASK_TGID", self.task_tgid),
            ("TASK_MM", self.task_mm),
            ("TASK_CRED", self.task_cred),
            ("MM_ARG_START", self.mm_arg_start),
            ("MM_ARG_END", self.mm_arg_end),
            ("CRED_UID", self.cred_uid),
            ("CRED_EUID", self.cred_euid),
            ("BINPRM_FILENAME", self.binprm_filename),
        ]
    }
}

/// What the BTF lacks: a struct (`task_struct`), a field
/// (`mm_struct.arg_start`), or `BTF` when the blob itself is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingField(pub &'static str);

/// From the running kernel's BTF; `Err` names the missing struct or field.
pub fn offsets_from_btf(btf: &[u8]) -> Result<Offsets, MissingField> {
    let b = Btf::parse(btf).ok_or(MissingField("BTF"))?;
    let at = |st: &'static str, field: &str, label: &'static str| {
        let s = b.struct_named(st).ok_or(MissingField(st))?;
        b.member_bits(s, field, 0)
            .map(|bits| bits / 8)
            .ok_or(MissingField(label))
    };
    Ok(Offsets {
        task_real_parent: at("task_struct", "real_parent", "task_struct.real_parent")?,
        task_tgid: at("task_struct", "tgid", "task_struct.tgid")?,
        task_mm: at("task_struct", "mm", "task_struct.mm")?,
        task_cred: at("task_struct", "cred", "task_struct.cred")?,
        mm_arg_start: at("mm_struct", "arg_start", "mm_struct.arg_start")?,
        mm_arg_end: at("mm_struct", "arg_end", "mm_struct.arg_end")?,
        cred_uid: at("cred", "uid", "cred.uid")?,
        cred_euid: at("cred", "euid", "cred.euid")?,
        binprm_filename: at("linux_binprm", "filename", "linux_binprm.filename")?,
    })
    .and_then(|mut o| {
        // `uid`/`euid` are `kuid_t`, a typedef of `struct { val }`.
        let kuid = b
            .typedef_target("kuid_t")
            .and_then(|t| b.member_bits(t, "val", 0))
            .map(|bits| bits / 8)
            .ok_or(MissingField("kuid_t.val"))?;
        o.cred_uid += kuid;
        o.cred_euid += kuid;
        Ok(o)
    })
}

/// The id of the typedef `name` in this BTF (`btf_trace_sched_process_exec`,
/// what a BTF tracepoint attaches by); `None` when absent or malformed.
pub fn typedef_id(btf: &[u8], name: &str) -> Option<u32> {
    let b = Btf::parse(btf)?;
    let i = b.at.iter().position(
        |&p| matches!(b.head(p), Some((n, TYPEDEF, _, _, _)) if b.name(n) == Some(name.as_bytes())),
    )?;
    u32::try_from(i + 1).ok()
}

/// A BTF blob whose type `id` is the typedef `name` (of `void`), every type
/// before it a nameless `PTR` stub: all aya reads when attaching a BTF
/// tracepoint (its id by name). The kernel never sees it (the attach id
/// refers to the kernel's own BTF). `id` is at least 1.
pub fn attach_only(id: u32, name: &str) -> Vec<u8> {
    let stubs = id.saturating_sub(1) as usize;
    let types_len = (stubs + 1) * 12;
    let strs_len = name.len() + 2;
    let mut b = Vec::with_capacity(24 + types_len + strs_len);
    b.extend_from_slice(&0xEB9Fu16.to_ne_bytes());
    b.extend_from_slice(&[1, 0]); // version, flags
    // ponytail: lengths fit u32 for any real kernel (ids < 2^24).
    let (types_len, strs_len) = (types_len as u32, strs_len as u32);
    for w in [24, 0, types_len, types_len, strs_len] {
        b.extend_from_slice(&u32::to_ne_bytes(w));
    }
    for _ in 0..stubs {
        for w in [0, PTR << 24, 0] {
            b.extend_from_slice(&u32::to_ne_bytes(w));
        }
    }
    for w in [1, TYPEDEF << 24, 0] {
        b.extend_from_slice(&u32::to_ne_bytes(w));
    }
    b.push(0);
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    b
}

const PTR: u32 = 2;
const STRUCT: u32 = 4;
const UNION: u32 = 5;
const TYPEDEF: u32 = 8;
/// Anonymous members nest this deep at most (the kernel needs 2); also
/// stops a self-referencing blob.
const MAX_DEPTH: u32 = 8;

struct Btf<'a> {
    types: &'a [u8],
    strs: &'a [u8],
    /// Byte position of each type in `types`; type id `n` is `at[n - 1]`.
    at: Vec<usize>,
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn section(b: &[u8], hdr: usize, off: usize, len: usize) -> Option<&[u8]> {
    let start = hdr.checked_add(off)?;
    b.get(start..start.checked_add(len)?)
}

impl<'a> Btf<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        if u16::from_ne_bytes(b.get(0..2)?.try_into().ok()?) != 0xEB9F {
            return None;
        }
        let hdr = word(b, 4)? as usize;
        let types = section(b, hdr, word(b, 8)? as usize, word(b, 12)? as usize)?;
        let strs = section(b, hdr, word(b, 16)? as usize, word(b, 20)? as usize)?;
        let mut at = Vec::new();
        let mut p = 0;
        while p < types.len() {
            let info = word(types, p + 4)?;
            let vlen = (info & 0xffff) as usize;
            let extra = match (info >> 24) & 0x1f {
                1 | 14 | 17 => 4,             // INT, VAR, DECL_TAG
                3 => 12,                      // ARRAY
                4 | 5 | 15 | 19 => 12 * vlen, // STRUCT, UNION, DATASEC, ENUM64
                6 | 13 => 8 * vlen,           // ENUM, FUNC_PROTO
                _ => 0,
            };
            at.push(p);
            p += 12 + extra;
        }
        // The last type must end inside the section.
        (p == types.len()).then_some(Self { types, strs, at })
    }

    fn name(&self, off: u32) -> Option<&[u8]> {
        let r = self.strs.get(off as usize..)?;
        r.get(..r.iter().position(|&c| c == 0)?)
    }

    /// `(name_off, kind, kind_flag, vlen, size_or_type)` of the type at `p`.
    fn head(&self, p: usize) -> Option<(u32, u32, bool, usize, u32)> {
        let info = word(self.types, p + 4)?;
        Some((
            word(self.types, p)?,
            (info >> 24) & 0x1f,
            info >> 31 == 1,
            (info & 0xffff) as usize,
            word(self.types, p + 8)?,
        ))
    }

    /// The struct with this name that has members (skips forward duplicates).
    fn struct_named(&self, name: &str) -> Option<usize> {
        self.at.iter().copied().find(|&p| {
            matches!(self.head(p), Some((n, STRUCT, _, vlen, _))
                if vlen > 0 && self.name(n) == Some(name.as_bytes()))
        })
    }

    /// The type a typedef names (`kuid_t` -> `struct { val }`).
    fn typedef_target(&self, name: &str) -> Option<usize> {
        self.at.iter().find_map(|&p| match self.head(p)? {
            (n, TYPEDEF, _, _, ty) if self.name(n) == Some(name.as_bytes()) => self.by_id(ty),
            _ => None,
        })
    }

    fn by_id(&self, id: u32) -> Option<usize> {
        self.at.get((id as usize).checked_sub(1)?).copied()
    }

    /// Bit offset of `field` in the struct/union at `p`, searching anonymous
    /// struct/union members and adding their offsets on the way.
    fn member_bits(&self, p: usize, field: &str, depth: u32) -> Option<u32> {
        let (_, kind, kflag, vlen, _) = self.head(p)?;
        if !matches!(kind, STRUCT | UNION) || depth > MAX_DEPTH {
            return None;
        }
        (0..vlen).find_map(|i| {
            let q = p + 12 + i * 12;
            let (name, ty, off) = (
                word(self.types, q)?,
                word(self.types, q + 4)?,
                word(self.types, q + 8)?,
            );
            // With kind_flag the top byte is a bitfield size.
            let bits = if kflag { off & 0xff_ffff } else { off };
            if name != 0 {
                return (self.name(name)? == field.as_bytes()).then_some(bits);
            }
            bits.checked_add(self.member_bits(self.by_id(ty)?, field, depth + 1)?)
        })
    }
}
