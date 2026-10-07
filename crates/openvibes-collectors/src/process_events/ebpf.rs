//! The eBPF exec program (`ebpf/openvibes-agent-ebpf`), built by this
//! crate's `build.rs` with feature `ebpf`. Loading and reading it is the
//! eBPF watcher's; the record layout is in that crate's `src/record.rs`.

/// The compiled object (ELF, `bpfel`), 8-byte aligned as aya needs.
pub static OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/openvibes-agent-ebpf"));

#[cfg(test)]
mod tests {
    use super::OBJECT;

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
}
