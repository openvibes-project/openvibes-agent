//! With feature `ebpf`, for a Linux target: build the eBPF exec program
//! (`ebpf/openvibes-agent-ebpf`) and leave the object in `OUT_DIR`, where
//! `process_events::ebpf::OBJECT` includes it.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[cfg(feature = "ebpf")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        build_ebpf();
    }
}

#[cfg(feature = "ebpf")]
fn build_ebpf() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ebpf/openvibes-agent-ebpf")
        .canonicalize()
        .expect("ebpf/openvibes-agent-ebpf exists");
    // aya-build runs `cargo build --package` in the current directory, and
    // the eBPF crate is not a workspace member: run it from the crate itself.
    std::env::set_current_dir(&dir).expect("enter the eBPF crate");
    // The crate pins its nightly; `rustup run` needs the name spelled out.
    let toolchain =
        std::fs::read_to_string("rust-toolchain.toml").expect("eBPF rust-toolchain.toml");
    let toolchain = toolchain
        .lines()
        .find_map(|l| l.strip_prefix("channel = \""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("a `channel = \"...\"` line in the eBPF rust-toolchain.toml");
    let package = aya_build::Package {
        name: "openvibes-agent-ebpf",
        root_dir: dir.to_str().expect("UTF-8 path to the eBPF crate"),
        ..Default::default()
    };
    if let Err(e) = aya_build::build_ebpf([package], aya_build::Toolchain::Custom(toolchain)) {
        panic!(
            "building the eBPF program failed (needs `rustup toolchain install \
             {toolchain} --component rust-src` and bpf-linker 0.11.1): {e:#}"
        );
    }
}
