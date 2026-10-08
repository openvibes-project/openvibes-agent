#!/usr/bin/env bash
# What feature `ebpf` (default for openvibes-agent) needs to build on Linux:
# the eBPF crate's pinned nightly with rust-src, and bpf-linker's prebuilt
# static binary (`cargo install` needs LLVM dev files). The digest is the
# v0.11.1 release asset's (checked 2026-10-08). BIN is where bpf-linker
# goes (default ~/.cargo/bin; it must be on PATH).
#
# Without rustup (the Fedora RPM jobs build with Fedora's own cargo), rustup
# comes from dnf with no default toolchain and only `rustup` on PATH, so
# the agent still builds with the system cargo; the eBPF build runs through
# `rustup run` (crates/openvibes-collectors/build.rs).
set -euo pipefail
cd "$(dirname "$0")/.."
BPF_LINKER_SHA256=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8
bin=${BIN:-$HOME/.cargo/bin}
if ! command -v rustup >/dev/null; then
    dnf -q -y install rustup zstd
    rustup-init -y -q --profile minimal --default-toolchain none --no-modify-path
    ln -sf "$HOME/.cargo/bin/rustup" /usr/local/bin/rustup
fi
(cd ebpf/openvibes-agent-ebpf && rustup toolchain install)
mkdir -p "$bin"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/bpf-linker.tar.zst" \
    https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst
echo "$BPF_LINKER_SHA256  $tmp/bpf-linker.tar.zst" | sha256sum -c -
tar --zstd -xf "$tmp/bpf-linker.tar.zst" -C "$bin" bpf-linker
"$bin/bpf-linker" --version
