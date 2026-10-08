#!/usr/bin/env bash
# The eBPF reader on real kernels (the five-kernel check of the eBPF
# watcher plan, Task 6). For each lab system: boots a bare VM, runs the
# ignored test `process_events::ebpf::tests::lab_starts_match_proc` as root
# while it starts known processes (as the user, on the first and last CPU,
# as root, with 100 kB and 10 kB arguments), saves the output to
# target/ebpf-lab/NAME.txt and takes the VM down. Read each file: every
# START line shows `cmdline_match=true`, except the 100 kB one
# (`truncated=true`, the program keeps the first 64 KiB).
#
# Usage: scripts/ebpf-lab-check.sh [NAME...]   (default: fedora debian ubuntu alma arch)
#   OPENVIBES_LAB  the openvibes-lab checkout (default: beside this repository)
#   VCPUS          resize each VM to this many vCPUs first (2 checks the per-CPU path)
# Needs the libvirt group (the lab's `up` and `down` run under `sg libvirt`).
# Every connection goes through `./lab ssh`, which offers only the lab key
# (-o IdentitiesOnly=yes -o IdentityAgent=none): no agent key, no desktop
# prompt per connection.
set -euo pipefail
cd "$(dirname "$0")/.."
lab_dir=$(realpath "${OPENVIBES_LAB:-../openvibes-lab}")
out=$PWD/target/ebpf-lab
mkdir -p "$out"
[[ $# -gt 0 ]] || set -- fedora debian ubuntu alma arch

bin=$(cargo test --locked -p openvibes-collectors --features ebpf --lib --no-run --message-format=json |
    jq -r 'select(.executable != null) | .executable')
[[ -x $bin ]] || { echo "no test binary" >&2; exit 1; }

lab() { (cd "$lab_dir" && sg libvirt -c "./lab $*"); }
trap 'lab down >/dev/null 2>&1 || true' EXIT

for name in "$@"; do
    # One VM at a time: wait for the memory a guest needs.
    for _ in $(seq 180); do
        (($(awk '/MemAvailable/ { print int($2 / 1024) }' /proc/meminfo) >= 5300)) && break
        sleep 10
    done
    lab up --bare "$name" | tail -2
    [[ -z ${VCPUS:-} ]] || lab resize "$name" 1024 "$VCPUS" | tail -2
    "$lab_dir/lab" ssh "$name" 'cat > t && chmod +x t' <"$bin"
    "$lab_dir/lab" ssh "$name" 'cat > run.sh' <<'RUN'
T=process_events::ebpf::tests::lab_starts_match_proc
echo "== kernel $(uname -r) cpus=$(nproc) possible=$(cat /sys/devices/system/cpu/possible) id -u=$(id -u)"
sudo ./t --ignored --exact $T --nocapture > out.txt 2>&1 &
sleep 4
for i in 1 2 3; do sh -c 'sleep 1' & P=$!; sleep 0.3; ps -o pid,ppid,uid,euid,args -p $P | tail -1; wait $P; done
for c in 0 $(($(nproc)-1)); do taskset -c $c sh -c 'sleep 1' & P=$!; sleep 0.3; echo "cpu$c:"; ps -o pid,ppid,uid,euid,psr,args -p $P | tail -1; wait $P; done
sudo sh -c 'sleep 1' & P=$!; sleep 0.3; ps -o pid,ppid,uid,euid,args -C sleep | tail -2; wait $P
sleep 1 "$(head -c 100000 /dev/zero | tr '\0' 0)"; echo "big rc=$?"
sleep 1 "$(head -c 10000 /dev/zero | tr '\0' 0)"; echo "10k rc=$?"
wait
echo "== test output"; grep -v '^$' out.txt | cut -c1-400
RUN
    LAB_SSH_TIMEOUT=280 "$lab_dir/lab" ssh "$name" 'sh run.sh' >"$out/$name.txt" 2>&1 || true
    lab down | tail -1
    echo "$name: $(grep -c 'cmdline_match=true' "$out/$name.txt") matched, $(grep -c 'cmdline_match=false' "$out/$name.txt") not ($out/$name.txt)"
done
