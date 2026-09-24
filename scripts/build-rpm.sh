#!/usr/bin/env bash
# Builds target/rpm/RPMS/x86_64/openvibes-agent-*.rpm. OV_VERSION overrides
# the package version (tests build an upgrade from the same code).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --locked -p openvibes-agent
version=${OV_VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
rpmbuild -bb packaging/rpm/openvibes-agent.spec \
    --define "_topdir $PWD/target/rpm" --define "_sourcedir $PWD" \
    --define "ov_version $version" >&2
ls target/rpm/RPMS/*/openvibes-agent-"$version"-*.rpm
