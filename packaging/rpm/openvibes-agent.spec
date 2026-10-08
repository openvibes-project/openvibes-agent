# Binary packaging: scripts/build-rpm.sh builds the release binary first
# (with rustup, the toolchain pinned in rust-toolchain.toml; CI uses
# Fedora's own cargo); this spec only installs it.
%global debug_package %{nil}

Name:           openvibes-agent
Version:        %{ov_version}
# Release builds use 1; CI builds pass ov_release=1.1.ci<run>, which sorts
# above the published 0.x.y-1 and below the next version, so a test
# install never looks identical to the published package (platform #88).
Release:        %{?ov_release}%{!?ov_release:1}%{?dist}
Summary:        OpenVIBES endpoint agent
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-agent
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

%description
Collects host facts, evaluates signed rules, and delivers findings to the
OpenVIBES platform over mTLS. Runs as the unprivileged openvibes_agent user.

%install
S=%{_sourcedir}
install -D -m 0755 $S/target/release/openvibes-agent %{buildroot}%{_bindir}/openvibes-agent
install -D -m 0644 $S/packaging/rpm/openvibes-agent.service %{buildroot}%{_unitdir}/openvibes-agent.service
install -D -m 0644 $S/packaging/rpm/openvibes-agent.sysusers %{buildroot}%{_sysusersdir}/openvibes-agent.conf
install -D -m 0640 $S/packaging/rpm/agent.toml %{buildroot}%{_sysconfdir}/openvibes-agent/agent.toml
# The exec audit rule is a template: audit-setup copies it into
# /etc/audit/rules.d on fallback hosts only (eBPF hosts get no audit rule).
install -D -m 0644 $S/packaging/rpm/openvibes-agent.rules %{buildroot}%{_datadir}/openvibes-agent/openvibes-agent.rules
install -D -m 0755 $S/packaging/rpm/audit-setup %{buildroot}%{_libexecdir}/openvibes-agent/audit-setup
printf '#!/bin/sh\n# Sets up the kernel-audit fallback for threat alarms (see audit-setup).\nexec %s/openvibes-agent/audit-setup fallback "$@"\n' %{_libexecdir} > %{buildroot}%{_libexecdir}/openvibes-agent/audit-fallback
chmod 0755 %{buildroot}%{_libexecdir}/openvibes-agent/audit-fallback
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-agent/LICENSE
# The opt-in drop-in for exact port owners (P15): documentation, not enabled.
install -D -m 0644 $S/packaging/rpm/owners.conf %{buildroot}%{_docdir}/openvibes-agent/owners.conf

%post
%systemd_post openvibes-agent.service
%preun
# Package erase: give the host its audit rules back while audit-setup exists.
if [ "$1" -eq 0 ]; then %{_libexecdir}/openvibes-agent/audit-setup remove || :; fi
%systemd_preun openvibes-agent.service
%postun
%systemd_postun_with_restart openvibes-agent.service
%posttrans
# After the whole transaction, so the rule file 0.2.5 owned is already erased
# (or renamed .rpmsave when edited) by rpm: set up the audit fallback on a
# fallback host, or undo 0.2.5's changes on an eBPF host (docs/components/packaging.md).
%{_libexecdir}/openvibes-agent/audit-setup apply || :
if [ -e %{_sysconfdir}/audit/rules.d/openvibes-agent.rules.rpmsave ]; then
    echo "openvibes-agent: your edited exec audit rule was saved as %{_sysconfdir}/audit/rules.d/openvibes-agent.rules.rpmsave and no longer loads; this host uses eBPF, or the package sets the rule up itself"
fi

%files
%license %{_licensedir}/openvibes-agent/LICENSE
%doc %{_docdir}/openvibes-agent/owners.conf
%{_bindir}/openvibes-agent
%{_unitdir}/openvibes-agent.service
%{_sysusersdir}/openvibes-agent.conf
%dir %attr(0750, root, openvibes_agent) %{_sysconfdir}/openvibes-agent
%config(noreplace) %attr(0640, root, openvibes_agent) %{_sysconfdir}/openvibes-agent/agent.toml
%{_datadir}/openvibes-agent/openvibes-agent.rules
%dir %{_libexecdir}/openvibes-agent
%{_libexecdir}/openvibes-agent/audit-setup
%{_libexecdir}/openvibes-agent/audit-fallback

%changelog
* Thu Sep 24 2026 itismelime <26064407+itismelime@users.noreply.github.com> - 0.1.0-1
- First package: hardened systemd service, unprivileged openvibes_agent user.
