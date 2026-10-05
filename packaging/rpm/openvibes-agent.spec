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
install -D -m 0640 $S/packaging/rpm/openvibes-agent.rules %{buildroot}%{_sysconfdir}/audit/rules.d/openvibes-agent.rules
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-agent/LICENSE
# The opt-in drop-in for exact port owners (P15): documentation, not enabled.
install -D -m 0644 $S/packaging/rpm/owners.conf %{buildroot}%{_docdir}/openvibes-agent/owners.conf

%post
%systemd_post openvibes-agent.service
# Load the exec audit rule now (P14). augenrules rebuilds the kernel rules
# from /etc/audit/rules.d, so rules added by hand with auditctl are
# replaced; see docs/components/packaging.md.
# Fedora's default audit rules end with `-a task,never`, which stops the
# kernel auditing any program start, so the exec rule could never fire:
# comment it out, unless agent.toml says manage_audit_rules = false.
if ! grep -Eq '^[[:space:]]*manage_audit_rules[[:space:]]*=[[:space:]]*false' %{_sysconfdir}/openvibes-agent/agent.toml 2>/dev/null; then
    for f in %{_sysconfdir}/audit/rules.d/*.rules; do
        [ -f "$f" ] || continue
        sed -i -E 's/^([[:space:]]*-a[[:space:]]+(task,never|never,task)([[:space:]].*)?)$/# disabled by openvibes-agent (exec alarms need it off): \1/' "$f"
    done
fi
if systemctl -q is-active auditd 2>/dev/null; then augenrules --load >/dev/null 2>&1 || :; fi
%preun
%systemd_preun openvibes-agent.service
%postun
%systemd_postun_with_restart openvibes-agent.service
if [ "$1" -eq 0 ] && systemctl -q is-active auditd 2>/dev/null; then
    augenrules --load >/dev/null 2>&1 || :
fi

%files
%license %{_licensedir}/openvibes-agent/LICENSE
%doc %{_docdir}/openvibes-agent/owners.conf
%{_bindir}/openvibes-agent
%{_unitdir}/openvibes-agent.service
%{_sysusersdir}/openvibes-agent.conf
%dir %attr(0750, root, openvibes_agent) %{_sysconfdir}/openvibes-agent
%config(noreplace) %attr(0640, root, openvibes_agent) %{_sysconfdir}/openvibes-agent/agent.toml
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/audit/rules.d/openvibes-agent.rules

%changelog
* Thu Sep 24 2026 itismelime <26064407+itismelime@users.noreply.github.com> - 0.1.0-1
- First package: hardened systemd service, unprivileged openvibes_agent user.
