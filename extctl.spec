# SPDX-License-Identifier: GPL-3.0-or-later
#
# extctl — distro-independent wrapper over systemd-sysext for signing and
# installing system extensions.
#
# Build with: rpmbuild -bb extctl.spec (from app/)
# Or via ./build-rpm, which drops the result into dist/.

Name:           extctl
Version:        0.1.0
Release:        1%{?dist}
Summary:        Manage systemd-sysext extensions (sign + install)

License:        GPL-3.0-or-later
URL:            https://github.com/OperatorProject/extctl
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo

%description
extctl is a small, distro-independent wrapper around systemd-sysext. It
scaffolds new system extensions (init), signs them with dm-verity (sign),
and verifies + installs them (install), so you don't have to remember the
veritysetup / openssl / install / refresh incantations by hand.

%prep
%autosetup

%build
cargo build --release --locked

%install
install -Dm0755 %{_builddir}/%{name}-%{version}/target/release/extctl \
    %{buildroot}%{_bindir}/extctl

%files
%{_bindir}/extctl

%changelog
* Tue Aug 18 2026 Operator Developers - 0.1.0-1
- Initial release: init, sign, install, status subcommands
