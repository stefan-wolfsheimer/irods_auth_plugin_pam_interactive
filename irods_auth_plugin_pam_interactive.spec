Name:           %{packagename}
Version:        %{version}
Release:        %{release}
Summary:        PAM auth plugin for iRODS

License:        GPLv3+
Source0:        %{packagename}-%{version}.tar.gz
%define debug_package %{nil}

%description
PAM auth plugin for iRODS

%prep
%setup -q

%build
/opt/irods-externals/cmake3.11.4-0/bin/cmake -D IRODS_VERSION=${IRODS_VERSION} .
make

%install
mkdir -p %{buildroot}/usr/lib/irods/plugins/auth/
mkdir -p %{buildroot}/usr/sbin/
install -m 755 libpam_interactive_client.so %{buildroot}/usr/lib/irods/plugins/auth/libpam_interactive_client.so
install -m 755 libpam_interactive_server.so %{buildroot}/usr/lib/irods/plugins/auth/libpam_interactive_server.so
install -m 755 pam_handshake_auth_check %{buildroot}/usr/sbin/pam_handshake_auth_check


%files
/usr/lib/irods/plugins/auth/libpam_interactive_client.so
/usr/lib/irods/plugins/auth/libpam_interactive_server.so
/usr/sbin/pam_handshake_auth_check

%post

%changelog
* Mon Jul 29 2020 Stefan Wolfsheimer <stefan.wolfsheimer@surf.nl> - develop
- initial development branch
