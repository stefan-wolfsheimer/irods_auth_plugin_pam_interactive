Name:           %{packagename}
Version:        %{version}
Release:        %{release}
Summary:        PAM auth plugin for iRODS

License:        GPLv3+
Source0:        %{packagename}-%{version}.tar.gz

# %if ( "%{irodsversion}" == "4.1.11" || "%{irodsversion}" == "4.1.12" )
# %define irods_msi_path /var/lib/irods/plugins/microservices
# %else
# %define irods_msi_path /usr/lib/irods/plugins/microservices
# %endif


# %define libs_dir lib/_%{irodsversion}
# %define irods_config_path /etc/irods
# %define debug_package %{nil}

%description
PAM auth plugin for iRODS

%prep
%setup -q

%build
/opt/irods-externals/cmake3.11.4-0/bin/cmake .
make

%install

# cp server pam_handshake_server
# cp auth_check pam_handshake_auth_check

# mkdir -p %{buildroot}/usr/sbin
# mkdir -p %{buildroot}/etc/systemd/system/
# install -m 755 pam_handshake_server %{buildroot}/usr/sbin
# install -m 755 pam_handshake_auth_check %{buildroot}/usr/sbin
# install -m 755 pam_handshake_start.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_status.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_stop.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_delete.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_post.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_get.sh %{buildroot}/usr/sbin
# install -m 755 pam_handshake_put.sh %{buildroot}/usr/sbin
# install -m 755 pam-handshake.service %{buildroot}/etc/systemd/system/

%files
# /usr/sbin/pam_handshake_server
# /usr/sbin/pam_handshake_auth_check
# /usr/sbin/pam_handshake_start.sh
# /usr/sbin/pam_handshake_status.sh
# /usr/sbin/pam_handshake_stop.sh
# /usr/sbin/pam_handshake_delete.sh
# /usr/sbin/pam_handshake_post.sh
# /usr/sbin/pam_handshake_get.sh
# /usr/sbin/pam_handshake_put.sh
# /etc/systemd/system/pam-handshake.service

%post

%changelog
* Mon Jul 29 2020 Stefan Wolfsheimer <stefan.wolfsheimer@surf.nl> - develop
- initial development branch
