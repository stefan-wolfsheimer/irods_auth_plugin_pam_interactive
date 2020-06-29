# irods_auth_plugin_pam_interactive

## Installation

1. Install iRODS 4.2.7 or 4.2.8 for CentOS

2. Install yum-plugin-priorities

```
yum install yum-plugin-priorities
```
(see https://wiki.centos.org/PackageManagement/Yum/Priorities)

3. Configure surf yum repository
```
sudo vi /etc/yum.repos.d/surf-irods.repo
```

**4.2.7**
```
[SURF]
name=SURF
baseurl=https://artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing-Public/Centos/7/irods-4.2.7/master
enabled=1
gpgcheck=0
priority=90
#Optional - if you have GPG signing keys installed, use the below flags to verify the repository metadata signature:
#gpgkey=artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing-Public/7/irods-4.2.7/master/repomd.xml.key
#repo_gpgcheck=1
```

**4.2.8**
```
[SURF]
name=SURF
baseurl=https://artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing-Public/Centos/7/irods-4.2.8/master
enabled=1
gpgcheck=0
priority=90
#Optional - if you have GPG signing keys installed, use the below flags to verify the repository metadata signature:
#gpgkey=artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing-Public/7/irods-4.2.8/master/repomd.xml.key
#repo_gpgcheck=1
```

4. Update icommands

```
update irods-icommands
```

5. Install additional packages

```
yum install python-pam-module \
            pam-handshake \
            irods_auth_plugin_pam_interactive
```

