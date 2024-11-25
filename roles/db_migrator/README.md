db_migrator
=========

Ansible role to migrate Nexus Repository Manager database

Requirements
------------

This role has been tested with Nexus Repository Manager OSS and Pro version 3.73 and higher.
To make this role work out-of-the-box you have to provide the following values first:
- `nexus_protocol:`
- `nexus_hostname:`
- `nexus_port:`
- `nexus_admin_username:`
- `nexus_admin_password:`

If you want to enable the Pro features, please note that you have to provide your own license.
If your Nexus instance is already running on the Pro version, you can leave the `nexus_enable_pro` set to false.

Role Variables
--------------

<!-- A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well. -->

### defaults file for nexus3-config-as-code
nexus_protocol: http
nexus_hostname: localhost
nexus_port: 8081
nexus_admin_username: admin
nexus_admin_password: changeme
nexus_enable_pro: false

nexus_repos_cleanup_policies: []

nexus_config_maven: true

__nexus_repos_maven_hosted_defaults:
  online: true
  format: maven2
  type: hosted
  storage:
    blobStoreName: default
    strictContentTypeValidation: false
    writePolicy: allow_once
  cleanup:
    policyNames: []
  component:
    proprietaryComponents: false
  maven:
    versionPolicy: MIXED
    layoutPolicy: STRICT
    contentDisposition: INLINE

__nexus_repos_maven_proxy_defaults:
  format: maven2
  type: proxy
  online: true
  storage:
    blobStoreName: default
    strictContentTypeValidation: true
  cleanup:
    policyNames: []
  proxy:
    remoteUrl: https://remote.repository.com
    contentMaxAge: 1440
    metadataMaxAge: 1440
  negativeCache:
    enabled: true
    timeToLive: 1440
  httpClient:
    blocked: false
    autoBlock: true
    connection:
      retries: 0
      userAgentSuffix: string
      timeout: 60
      enableCircularRedirects: false
      enableCookies: false
      useTrustStore: false
    # authentication:
    #   type:
    #   username:
    #   preemptive:
    #   ntlmHost:
    #   ntlmDomain:
  routingRule:
  replication:
  maven:
    versionPolicy: MIXED
    layoutPolicy: STRICT
    contentDisposition: ATTACHMENT

nexus_repos_maven_hosted: []

nexus_repos_maven_proxy: []

nexus_repos_maven_group: []

nexus_routing_rules: []

If you set `nexus_enable_pro` to `true`, you must provide a base64 encoded license file

Either by setting the `NEXUS_LICENSE_B64` environment variable or by providing the base64 encoded license string directly below.
`nexus_license_b64: <your Nexus .lic license file encoded into a base64 string>`


Dependencies
------------
No dependencies

Example Playbook
----------------
This role will be executed against the Nexus API only. It does not make any changes to your target, so we can run this playbook from localhost, given the fact the machine you're running this on, is able to establish a connection to your Nexus instance.

```yaml
- name: Configure Nexus
  hosts: localhost
  gather_facts: true
  roles:
    - role: nexus3-config-as-code
```

License
-------

GNUv3

Author Information
------------------

[CloudKrafter](https://github.com/CloudKrafter)

Special thanks to [Oliver Clavel](https://github.com/zeitounator) who created the popular [Nexus3-OSS Ansible role](https://github.com/ansible-ThoTeam/nexus3-oss) where this project is inspired and partially based upon.
