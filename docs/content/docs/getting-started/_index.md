---
title: Getting Started
weight: 1
comments: true
type: docs
---

{{% steps %}}

### Installing the collection

```shell
ansible-galaxy collection install cloudkrafter.nexus
```

### Initial setup and using the nexus_oss role

```yaml  {linenos=table,hl_lines=[3,4,5,6],linenostart=1,filename="playbook.yml"}
- name: Provisioning Playbook (former fork of thoteam/nexus_oss role)
  hosts: all
  collections:
    - cloudkrafter.nexus
  roles:
    - role: cloudkrafter.nexus.nexus_oss
```

### Running desired-state configurations

{{< callout type="warning" >}}
  The `config_api` role uses a different approach to set defaults. If you override the `_nexus_repos_maven_defaults` variable for example, make sure you apply the same defaults to the `nexus_repos_global_defaults`, `nexus_repos_type_defaults` and `nexus_repos_format_defaults` dictionaries! See role defaults for the full dictionaries.
{{< /callout >}}

Once you have a working Nexus instance, you can execute most configuration tasks without rebooting your Nexus instance.

{{< callout type="warning" >}}
The `config_api` role will ensure a desired state. For example repositories not defined in `nexus_repos_*_*` will be **DELETED** in your Nexus instance. If you don't want this, stick with the `nexus_oss` role.
{{< /callout >}}

```yaml  {linenos=table,hl_lines=[6],linenostart=1,filename="playbook.yml"}
- name: Run Desired state config
  hosts: all
  collections:
    - cloudkrafter.nexus
  roles:
    - role: cloudkrafter.nexus.config_api
```

You can also use both roles in one play:

```yaml  {linenos=table,hl_lines=[3,4,5,9,10],linenostart=1,filename="playbook.yml"}
- name: Playbook
  hosts: all
  vars:
    # Disables the creation and modification of assets such as repos using the nexus_oss role
    nexus_run_provisionning: false
  collections:
    - cloudkrafter.nexus
  roles:
    - role: cloudkrafter.nexus.nexus_oss # Still ensuring the Nexus server configs
    - role: cloudkrafter.nexus.config_api # Creating, updating or deleting assets such as LDAP servers
```

### Using tags for an execution strategy

All tasks are tagged to allow certain parts to be executed.

Available tags:

{{< badge "license">}}
{{< badge "security-anonymous-access" >}}
{{< badge "user-tokens" >}}
{{< badge "ssl-truststore" >}}
{{< badge "ldap" >}}
{{< badge "security-realms" >}}
{{< badge "cleanup-policies" >}}
{{< badge "routing-rules" >}}
{{< badge "content-selectors" >}}
{{< badge "blobstores" >}}
{{< badge content="privileges" type="warning">}}
{{< badge content="roles" type="warning">}}
{{< badge content="users" type="warning">}}
{{< badge content="repositories" type="warning">}}
{{< badge content="maven-hosted" type="warning">}}
{{< badge content="maven-proxy" type="warning">}}
{{< badge content="maven" type="warning">}}
{{< badge content="apt-hosted" type="warning">}}
{{< badge content="apt-proxy" type="warning">}}
{{< badge content="apt" type="warning">}}
{{< badge content="cargo-hosted" type="warning">}}
{{< badge content="cargo-proxy" type="warning">}}
{{< badge content="cargo" type="warning">}}
{{< badge content="cocoapods-proxy" type="warning">}}
{{< badge content="cocoapods" type="warning">}}
{{< badge content="conan-hosted" type="warning">}}
{{< badge content="conan-proxy" type="warning">}}
{{< badge content="conan" type="warning">}}
{{< badge content="conda-proxy" type="warning">}}
{{< badge content="conda" type="warning">}}
{{< badge content="docker-hosted" type="warning">}}
{{< badge content="docker-proxy" type="warning">}}
{{< badge content="docker" type="warning">}}
{{< badge content="gitlfs-hosted" type="warning">}}
{{< badge content="gitlfs" type="warning">}}
{{< badge content="go-proxy" type="warning">}}
{{< badge content="go" type="warning">}}
{{< badge content="helm-hosted" type="warning">}}
{{< badge content="helm-proxy" type="warning">}}
{{< badge content="helm" type="warning">}}
{{< badge content="npm-hosted" type="warning">}}
{{< badge content="npm-proxy" type="warning">}}
{{< badge content="npm" type="warning">}}
{{< badge content="nuget-hosted" type="warning">}}
{{< badge content="nuget-proxy" type="warning">}}
{{< badge content="nuget" type="warning">}}
{{< badge content="pypi-hosted" type="warning">}}
{{< badge content="pypi-proxy" type="warning">}}
{{< badge content="pypi" type="warning">}}
{{< badge content="raw-hosted" type="warning">}}
{{< badge content="raw-proxy" type="warning">}}
{{< badge content="raw" type="warning">}}
{{< badge content="r-hosted" type="warning">}}
{{< badge content="r-proxy" type="warning">}}
{{< badge content="r" type="warning">}}
{{< badge content="p2-proxy" type="warning">}}
{{< badge content="p2" type="warning">}}
{{< badge content="rubygems-hosted" type="warning">}}
{{< badge content="rubygems-proxy" type="warning">}}
{{< badge content="rubygems" type="warning">}}
{{< badge content="yum-hosted" type="warning">}}
{{< badge content="yum-proxy" type="warning">}}
{{< badge content="yum" type="warning">}}

{{< callout type="warning" >}}
Yellow tags always depend on another tag, so you'll need to combine them.
For example `--tags="repositories,maven-hosted"` to configure hosted maven repositories only.
or `--tags="roles,users"` to configure roles and users.
{{< /callout >}}

When no tags are specified, all tasks will be executed.

{{< callout type="error" >}}
There are no `*-group` tags! Groups are always depending on either hosted or proxy repos. Therefore group repos can be configured using the format tag of a group, for example `--tags="repositories,maven"`
{{< /callout >}}

### Dry run

Sometimes you want to see what will be changed before proceeding. By setting the `nexus_config_dry_run: true` variable, the role will still show you what would have been changed upon a regular playbook run, without making any changes to your repositories.

To only show changed items in your Ansible logs you can do the following:

```ini {filename="ansible.cfg"}
[defaults]
display_skipped_hosts = false
display_ok_hosts = false
```

or in your terminal session:

```bash
# Only show possible changes
export ANSIBLE_DISPLAY_SKIPPED_HOSTS=false
export ANSIBLE_DISPLAY_OK_HOSTS=false
ansible-playbook -i all playbook.yml -e nexus_config_dry_run=true
```

#### Examples for execution strategies

```bash
# Only configure cleanup policies
ansible-playbook -i all --tags cleanup-policies playbook.yml
```

### [Optional] Enabling Nexus Repository Manager Pro

If you want to enable the Pro features, please note that you have to provide your own license.
If your Nexus instance is already running on the Pro version, you still need the `nexus_enable_pro_version` variable set to be `true`, otherwise the `nexus_enable_pro_version` will default to `false` resulting in disabling Pro features and removing your license, to comply with desired-state principles.

If you set `nexus_enable_pro_version` to `true`, you must provide a base64 encoded license file.

Either by setting the `NEXUS_LICENSE_B64` environment variable on the system that executes your playbook or by providing a base64 encoded license string in your vars.

```yaml {linenos=table ,filename="group_vars/all.yml"}
nexus_enable_pro_version: true
nexus_license_b64: <your Nexus .lic license file encoded into a base64 string>`
```

{{% /steps %}}

## Next

When ready, explore the role capabilities and configurations:

{{< cards >}}
  {{< card link="../config-api-role" title="Config API Role" icon="collection" >}}
  {{< card link="../nexus-oss-role" title="Nexus OSS Role" icon="collection" >}}
{{< /cards >}}
