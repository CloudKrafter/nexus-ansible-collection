---
title: Privileges
weight: 14
---

Nexus privileges that are created initially or automatically by Nexus will not be updated or deleted. These roles have a `readOnly: true` attribute.

{{< tabs items="mixed format,config_api,nexus_oss" >}}
  {{< tab >}}
  ```yaml {filename="group_vars/all.yml"}
  # Mixed formats
  nexus_privileges:

    # Mixed format is only for the script_name / scriptName attribute.
    # other attributes are the same for the nexus_oss and config_api role

    - name: script1
      type: script
      description: privileges for script1
      script_name: setup_realms
      actions:
        - all
    - name: script-new-syntax
      type: script
      description: second script
      scriptName: create_task
      actions:
        - all
  ```
  {{< /tab >}}
  {{< tab >}}
  ```yaml {filename="group_vars/all.yml"}
  nexus_privileges:
    - name: all-repos-read
      description: Read & Browse access to all repos
      type: repository-view
      repository: "*"
      format: "*"
      actions:
        - read
        - browse
    - name: wildcard
      type: wildcard
      description: first wilcard
      pattern: nexus:repository-view:yum:*
    - name: application-1
      type: application
      description: priviliges for application-1
      domain: domain
      actions:
        - all
    - name: script-new-syntax
      type: script
      description: second script
      scriptName: create_task
      actions:
        - all
    - name: docker-login-search-all
      type: repository-content-selector
      format: docker
      contentSelector: docker-login-search
      description: Login to and search docker registry
      repository: "*"
      actions:
        - read
    - name: admin-docker-private-team-a-rw
      type: repository-admin
      format: docker
      description: admin write access to team-a namespace on docker-hosted
      repository: docker-private
      actions:
        - read
        - add
        - edit
        - browse
  ```
  {{< /tab >}}
  {{< tab >}}
  ```yaml {filename="group_vars/all.yml"}
  nexus_privileges:
    - name: all-repos-read
      description: Read & Browse access to all repos
      type: repository-view
      repository: "*"
      format: "*"
      actions:
        - read
        - browse
    - name: wildcard
      type: wildcard
      description: first wilcard
      pattern: nexus:repository-view:yum:*
    - name: application-1
      type: application
      description: priviliges for application-1
      domain: domain
      actions:
        - all
    - name: script1
      type: script
      description: privileges for script1
      script_name: setup_realms
      actions:
        - all
    - name: docker-login-search-all
      type: repository-content-selector
      format: docker
      contentSelector: docker-login-search
      description: Login to and search docker registry
      repository: "*"
      actions:
        - read
    - name: admin-docker-private-team-a-rw
      type: repository-admin
      format: docker
      description: admin write access to team-a namespace on docker-hosted
      repository: docker-private
      actions:
        - read
        - add
        - edit
        - browse
  ```
  {{< /tab >}}
{{< /tabs >}}

For some attributes you can set global defaults:
```yaml {filename="group_vars/all.yml"}
_nexus_privilege_defaults:
  type: application
  format: maven2
  actions:
    - read
```
If you define a custom privilege without specifying it's `type` the value `application` will be used.
Same principle applies to `format` and `actions`.

{{< callout emoji="💡" >}}
set `nexus_config_dry_run: true` to see what will be changed, without making any changes to your Nexus instance.
{{< /callout >}}

This config can be applied with the {{< badge content="privileges" type="warning">}} tag. Just keep in mind the content-selectors assigned to your privileges need to be present!
