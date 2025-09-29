---
title: Requirements
weight: 1
prev: /docs/getting-started
---

This role has been tested with Nexus Repository Manager OSS and Pro `version 3.73` and higher.
To make this role work out-of-the-box you have to provide the following values first:

```yaml {filename="group_vars/all.yml"}
nexus_api_scheme:
nexus_api_hostname:
nexus_api_port:
nexus_admin_username:
nexus_admin_password:

```

## Compatibility with the `nexus_oss` role

Most of the variables in this role are the same as the variables used in the `nexus_oss` role.
This is intentionally to help facilitating the migration process where the _provisional_ and _configuration_ tasks will be separated.

This role also aims to stick with the API definitions as described in the Nexus API reference.
Meaning the format of all dictionaries, lists, strings etc. will be in line with the API requirements.

To maintain compatibility with the values set previously in the `nexus_oss` role, all payloads to the API will be transformed and mapped accordingly a.k.a normalized.

### New vs. Legacy syntax

Throughout the documentation you will see two different code examples, one with the new syntax, used in the `config_api` role and one with the old syntax, used in the `nexus_oss` role. Both works if you use the `config_api` role, but we do recommend to use the new syntax anywhere you can.

{{< tabs items="config_api,nexus_oss" >}}
  {{< tab >}}

  ```yaml
  - name: docker-hosted
    online: true
    storage:
      blobStoreName: blob-docker
      strictContentTypeValidation: true
    cleanup:
      policyNames:
        - docker_cleanup_weekly
    docker:
      httpPort: 5001
      v1Enabled: false
      forceBasicAuth: true
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml
  - name: docker-hosted
    blob_store: blob-docker
    strict_content_validation: true
    cleanup_policies:
      - docker_cleanup_weekly
    http_port: 5001
    v1_enabled: false
    force_basic_auth: true
  ```

  {{< /tab >}}
{{< /tabs >}}

Eventually the `nexus_oss` role will not be handling tasks to create, update or delete Nexus assets suchs as; repositories, local users, cleanup policies, routing rules, content selectors, security realms, roles, privileges etc.. That will be handled by this role.
