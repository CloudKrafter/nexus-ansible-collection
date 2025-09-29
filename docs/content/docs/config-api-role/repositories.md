---
title: Repositories
weight: 21
---

Repositories can be defined in two formats: `config_api` format or `nexus_oss` format.
For compatibility reasons you can use and mix BOTH formats when using the the `config_api` role since it will map, transform and normalize the body before sending it to the Nexus API.

If you use the `nexus_oss` role for creating, updating or deleting repositories, use the `nexus_oss` format.

{{< callout type="info" >}}
We do recommend to adopt the `config_api` format where possible. This format will be passed to the Nexus API **as-is**. Meaning if a new attribute is added to the Nexus API, you can simply use it by adding it to your repo definition, without updating or modifying this role.
{{< /callout >}}

## Examples of formats

{{< tabs items="mixed format,config_api,nexus_oss" >}}
  {{< tab >}}

  ```yaml {linenos=table,hl_lines=[5,15],linenostart=1,filename="group_vars/all.yml"}
  # Mixed formats
  nexus_repos_docker_hosted:
    - name: docker-hosted
      online: true
      blob_store: default # nexus_oss format
      storage:
        strictContentTypeValidation: true
      cleanup:
        policyNames:
          - docker_cleanup_weekly
          - docker_cleanup_unused
      docker:
        httpPort: 5000
        v1Enabled: false
      force_basic_auth: true # nexus_oss format

    # Mixed formats can be used within the dictionary as well

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
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  - name: docker-hosted
    online: true
    storage:
      blobStoreName: default
      strictContentTypeValidation: true
    cleanup:
      policyNames:
        - docker_cleanup_weekly
        - docker_cleanup_unused
    docker:
      httpPort: 5000
      v1Enabled: false
      forceBasicAuth: true
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
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

## Repository Defaults

You can extend the repository defaults for specific types, formats or simply all repos that have the same attributes.

{{< callout type="info" >}}
  Defaults will be overwritten in the following order:

- Global defaults (overwrite nothing)
- Type defaults (overwrite Global defaults)
- Format defaults (overwrite Type defaults)
- Repo specific attributes (overwrite ALL of the above)

{{< /callout >}}

### Global Defaults

By default all repositories are `online` and have their `blobstore` set to `default` and have the `strictContentTypeValidation` set to `true`.

You may add more defaults, just make sure it's in the `config_api` format.

```yaml {filename="group_vars/all.yml"}
nexus_repos_global_defaults:
  online: true
  storage:
    blobStoreName: default
    strictContentTypeValidation: true
```

### Type Defaults

```yaml {linenos=table,hl_lines=[2,22,30],linenostart=1,filename="group_vars/all.yml"}
nexus_repos_type_defaults:
  # Defaults for all proxy repos
  proxy:
    cleanup:
      policyNames: []
    httpClient:
      blocked: false
      autoBlock: true
      connection:
        retries: 0
        timeout: # Left blank on purpose to use the http global value
        enableCircularRedirects: false
        enableCookies: false
        useTrustStore: false
      authentication: # Left blank on purpose to return null for the API
    proxy:
      contentMaxAge: -1
      metadataMaxAge: 1440
    negativeCache:
      enabled: true
      timeToLive: 1440
  # Defaults for all hosted repos
  hosted:
    storage:
      writePolicy: allow_once
    component:
      proprietaryComponents: false
    cleanup:
      policyNames: []
  # Defaults for all group repos
  group:
    group:
      memberNames: []
```

You may add more defaults, just make sure it's in the `config_api` format.

### Format Defaults

```yaml {linenos=table,hl_lines=[2,10,14,25,29,35,39,43,47,51,55,59,63,67,76,82,88,92],linenostart=1,filename="group_vars/all.yml"}
nexus_repos_format_defaults:
  # maven defaults
  maven:
    storage:
      blobStoreName: "{{ nexus_blob_names.mvn.blob | default('default') }}"
    maven:
      versionPolicy: RELEASE
      layoutPolicy: STRICT
      contentDisposition: ATTACHMENT
  # pypi defaults
  pypi:
    storage:
      blobStoreName: "{{ nexus_blob_names.pypi.blob | default('default') }}"
  # docker defaults
  docker:
    storage:
      blobStoreName: "{{ nexus_blob_names.docker.blob | default('default') }}"
    docker:
      forceBasicAuth: true
      v1Enabled: false
    dockerProxy:
      indexType: HUB
      cacheForeignLayers: false
      foreignLayerUrlWhitelist: []
  # rubygems defaults
  rubygems:
    storage:
      blobStoreName: "{{ nexus_blob_names.rubygems.blob | default('default') }}"
  # nuget defaults
  nuget:
    storage:
      blobStoreName: "{{ nexus_blob_names.nuget.blob | default('default') }}"
    nugetProxy:
      nugetVersion: V3
  # gitlfs defaults
  gitlfs:
    storage:
      blobStoreName: "{{ nexus_blob_names.gitlfs.blob | default('default') }}"
  # helm defaults
  helm:
    storage:
      blobStoreName: "{{ nexus_blob_names.helm.blob | default('default') }}"
  # p2 defaults
  p2:
    storage:
      blobStoreName: "{{ nexus_blob_names.p2.blob | default('default') }}"
  # conda defaults
  conda:
    storage:
      blobStoreName: "{{ nexus_blob_names.conda.blob | default('default') }}"
  # go defaults
  go:
    storage:
      blobStoreName: "{{ nexus_blob_names.go.blob | default('default') }}"
  # cocoapods defaults
  cocoapods:
    storage:
      blobStoreName: "{{ nexus_blob_names.cocoapods.blob | default('default') }}"
  # r defaults
  r:
    storage:
      blobStoreName: "{{ nexus_blob_names.r.blob | default('default') }}"
  # cargo defaults
  cargo:
    storage:
      blobStoreName: "{{ nexus_blob_names.cargo.blob | default('default') }}"
  # apt defaults
  apt:
    storage:
      blobStoreName: "{{ nexus_blob_names.apt.blob | default('default') }}"
    apt:
      distribution: bionic
      flat: false
    aptSigning:
      keypair: test-keypair
  # yum defaults
  yum:
    storage:
      blobStoreName: "{{ nexus_blob_names.yum.blob | default('default') }}"
    yum:
      repodataDepth: 0
  # raw defaults
  raw:
    storage:
      blobStoreName: "{{ nexus_blob_names.raw.blob | default('default') }}"
    raw:
      contentDisposition: ATTACHMENT
  # npm defaults
  npm:
    storage:
      blobStoreName: "{{ nexus_blob_names.npm.blob | default('default') }}"
  # conan defaults
  conan:
    storage:
      blobStoreName: "{{ nexus_blob_names.conan.blob | default('default') }}"
  ```

These defaults may be extended as well in the `config_api` format.

## Enabling Repositories

By default all repository types and formats will be configured.
Change the value to `false` to disable the processing, creation, updating or deleting of a specific format.

Formats that have been set to `false` will NOT be deleted. It simply skips any task for that format, including the delete task.

```yaml {filename="group_vars/all.yml"}
nexus_config_maven: true
nexus_config_docker: true
nexus_config_gitlfs: true
nexus_config_npm: true
nexus_config_pypi: true
nexus_config_conda: true
nexus_config_helm: true
nexus_config_r: true
nexus_config_nuget: true
nexus_config_apt: true
nexus_config_yum: true
nexus_config_raw: true
nexus_config_p2: true
nexus_config_cocoapods: true
nexus_config_conan: true
nexus_config_go: true
nexus_config_cargo: true
nexus_config_rubygems: true
```

## APT

### APT Hosted

{{< tabs items="config_api,nexus_oss, mixed format" >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_hosted:
    # Minimal definition of a repo
    - name: minimal-apt-hosted

    # Only define needed attributes
    - name: apt-hosted
      cleanup:
        policyNames:
          - apt_cleanup_weekly
          - apt_cleanup_unused

    # Pretty much all attributes defined
    - name: full-apt-hosted
      online: true
      storage:
        blobStoreName: default
        strictContentTypeValidation: true
        writePolicy: ALLOW
      cleanup:
        policyNames:
          - apt_cleanup_config_api
          - apt_cleanup_nexus_oss
      component:
        proprietaryComponents: true
      aptSigning:
        keypair: keypair-apt
        passphrase: passphrase-apt
      apt:
        distribution: bionic
        flat: true
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_hosted:
    # Minimal definition of a repo
    - name: minimal-apt-hosted
      blob_store: default
      strict_content_validation: true

    # Only define needed attributes
    - name: apt-hosted
      cleanup_policies:
        - apt_cleanup_nexus_oss
        - apt_cleanup_config_api

    # Pretty much all attributes defined
    - name: full-apt-hosted
      blob_store: blobstore-apt
      strict_content_validation: true
      cleanup_policies:
        - apt_cleanup_nexus_oss
        - apt_cleanup_config_api
      write_policy: ALLOW
      proprietary_components: true
      keypair: keypair-apt
      passphrase: passphrase-apt
      distribution: bionic
      flat: true
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_hosted:
    # Mixed format within one repo definition
    - name: mixed-format-apt-hosted
      blob_store: legacy-blobstore-complete
      storage:
        strictContentTypeValidation: false
      cleanup_policies:
        - apt_cleanup_nexus_oss

    # Mixed formats can be used within the parent too

    # config_api format
    - name: apt-hosted
      cleanup:
        policyNames:
          - apt_cleanup_weekly
          - apt_cleanup_unused

    # nexus_oss format
    - name: apt-hosted
      cleanup_policies:
        - apt_cleanup_nexus_oss
        - apt_cleanup_config_api
  ```

  {{< /tab >}}
{{< /tabs >}}

### APT Proxy

{{< tabs items="config_api,nexus_oss, mixed format" >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_proxy:
  - name: new-format-minimal-apt-proxy
    proxy:
      remoteUrl: https://repo.apt.com/pkgs/main

  - name: new-format-cleanup-reverse-order-apt-proxy
    cleanup:
      policyNames:
        - apt_cleanup_config_api
        - apt_cleanup_nexus_oss
    remote_url: https://repo.apt.com/pkgs/main

  - name: full-new-format-apt-proxy
    online: true
    storage:
      blobStoreName: default
      strictContentTypeValidation: true
    cleanup:
      policyNames:
        - apt_cleanup_config_api
        - apt_cleanup_nexus_oss
    proxy:
      remoteUrl: https://repo.apt.com/pkgs/main
      contentMaxAge: 1440
      metadataMaxAge: 1440
    negativeCache:
      enabled: true
      timeToLive: 1440
    httpClient:
      blocked: false
      autoBlock: true
      connection:
        useTrustStore: true
        retries: 3
        timeout: 60
        userAgentSuffix: "Nexus/3.20.1-01 (OSS)"
        enableCircularRedirects: true
        enableCookies: true
      authentication:
        type: username
        username: "full-auth-user"
        password: "full-auth-pass"
    routingRule: routing-rule-allow-all
    apt:
      distribution: bionic
      flat: false

  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_proxy:
    # Minimal definition of a repo
    - name: legacy-format-minimal-apt-proxy
      remote_url: https://repo.apt.com/pkgs/main

    # Only define needed attributes
    - name: legacy-format-cleanup-apt-proxy
      cleanup_policies:
        - apt_cleanup_nexus_oss
        - apt_cleanup_config_api
      remote_url: https://repo.apt.com/pkgs/main

    # Pretty much all attributes defined
    - name: full-legacy-format-apt-proxy
      blob_store: legacy-minimal-blobstore
      strict_content_validation: true
      cleanup_policies:
        - apt_cleanup_config_api
        - apt_cleanup_nexus_oss
      remote_url: https://repo.apt.com/pkgs/main
      maximum_component_age: 1440
      maximum_metadata_age: 1440
      negative_cache_enabled: true
      negative_cache_ttl: 1440
      blocked: false
      auto_block: true
      use_trust_store: true
      connection_retries: 3
      connection_timeout: 60
      user_agent_suffix: "Nexus/3.20.1-01 (OSS)"
      enable_circular_redirects: true
      enable_cookies: true
      remote_username: "full-auth-user"
      remote_password: "full-auth-pass"
      ntlm_domain: "full-ntlm-domain"
      ntlm_host: "full-ntlm-host"
      routing_rules: routing-rule-allow-all
      distribution: bionic
      flat: false
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  nexus_repos_apt_proxy:
    # Mixed format within one repo definition
  - name: mixed-format-apt-proxy
    blob_store: legacy-minimal-blobstore
    storage:
      strictContentTypeValidation: false
    cleanup_policies:
      - apt_cleanup_nexus_oss
    remote_url: https://repo.apt.com/pkgs/main

    # Mixed formats can be used within the parent too

    # config_api format
    - name: apt-proxy
      cleanup:
        policyNames:
          - apt_cleanup_weekly
          - apt_cleanup_unused

    # nexus_oss format
    - name: legacy-format-cleanup-apt-proxy
      cleanup_policies:
        - apt_cleanup_nexus_oss
        - apt_cleanup_config_api
      remote_url: https://repo.apt.com/pkgs/main
  ```

  {{< /tab >}}
{{< /tabs >}}

## Docker

### Docker Hosted

{{< tabs items="config_api,nexus_oss" >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
  - name: full-new-format-docker-hosted
    online: true
    storage:
      blobStoreName: default
      strictContentTypeValidation: true
    cleanup:
      policyNames:
        - docker_cleanup_config_api
        - docker_cleanup_nexus_oss
    docker:
      httpPort: 5000
      v1Enabled: false
      forceBasicAuth: true
  ```

  {{< /tab >}}
  {{< tab >}}

  ```yaml {filename="group_vars/all.yml"}
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
