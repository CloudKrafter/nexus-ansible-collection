---
title: Default variables
weight: 2
---

```yaml {filename="roles/config_api/defaults/main.yml"}
nexus_api_scheme: http
nexus_api_hostname: localhost
nexus_api_port: 8081
nexus_api_validate_certs: "{{ nexus_api_scheme == 'https' }}"
nexus_api_timeout: 60
nexus_admin_username: admin
nexus_admin_password: changeme
nexus_enable_pro_version: false
nexus_config_dry_run: false
nexus_ssl_truststore: []
ldap_connections: []
nexus_security_realms:
  - NexusAuthenticatingRealm

nexus_blobstores:
  - name: default
    type: File
    path: default
    softQuota:
      type: spaceRemainingQuota
      limit: 104857600 # 100Mb

nexus_repos_cleanup_policies: []

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

nexus_repos_rubygems_hosted: []

nexus_repos_rubygems_proxy: []

nexus_repos_rubygems_group: []

nexus_repos_cargo_hosted: []

nexus_repos_cargo_proxy: []

nexus_repos_cargo_group: []

nexus_repos_go_proxy: []

nexus_repos_go_group: []

nexus_repos_conan_hosted: []

nexus_repos_conan_proxy: []

nexus_repos_cocoapods_proxy: []

nexus_repos_p2_proxy: []

nexus_repos_raw_hosted: []

nexus_repos_raw_proxy: []

nexus_repos_raw_group: []

nexus_repos_yum_hosted: []

nexus_repos_yum_proxy: []

nexus_repos_yum_group: []

nexus_repos_apt_hosted: []

nexus_repos_apt_proxy: []

nexus_repos_r_hosted: []

nexus_repos_r_proxy: []

nexus_repos_r_group: []

nexus_repos_helm_hosted: []

nexus_repos_helm_proxy: []

nexus_repos_conda_proxy: []

nexus_repos_pypi_hosted: []

nexus_repos_pypi_proxy: []

nexus_repos_pypi_group: []

nexus_repos_npm_hosted: []

nexus_repos_npm_proxy: []

nexus_repos_npm_group: []

nexus_repos_gitlfs_hosted: []

nexus_repos_docker_hosted: []

nexus_repos_docker_proxy: []

nexus_repos_docker_group: []

nexus_repos_maven_hosted: []

nexus_repos_maven_proxy: []

nexus_repos_maven_group: []

nexus_repos_routing_rules: []

nexus_default_user_password: changeme
nexus_local_users: []

nexus_license_b64: "<your Nexus .lic license file encoded into a base64 string>"

nexus_user_tokens_capability:
  enabled: true
  protectContent: true
  expirationEnabled: true
  expirationDays: 30

nexus_anonymous_access:
  enabled: false
  userId: anonymous
  realmName: NexusAuthorizingRealm

nexus_roles:
  - id: "nx-admin"
    name: "nx-admin"
    description: "Administrator Role"
    privileges:
      - "nx-all"
    roles: []
  - id: "nx-anonymous"
    name: "nx-anonymous"
    description: "Anonymous Role"
    privileges:
      - "nx-healthcheck-read"
      - "nx-search-read"
      - "nx-repository-view-*-*-read"
      - "nx-repository-view-*-*-browse"
    roles: []

nexus_content_selectors: []

# Global Defaults
nexus_repos_global_defaults:
  online: true
  storage:
    blobStoreName: default
    strictContentTypeValidation: true

# Type-Specific Defaults
nexus_repos_type_defaults:
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
  hosted:
    storage:
      writePolicy: allow_once
    component:
      proprietaryComponents: false
    cleanup:
      policyNames: []
  group:
    group:
      memberNames: []

# Format-Specific Defaults
nexus_repos_format_defaults:
  maven:
    storage:
      blobStoreName: "{{ nexus_blob_names.mvn.blob | default('default') }}"
    maven:
      versionPolicy: RELEASE
      layoutPolicy: STRICT
      contentDisposition: ATTACHMENT
  pypi:
    storage:
      blobStoreName: "{{ nexus_blob_names.pypi.blob | default('default') }}"
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
  rubygems:
    storage:
      blobStoreName: "{{ nexus_blob_names.rubygems.blob | default('default') }}"
    yum:
      repodataDepth: 0
  nuget:
    storage:
      blobStoreName: "{{ nexus_blob_names.nuget.blob | default('default') }}"
    nugetProxy:
      nugetVersion: V3
  gitlfs:
    storage:
      blobStoreName: "{{ nexus_blob_names.gitlfs.blob | default('default') }}"
  helm:
    storage:
      blobStoreName: "{{ nexus_blob_names.helm.blob | default('default') }}"
  p2:
    storage:
      blobStoreName: "{{ nexus_blob_names.p2.blob | default('default') }}"
  conda:
    storage:
      blobStoreName: "{{ nexus_blob_names.conda.blob | default('default') }}"
  go:
    storage:
      blobStoreName: "{{ nexus_blob_names.go.blob | default('default') }}"
  cocoapods:
    storage:
      blobStoreName: "{{ nexus_blob_names.cocoapods.blob | default('default') }}"
  r:
    storage:
      blobStoreName: "{{ nexus_blob_names.r.blob | default('default') }}"
  cargo:
    storage:
      blobStoreName: "{{ nexus_blob_names.cargo.blob | default('default') }}"
  apt:
    storage:
      blobStoreName: "{{ nexus_blob_names.apt.blob | default('default') }}"
    apt:
      distribution: bionic
      flat: false
    aptSigning:
      keypair: test-keypair
  yum:
    storage:
      blobStoreName: "{{ nexus_blob_names.yum.blob | default('default') }}"
    yum:
      repodataDepth: 0
  raw:
    storage:
      blobStoreName: "{{ nexus_blob_names.raw.blob | default('default') }}"
    raw:
      contentDisposition: ATTACHMENT
  npm:
    storage:
      blobStoreName: "{{ nexus_blob_names.npm.blob | default('default') }}"
  conan:
    storage:
      blobStoreName: "{{ nexus_blob_names.conan.blob | default('default') }}"

legacy_field_map:
  blob_store: "storage.blobStoreName"
  strict_content_validation: "storage.strictContentTypeValidation"
  maximum_metadata_age: "proxy.metadataMaxAge"
  maximum_component_age: "proxy.contentMaxAge"
  negative_cache_enabled: "negativeCache.enabled"
  negative_cache_ttl: "negativeCache.timeToLive"
  remote_username: "httpClient.authentication.username"
  remote_password: "httpClient.authentication.password"
  layout_policy: "maven.layoutPolicy"
  version_policy: "maven.versionPolicy"
  content_disposition:
    maven:
      hosted: "maven.contentDisposition"
      proxy: "maven.contentDisposition"
    raw:
      hosted: "raw.contentDisposition"
      proxy: "raw.contentDisposition"
      group: "raw.contentDisposition"
  write_policy: "storage.writePolicy"
  remote_url: "proxy.remoteUrl"
  proprietary_components: "component.proprietaryComponents"
  cleanup_policies: "cleanup.policyNames"
  member_repos: "group.memberNames"
  writable_member_repo: "group.writableMember"
  http_port: "docker.httpPort"
  https_port: "docker.httpsPort"
  sub_domain: "docker.subdomain"
  v1_enabled: "docker.v1Enabled"
  force_basic_auth: "docker.forceBasicAuth"
  index_type: "dockerProxy.indexType"
  index_url: "dockerProxy.indexUrl"
  allow_redeploy_latest: "docker.latestPolicy"
  cache_foreign_layers: "dockerProxy.cacheForeignLayers"
  use_nexus_certificates_to_access_index: "dockerProxy.useTrustStoreForIndexAccess"
  foreign_layer_url_whitelist: "dockerProxy.foreignLayerUrlWhitelist"
  nuget_version: "nugetProxy.nugetVersion"
  query_cache_item_max_age: "nugetProxy.queryCacheItemMaxAge"
  connection_retries: "httpClient.connection.retries"
  connection_timeout: "httpClient.connection.timeout"
  enable_cookies: "httpClient.connection.enableCookies"
  enable_circular_redirects: "httpClient.connection.enableCircularRedirects"
  user_agent_suffix: "httpClient.connection.userAgentSuffix"
  use_trust_store: "httpClient.connection.useTrustStore"
  auto_block: "httpClient.autoBlock"
  blocked: "httpClient.blocked"
  routing_rules: "routingRule"
  remote_auth_type: "httpClient.authentication.type"
  ntlm_domain: "httpClient.authentication.ntlmDomain"
  ntlm_host: "httpClient.authentication.ntlmHost"
  preemptive: "httpClient.authentication.preemptive"
  bearerToken: "httpClient.authentication.bearerToken"
  conan_version: "conanProxy.conanVersion"
  deploy_policy: "yum.deployPolicy"
  repodata_depth: "yum.repodataDepth"
  passphrase:
    yum:
      proxy: "yumSigning.passphrase"
      group: "yumSigning.passphrase"
    apt:
      hosted: "aptSigning.passphrase"
  keypair:
    yum:
      proxy: "yumSigning.keypair"
      group: "yumSigning.keypair"
    apt:
      hosted: "aptSigning.keypair"
  distribution: "apt.distribution"
  flat: "apt.flat"
  remove_quarantined:
    pypi:
      proxy: "pypi.removeQuarantined"
    npm:
      proxy: "npm.removeQuarantined"
```
