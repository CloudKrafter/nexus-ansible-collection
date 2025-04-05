# Changelog

## Release notes moved to GitHub Releases

Release notes can be found at: https://github.com/CloudKrafter/nexus-ansible-collection/releases


## [1.21.0] - 2025-03-28

### Changed
- **nexus_oss role** Ensure nexus.rc task is idempotent by @Thulium-Drake in https://github.com/CloudKrafter/nexus-ansible-collection/pull/42

### Added
- **nexus_oss role** Added a task to accept the Nexus Community EULA by @Thulium-Drake in https://github.com/CloudKrafter/nexus-ansible-collection/pull/43
- **nexus_oss role** Added task to configure SSL truststore by @Thulium-Drake in https://github.com/CloudKrafter/nexus-ansible-collection/pull/42
- **module** RAW component module by @brianveltman in https://github.com/CloudKrafter/nexus-ansible-collection/pull/44

### Fixed
- **nexus_oss role** check SSL truststore content before configuring LDAP servers by @Thulium-Drake in https://github.com/CloudKrafter/nexus-ansible-collection/pull/42


## [1.20.0] - 2025-03-21

## BREAKING CHANGE WHEN USING POSTGRES!
Please follow the new instructions at https://github.com/CloudKrafter/nexus-ansible-collection/tree/main/roles/nexus_oss#postgres-database to update your postgres variables.

### Changed
- **nexus_oss role** Ability to define multiple Postgres bouncers when running Nexus in HA.
- **nexus_oss role** Using the `cloudkrafter.nexus.download` module to download the given Nexus version.
- **nexus_oss role** [BREAKING] Using the `nexus_version_file: latest` has been deprecated in favor of the new download mechanism.
- **nexus_oss role** [BREAKING] Using a redirect url such as `https://download.sonatype.com/nexus/3/latest-unix.tar.gz` is no longer supported as `nexus_download_url`.
- **nexus_oss role** unset the `nexus_download_url` variable by default. If you have set it, it will be used.
- **nexus_oss role** Configuring Anonymous Access is now done via the API instead of Groovy scripts.
- **nexus_oss role** Configuring Security Realms is now done via the API instead of Groovy scripts.
- **nexus_oss role** Log4j Visualizer and Bower repos are now only available on Nexus 3.77.2-02 or earlier.

### Added
- **download module** Introduced a Nexus download module to handle downloading the given Nexus version.
- **nexus_oss** Introduced proxy settings for downloading Nexus.
- **download module** Added Ansible Sanity and Unit tests for the python module.

### Fixed
- **nexus_oss role** Downloading latest version of Nexus works again.
- **nexus_oss role** Nexus 3.78.x does not ship with the `nexus.rc` file. We added this file back into the installation directory.

More information on how the new download feature works see: https://github.com/CloudKrafter/nexus-ansible-collection/tree/main/roles/nexus_oss#downloading-nexus


## [1.19.0] - 2025-03-02

### Changed
- **nexus_oss** remove groovy script for privilege setup. Using API now.
- **config_api** Desired state is no longer enforced by default. To maintain backwards compatibility. Set `nexus_enforce_desired_state: true` to enforce desired state again.

### Added
- **config_api** new Molecule scenario introduced to be executed during GHA workflows.

### Fixed
- **nexus_oss** Nexus group now accepts Group ID instead of User ID
- **config_api** Removing license will be skipped when on Community edition.

## [1.18.0] - 2025-02-01
### Added
- **nexus_oss** Adding support for using custom encryption keys

### Fixed
- **config_api** Fixed python filter to enhance LDAP connection normalization
- **nexus_oss** Enhanced Jinja templating for processing repos. Fixes #14 by @caroldx

## [1.17.1] - 2025-01-14
### Changed
- **nexus_oss** Privileges will no longer be created when `nexus_use_api_for_provisioning` is set to `true`. Please use the `config_api` role to manage privileges. See: https://nexus.cloudkrafter.org/docs/config-api-role/privileges/

## [1.17.0] - 2025-01-14
### Added
- **config_api** Added support to create and delete custom privileges

### Changed
- **nexus_oss** Default for privilege 'type' has been changed to `application` to be in line with how privilege defaults are handled in the **config_api** role.
- **config_api** Exclude users that are not in the default source. Nexus API can't manage users in another IAM system.
- **config_api** The anonymous and admin user are defined in `nexus_local_users` by default.

### Fixed
- **config_api** fixed an issue where creating blobstore return wrong status code.

## [1.16.4] - 2024-12-22
### Fixed
- **config_api** Cleanup policies are now idempotent.


## [1.16.3] - 2024-12-16
### Added
- **config_api** Added support for dry-run for the User, Routing Rules, Cleanup Policy, Content Selectors and LDAP tasks.

### Changed
- **config_api** When doing a dry-run, the role will report `changed` if there are differences between the current and desired state, but it will not make changes to your Nexus instance.


## [1.16.2] - 2024-12-15
### Changed
- **config_api** Newly created repos will not be updated in the same run, all attributes are already set during the create operation. Making the role 30% faster.


## [1.16.1] - 2024-12-12
### Fixed
- **config_api** Ensure only roles within the default source are managed by this role. Leaving roles created by Nexus as-is.

## [1.16.0] - 2024-12-10
### Added
- **config_api** Introduced new variable `nexus_config_dry_run` with a default of `false` to control if repos need to be created, updated or deleted. When setting the value to `true` it will only show what will be changed during a regular play.

### Changed
- **nexus_oss** Updated Groovy script to handle contentDisposition for both maven and raw formats (groups, hosted and proxy)
- **config_api** Adjusted contentMaxAge for proxy to 1440 and added it to maven format with a default of -1.

### Fixed
- **config_api** Corrected blob store name for rubygems storage to use 'ruby' instead of 'rubygems'.


## [1.15.0] - 2024-12-10
### Added
- **config_api** Added support for Composer proxy repositories
- **nexus_oss** Added support for Composer proxy repositories
- **config_api** Introduced new variable `nexus_config_dry_run` with a default of `false` to control if repos need to be created, updated or deleted. When setting the value to `true` it will only show what will be changed during a regular play.

### Changed
- **nexus_oss** Cleanup policies will only be created using the API if ALL cleanup policies are in the proper API format and `nexus_enable_pro_version` is `true` since the cleanup API endpoint is a Pro feature.
  However, we do recommend to use the `config_api` role when managing cleanup policies via the API.
- **nexus_oss** Alle repo defaults have been set to `[]`. Meaning the role will not create repositories by default. Might cause unexpected behaviour for users who do not specifiy their default repositories in their group_vars, but it will not delete the repositories.
- **nexus_oss** Updated Groovy script to handle contentDisposition for both maven and raw formats (groups, hosted and proxy)
- **config_api** Adjusted contentMaxAge for proxy to 1440 and added it to maven format with a default of -1.

### Fixed
- **config_api** Corrected blob store name for rubygems storage to use 'ruby' instead of 'rubygems'.


## [1.14.3] - 2024-12-09
### Fixed
- **config_api** Ensure comparision is case-insensitive and uppercase for certain attributes


## [1.14.2] - 2024-12-09
### Added
- **nexus_oss** Check if `nexus_anonymous_access` is boolean
- Published documentation website at https://nexus.cloudkrater.org/docs

### Fixed
- **config_api** Ensure comparision is case-insensitive for certain attributes


## [1.14.1] - 2024-12-07
### Fixed
- **config_api** Fix line breaks in normalize_repositories.py filter

## [1.14.0] - 2024-12-07
### Added
- **config_api** Added support to set and update httpClient.authentication attributes

### Fixed
- **config_api** updating raw.contentDisposition for raw proxy and hosted repos are now idempotent.

## [1.13.0] - 2024-12-06
### Added
- **config_api** Added support to normalize the following repositories types/formats.
  you can now use your
  - `nexus_repos_raw_hosted`, `nexus_repos_raw_proxy`, `nexus_repos_raw_group`
  - `nexus_repos_npm_hosted`, `nexus_repos_npm_proxy`, `nexus_repos_npm_group`
  - `nexus_repos_pypi_hosted`, `nexus_repos_pypi_proxy`, `nexus_repos_pypi_group`
  - `nexus_repos_conan_hosted`, `nexus_repos_conan_proxy`
  - `nexus_repos_yum_hosted`, `nexus_repos_yum_proxy`, `nexus_repos_yum_group`
  - `nexus_repos_apt_hosted`, `nexus_repos_apt_proxy`
  definitions with the `config_api` role without reformatting the dictionary.


## [1.12.1] - 2024-12-05
### Fixed
- **nexus_oss** After introducing `nexus_api_availability_*` variables the role would fail while waiting for Nexus to be started.
  this has been fixed.

## [1.12.0] - 2024-12-04
### Added
- **nexus_oss** Introduced variables to control waiting time for nexus to startup.
  `nexus_api_availability_delay: 10`
  `nexus_api_availability_retries: 30`
- **config_api** Added support to normalize the following repositories types/formats.
  you can now use your
  - `nexus_repos_maven_hosted`, `nexus_repos_maven_proxy`, `nexus_repos_maven_group`
  - `nexus_repos_docker_hosted`, `nexus_repos_docker_proxy`, `nexus_repos_docker_group`
  - `nexus_repos_rubygems_hosted`, `nexus_repos_rubygems_proxy`, `nexus_repos_rubygems_group`
  - `nexus_repos_r_hosted`, `nexus_repos_r_proxy`, `nexus_repos_r_group`
  - `nexus_repos_cargo_hosted`, `nexus_repos_cargo_proxy`, `nexus_repos_cargo_group`
  - `nexus_repos_nuget_hosted`, `nexus_repos_nuget_proxy`, `nexus_repos_nuget_group`
  - `nexus_repos_go_proxy`, `nexus_repos_go_group`
  - `nexus_repos_helm_hosted`, `nexus_repos_helm_proxy`
  - `nexus_repos_gitlfs_hosted`
  - `nexus_repos_conda_proxy`
  - `nexus_repos_p2_proxy`
  and `nexus_repos_cocoapods_proxy` definitions with the `config_api` role without reformatting the dictionary.

#### Important note on repository defaults
The `config_api` role uses a different approach to set defaults. If , for example, you override the `_nexus_repos_maven_defaults` variable, make sure you apply the same defaults to the `nexus_repos_global_defaults`, `nexus_repos_type_defaults` and `nexus_repos_format_defaults` dictionaries! See role defaults for the full dictionaries.

### Fixed
- **config_api** Use defaults from `_nexus_repos_<format>_defaults` for normalizing repos.
- **nexus_oss** Fixed attribute `allow_redeploy_latest` for docker repos

### Changed
- **nexus_oss** Renamed `layout_policy` to `deploy_policy` for yum repos


## [1.11.1] - 2024-12-02

### Changed
- **config_api** Renamed `nexus_hostname` to `nexus_api_hostname` to be compatible with with nexus_oss role

## [1.11.0] - 2024-12-02

### Added
- **nexus_oss** Introduced new option to run in clustered mode. This variable with is default value is `nexus_cluster_enabled: false`.
- **config_api** Nexus license API will always be queried to obtain the license status
  We need this information to determine if we can use API endpoints for pro features

## [1.10.3] - 2024-12-01

### Added
- Introduced `nexus_api_validate_certs` and `nexus_api_timeout` variables.

### Changed
- **config_api** `nexus_protocol` variable has be renamed to `nexus_api_scheme` to be compatible with nexus_oss role.
- **config_api** `nexus_hostname` variable has be renamed to `nexus_api_hostname` to be compatible with nexus_oss role.
- **config_api** `nexus_port` variable has be renamed to `nexus_api_port` to be compatible with nexus_oss role.

## [1.10.2] - 2024-11-30

### Added

- **Config API - Compatibility for Cleanup Policies defined in nexus_oss**
  Cleanup policies defined for the `nexus_oss` role are now fully compatible with the `config_api` role. A new filter automatically normalizes the cleanup policies API payload to the required format.
  **What this means for you:**
  - No changes are needed to your existing `nexus_repos_cleanup_policies` definitions when transitioning to the `config_api` role.
  - Your current configurations will work seamlessly without requiring manual transformation.

- **Config API - Compatibility for Anonymous Access defined in nexus_oss**
  Anonymous Access settings defined for the `nexus_oss` role are now compatible with the `config_api` role. A new filter normalizes the anonymous access API payload to the correct format.
  **What this means for you:**
  - You can continue using your existing `nexus_anonymous_access` definitions.
  - No manual adjustments are required when migrating to the `config_api` role.

- **Config API - Compatibility for Security Realms defined in nexus_oss**
  Security realms configured in the `nexus_oss` role are now automatically mapped and normalized to be compatible with the `config_api` role.
  **What this means for you:**
  - The standalone realm variables (e.g., `nexus_nuget_api_key_realm`, `nexus_npm_bearer_token_realm`) are now supported directly in `config_api`.
  - You do not need to rewrite these variables; the role will handle the transformation automatically.
  - If you define the `nexus_security_realms` with any realm other than `NexusAuthenticatingRealm`, the realms variables of `nexus_oss` will be ignored.

- **Config API - Compatibility for LDAP Connections defined in nexus_oss**
  The `config_api` role now supports LDAP connections defined in the legacy format used by the `nexus_oss` role. A new filter normalizes these connections to the required API-compatible format.
  **What this means for you:**
  - You can continue using the legacy `ldap_connections` format as defined in the `nexus_oss` role.
  - However, it is **recommended** to adopt the new API-compatible format for future configurations to ensure consistency and compatibility with future updates.

- **Config API - Compatibility for Content Selectors defined in nexus_oss**
  The `config_api` role now supports Content Selectors defined in the legacy format used by the `nexus_oss` role. A new filter normalizes these connections to the required API-compatible format.
  **What this means for you:**
  - You can continue using the legacy `nexus_content_selectors` format as defined in the `nexus_oss` role.

- **Config API - Compatibility for Local Nexus Users defined in nexus_oss**
  The `config_api` role now supports Local Nexus Users defined in the legacy format used by the `nexus_oss` role. A new filter normalizes these connections to the required API-compatible format.
  **What this means for you:**
  - You can continue using the legacy `nexus_local_users` format as defined in the `nexus_oss` role.

### Changed
- **config_api** `nexus_enable_pro` variable has be renamed to `nexus_enable_pro_version` to be compatible with nexus_oss role.
- **config_api** `nexus_routing_rules` variable has be renamed to `nexus_repos_routing_rules` to be compatible with nexus_oss role.
- **config_api** `nexus_users` variable has be renamed to `nexus_local_users` to be compatible with nexus_oss role.

---
### Summary of Actions

1. **Transitioning to `config_api`:** If you're currently using the `nexus_oss` role:
   - You **do not need to rewrite** your existing configurations for cleanup policies, anonymous access, content selectors or security realms.
   - All legacy configurations will be normalized automatically.
2. **LDAP Connections:** While legacy LDAP connection definitions are supported, it’s a good opportunity to transition to the new API-compatible format to future-proof your setup.
3. **Security Realms:** Our recommendation is to configure security realms using the `config_api` role and not using the `nexus_oss` role.
4. **Change routing rules variable:** Change `nexus_routing_rules` to `nexus_repos_routing_rules`
5. **Change nexus Pro variable:** Change `nexus_enable_pro` to `nexus_enable_pro_version`

## [1.10.1] - 2024-11-28
### Added
- Nothing added

### Fixed
- plugin filter for nexus_oss role works as expected


## [1.10.0] - 2024-11-27
### Added
- Former nexus3-pro role (based on the ThoTeam/nexus-oss role) has been added to this collection.
Note that this is only temporarily until their features are covered in new roles.

## [1.9.1] - 2024-11-25
### Added
- Molecule Nexus Pro scenario

### Changed
- Removed various debug tasks to clean logging output.

## [v1.9.0] - 2024-11-24
### Added
- Creating, updating and deleting Cargo hosted, proxy and group repos
- Creating, updating and deleting RubyGems hosted, proxy and group repos

**Important:** Role has been migrated to a collection.
`ansible-galaxy collection install cloudkrafter.nexus`

Example how to add it to your playboks:

```yaml
---
- name: Playbook
  hosts: localhost
  gather_facts: true
  collections:
    - cloudkrafter.nexus

  roles:
    - role: cloudkrafter.nexus.nexus_oss # (fork of thoteam/nexus3-oss)
    - role: cloudkrafter.nexus.config_api # Only use this role if you know what you're doing.
```

## [v1.8.0] - 2024-11-21
### Added
- Configuring realms is now available through the `nexus_security_realms` variable. By default only NexusAuthenticatingRealm is enabled.
- Ability to manage SSL certificates in trust store (Adding and deleting)
- Create, update and delete LDAP conigurations


## [v1.7.0] - 2024-11-19
### Added
- Creating and deleting S3, File and Group blob stores. Might work with Azure and Google too, not tested.
- Creating, updating and deleting P2 proxy repos
- Creating, updating and deleting Cocoapods proxy repos
- Creating, updating and deleting Conda proxy repos
- Creating, updating and deleting Helm hosted and proxy repos
- Creating, updating and deleting Conan hosted and proxy repos
- Creating, updating and deleting Go group and proxy repos
- Creating, updating and deleting R hosted, proxy and group repos
- Creating, updating and deleting NuGet hosted, proxy and group repos
- Creating, updating and deleting Yum hosted, proxy and group repos
- Creating, updating and deleting Raw hosted, proxy and group repos
- Creating, updating and deleting APT hosted and proxy repos

### Changed
- **Breaking!** PUT requests to file blobstores are currently not supported, until a better implementation is available


## [v1.6.0] - 2024-11-16
### Added
- Creating, updating and deleting Docker hosted, proxy and group repos
- Creating, updating and deleting GitLFS hosted repos
- Creating, updating and deleting NPM hosted, proxy and group repos
- Creating, updating and deleting PyPi hosted, proxy and group repos

### Fixed
- Unable to set Nexus Trust Store for maven proxy repos. Fixed now :-)

## [v.1.5.0] - 2024-11-15
### Added
- Creating, updating and deleting maven group repositories

## [v.1.4.2] - 2024-11-12
### Added
- Added ansible-lint configuration

### Changed
- repo has been moved to Cloudkrafters GitHub organization
- Role will be published at the Cloudkrafter namespace in Galaxy
- Updated pip requirements

### Fixed
- Podman support for molecule scenario
- Maven repo updates are now idempotent again

## [v.1.4.1] - 2024-11-11
### Added
No features added

### Changed
No existing behaviour has changed

### Fixed
- Refactored code base for maintainability

## [v.1.4.0] - 2024-11-11
### Added
- Added support for File blob stores

## [v1.3.0] - 2024-11-10
### Added
- Added support for Content Selectors API endpoint
- Added support for Security - Anonymous Access API endpoint
- Added support for Roles API endpoint

### Changed
- Each part of the configuration can be ran seperately by specifing its tag. For example `--tags="roles,users,cleanup-policies"`
- moved role to cloudkrafter namespace
- renamed role from nexus_config_as_code to nexus_config_api

### Fixes
- API endpoints that require a pro license will be skipped when `nexus_enable_pro: false` is set.
- License will now be removed properly when `nexus_enable_pro: false` is set.

## [v1.2.0] - 2024-11-09
### Added
- Added support for User Tokens capability API endpoint.

## [v1.1.0] - 2024-11-09
### Added
- Added support for Users API endpoints. You can now create, update and delete users using this role.

## [v1.0.0] - 2024-11-09
Initial release. Support Create, Update and Delete actions for:
- Maven Hosted repositories
- Maven Proxy repositories
- Cleanup Policies
- Routing Rules
- Pro License
