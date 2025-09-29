# Contributing Guide

This project ships with a `.devcontainer` configuration that can be used either locally or within [Github Codespaces](https://docs.github.com/en/codespaces). TLDR; Github Codespaces is basically just a `.devcontainer` hosted on a dedicated cloud server.

The purpose of this devcontainer is to provide you with a out-of-the-box development environment containing the latest Ansible, Molecule and Python tooling.
Additionally the devcontainer comes preconfigured with some useful VS Code extensions for this project. This way we can ensure all contributors have access to the same workspace configurations.

In order to use the devcontainer locally you need to have docker installed on your machine. Otherwise consider [creating a Codespace](https://github.com/codespaces/new).

## Setup

1. Fork the repository on GitHub.
2. Create a new branch on your newly forked repository.
3. Open your new branch within a Codespace, or [run the devcontainer locally from VS Code](https://code.visualstudio.com/docs/devcontainers/containers#_quick-start-open-an-existing-folder-in-a-container).
4. Run molecule create to create all needed containers within your workspace.

    ```bash
    molecule create -s default-rockylinux9
    ```
    This will create the default scenario with the rockylinux9 OS.

    ```bash
    molecule converge -s default-rockylinux9
    ```
    converge will start Nexus inside a container.
    You can access the Nexus UI at https://127.0.0.1:8092.
    The default username is `admin` and the default password is `changeme`.

    If the port number is not working, please take a look at the **PORTS** tab within VS Code to determine which port is used.

    Also make sure you're using HTTPS and not HTTP for the local url.

    When using Codespaces, Nexus will be made available through a unique FQDN url.

## Making Changes

1. Create a new branch for your changes.

2. Make your changes and commit them. Make sure to follow the commit message guidelines.

3. Push your changes to your forked repository.

## Testing

Before submitting a pull request, make sure your changes pass all tests.

```bash
molecule test
```

## Submitting Changes

1. Open a pull request from your forked repository on GitHub.
2. Ensure your pull request adheres to the provided template.
3. Wait for the pull request to be reviewed.
Thank you for your contributions!


## Troubleshooting

When running molecule test, you may encounter the following errors:

```
ConnectionRefusedError: [Errno 61] Connection refused
or
ProtocolError: ('Connection aborted.', ConnectionRefusedError(61, 'Connection refused'))
or
ConnectionError: ('Connection aborted.', ConnectionRefusedError(61, 'Connection refused'))
or
DockerException: Error while fetching server API version: ('Connection aborted.', ConnectionRefusedError(61, 'Connection refused'))

```
This means Docker is not running on your machine.
Make sure Docker is running AND your docker socket is made available through the 'Allow the default Docker socket to be used (requires password)' setting at the advanced settings overview

```
fatal: [nexus3-oss-rockylinux9]: UNREACHABLE! => {"changed": false, "msg": "Failed to create temporary directory. In some cases, you may have been able to authenticate and did not have permissions on the target directory. Consider changing the remote tmp path in ansible.cfg to a path rooted in \"/tmp\", for more error information use -vvv. Failed command was: ( umask 77 && mkdir -p \"` echo ~/.ansible/tmp `\"&& mkdir \"` echo ~/.ansible/tmp/ansible-tmp-1702769993.113389-4129-153610542777930 `\" && echo ansible-tmp-1702769993.113389-4129-153610542777930=\"` echo ~/.ansible/tmp/ansible-tmp-1702769993.113389-4129-153610542777930 `\" ), exited with result 1", "unreachable": true}
```
Do not get fooled with this error. It's UNREACHABLE, meaning the container is not started. Usually its refering to an old container that does not exist anymore.
Try to run `molecule reset` or `molecule destroy --all` first to clean up old references and resources. Then try to run molecule test again.

# Maven Proxy Schema Documentation

## Overview

This documentation outlines the structure and purpose of the schema for normalizing Maven proxy repository configurations. The schema is used to ensure input data (legacy or mixed formats) is transformed into the API-compatible format required by Nexus Repository Manager.

## Schema Structure

```yaml
schemas:
  proxy:  # Top-level key indicating the repository type (e.g., proxy, hosted, group)
    maven:  # Repository format (e.g., maven, docker, npm)
      field_map:
        name: name
        remote_url: proxy.remoteUrl
        blob_store: storage.blobStoreName
        strict_content_validation: storage.strictContentTypeValidation
        maximum_component_age: proxy.contentMaxAge
        maximum_metadata_age: proxy.metadataMaxAge
        negative_cache_enabled: negativeCache.enabled
        negative_cache_ttl: negativeCache.timeToLive
        remote_username: httpClient.authentication.username
        remote_password: httpClient.authentication.password
        layout_policy: maven.layoutPolicy
        version_policy: maven.versionPolicy
      default_values:
        online: true
        type: "proxy"
        storage:
          blobStoreName: "default"
          strictContentTypeValidation: true
        proxy:
          contentMaxAge: 1440
          metadataMaxAge: 1440
        negativeCache:
          enabled: true
          timeToLive: 1440
        httpClient:
          blocked: False
          autoBlock: True
          connection:
            retries: 0
            timeout: 60
            enableCircularRedirects: False
            enableCookies: False
            useTrustStore: False
        maven:
          layoutPolicy: "STRICT"
          versionPolicy: "MIXED"
          contentDisposition: "ATTACHMENT"
      required_fields:
        - storage.blobStoreName
        - storage.strictContentTypeValidation
        - maven
        - type
```

---

## Key Components of the Schema

### `field_map`

**Purpose**:
Maps input attributes (flat or legacy) to their corresponding API-compatible format.

**When to Use**:
- When input attributes need renaming or restructuring.
- To handle legacy formats or flat attributes that need to be transformed into nested structures.

**Example**:
```yaml
field_map:
  remote_url: proxy.remoteUrl  # Maps legacy 'remote_url' to 'proxy.remoteUrl'.
  blob_store: storage.blobStoreName  # Maps 'blob_store' to a nested key in 'storage'.
```
**Behavior**:

If the input contains `remote_url`, its value will be mapped to `proxy.remoteUrl` in the normalized output.
Attributes not present in the input are ignored unless handled by `default_values`.

---
### `default_values`

**Purpose**: Provides sensible defaults for attributes that are often omitted but required by the API.

**When to Use**:

When attributes are mandatory but may not always be provided in the input.
To ensure API compatibility without requiring users to define every attribute.

**Example**:
```yaml
default_values:
  online: true  # Ensures all repositories are online by default.
  type: "proxy"  # Sets the type of repository to 'proxy' as it is mandatory for this schema.
  storage:
    blobStoreName: "default"  # Assigns 'default' blob store if not explicitly provided.
```

**Behavior**:

Defaults are applied **only if the attribute is missing** in the input.
Input values always take precedence over defaults.


---

### `required_fields`

**Purpose**: Validates that all mandatory attributes are present in the final normalized output.

**When to Use**:

To catch missing critical attributes that would cause API errors.
To enforce schema consistency.
**Example**:

```yaml
required_fields:
  - storage.blobStoreName  # Ensures 'blobStoreName' is always present in the 'storage' section.
  - type  # The repository type must always be specified.
  ```

**Behavior**:

After normalization, the filter checks for the presence of all attributes listed in `required_fields`.
If any required field is missing, an error is raised.

---

## When to Use Each Schema Section

| **Schema Section**  | **Purpose**                                                                                     | **When to Use**                                                                                           |
|----------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `field_map`          | Maps input attributes to their corresponding API-compatible format.                           | Use when input attributes need renaming, nesting, or restructuring.                                       |
| `default_values`     | Provides sensible defaults for optional or missing attributes.                                | Use when attributes are mandatory but often omitted in user-provided input.                               |
| `required_fields`    | Validates that all mandatory attributes are included in the final normalized structure.        | Use when missing attributes would cause the API to reject the repository configuration.                   |

## Example: Maven Proxy Configuration

### Input Data (Mixed Format)

```yaml
nexus_repos_maven_proxy:
  - name: "maven-central"
    remote_url: "https://repo1.maven.org/maven2/"
    blob_store: "custom_blob"
    strict_content_validation: true
    version_policy: "release"
```
### Output Data

```yaml
nexus_repos_maven_proxy_normalized:
  - name: "maven-central"
    online: true
    type: "proxy"
    storage:
      blobStoreName: "custom_blob"  # Input value takes precedence over default.
      strictContentTypeValidation: true  # Input value takes precedence over default.
    proxy:
      remoteUrl: "https://repo1.maven.org/maven2/"
      contentMaxAge: 1440  # Default value applied.
      metadataMaxAge: 1440  # Default value applied.
    maven:
      versionPolicy: "release"  # Input value takes precedence over default.
      layoutPolicy: "STRICT"  # Default value applied.
      contentDisposition: "ATTACHMENT"  # Default value applied.
```
---

## Why This Schema Design?

1. **Flexibility**:
   - Allows handling of legacy formats (flat attributes) and normalized structures (nested attributes) seamlessly.

2. **Error Prevention**:
   - Defaults ensure mandatory attributes are always included, avoiding API rejections.
   - Validation through `required_fields` catches missing attributes before submission.

3. **Reusability**:
   - The schema-driven design allows extending the normalization logic to other repository types (e.g., Docker, NPM).

4. **Ease of Maintenance**:
   - Centralized definitions (`field_map`, `default_values`, `required_fields`) make updates straightforward.
