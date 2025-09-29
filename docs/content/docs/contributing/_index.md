---
title: Contributing
weight: 5
prev: /docs/getting-started
next: /docs/planned-features
comments: true
---

The top 4 contributors with an active GitHub Sponsors account will be added to the FUNDING.yml to show up on the GitHub repository page.

More information about GitHub Sponsors can be found at [GitHub Sponsors](https://github.com/sponsors) and [GitHub FUNDING.yml](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/displaying-a-sponsor-button-in-your-repository)

# Setting up local dev/test environment

There are a few ways to get this project up & running locally.

## 1: Use the devcontainer

Using a devcontainer is the preferred approach to setup a dev/test environment for this project, for the following reasons:

1. **Consistency**: The devcontainer ensures that all developers are using the same development environment configuration.
2. **Isolation**: Dependencies and tools are isolated from your local system, preventing potential conflicts with other projects.
3. **Reproducibility**: The environment can be easily recreated, ensuring that the setup process is quick and reliable.
4. **Portability**: The devcontainer configuration can be shared across different projects, teams and environments. Making it easier to onboard new contributors.

To use the devcontainer, follow these steps:

1. Make sure you have Docker installed and running on your system.
2. Open the project in Visual Studio Code.
3. When prompted, reopen the project in the container.

Visual Studio Code will build the container based on the configuration in the `.devcontainer` folder and open the project inside the container.
If its the first time you're running the devcontainer, please wait a minute or two until the terminal has been reactivated. This will ensure you're using the Python virtual environment which contain all the tools you'll need.

## 2: Install dependencies directly on your system

Make sure you have at least python 3.10 available on your system.
On macOS you can simply run `brew install python3`, assuming you have Homebrew already up & running.

Once Python3.10 or higher is available, continue to create a virtual environment:
`python3 -m venv .venv-3.10`
If you have another python3 version, feel free to name the virtual environment accordingly, for example `python3 -m venv .venv-3.13`.
Once the virtual environment is created, activate it with the following command:
`source .venv-3.10/bin/activate`

## Enabling Nexus Pro

To enable Nexus Pro features during development, you'll have to bring your own license.
The molecule prepare playbook will look for the environment variable `NEXUS_LICENSE_B64` on the host. i.e your development environment. This may be a GitHub Codespace or your system environment variable.

**Note:** when using the devcontainer, the `NEXUS_LICENSE_B64` environment variable on your local system will be used. See .devcontainer/devcontainer.json and <https://code.visualstudio.com/remote/advancedcontainers/environment-variables>

To base64 encode your Nexus Pro license file and set it as an environment variable, follow these steps:

1. **Encode the file**: Use the following command to encode your license file:

    ```sh
    base64 path/to/your/nexus-license.lic > encoded-license.txt
    ```

    Replace `path/to/your/nexus-license.lic` with the actual path to your Nexus Pro license file.

2. **Set the environment variable**: Copy the contents of `encoded-license.txt` and set it as an environment variable:

    ```sh
    export NEXUS_LICENSE_B64=$(cat encoded-license.txt)
    ```

3. **Restart dev environment**: Depending on your setup, restart your terminal sessions, editor or rebuild the devcontainer.

Now, the `NEXUS_LICENSE_B64` environment variable contains your base64 encoded license, which will be detected by the molecule to enable the pro features.
If you provide an invalid license Nexus will ignore it and start as the OSS version.

If working with an environment variable is not an option, you can provide the base64 encoded license using an Ansible variable: `nexus_license_b64: "your-base64-encoded-license-string"`

## Using S3 object storage

Coming soon

## Running tests

```bash
# Install local collection
$ uv run  ansible-galaxy collection install . --force
# Change dir to collection
cd /root/.ansible/collections/ansible_collections/cloudkrafter/nexus
# Sanity & Unit tests
$ uv run ansible-test sanity plugins/modules/ plugins/module_utils/ tests/
$ uv run ansible-test units --docker default --coverage

# Molecule tests
# Needs to run from workspace dir /workspaces/nexus-ansible-collection
cd /workspaces/nexus-ansible-collection
# Define Nexus version to test with (default-community is a Molecule scenario that uses the Sonatype/nexus3 container, not suitable for testing nexus_oss role changes!)
NEXUS_VERSION=3.79.0 uv run molecule converge -s default-community

# Use default-rockylinux9 to test nexus_oss role changes.
uv run molecule converge -s default-rockylinux9
```

## Some guidelines to comply with desired-state-config principles

This role aims to identify changes to singular items. That can be a single repository, LDAP server, routing rule, cleanup policy etc..

In order to do that each item need to be compared against its current state, then for each difference we either create, update or delete the item.

To show every create, update or delete action as 'changed' in the ansible output, we're looping over each item when executing the API call, rather than constructing one big massive api call that contains all changed items. This way when we create, update or delete 2 repositories, Ansible will return changed=2 (rather than changed=1 if we would combine the changes).

This means that for every API call we use the `*-api.yml` file that accepts a list of items with the `with_items:` or `loop:` directive.

### Examples

#### Identify differences (*-tasks.yml)

Each resource uses their corresponding `*-tasks.yml` this file contains the logic to determine if an item needs to be created, updated or deleted and will set the facts for it.

The structure of the tasks are:

- Get all items of the specific configuration
- Set fact for the current config
- Determine if the item needs to be created, comparing desired state (YAML definition) with the current state (API response).
- Determine if the item config needs to be deleted, comparing current state (API response) with desired state (YAML definition).
- Determine if the item config needs to be updated, comparing all item attributes returned from API with attributes of desired item config
- Show the number of changes
- Call the `*-api.yml` task with the POST, PUT or DELETE method.
