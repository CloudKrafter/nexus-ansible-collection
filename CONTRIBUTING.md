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