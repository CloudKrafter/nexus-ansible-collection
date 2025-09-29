#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''
---
module: download
short_description: Download Nexus package
description:
  - This module downloads a specified Nexus package from Sonatype's Nexus repository.
version_added: "1.20.0"
options:
  state:
    description:
      - Determines whether to download the latest version or a specific version.
    required: true
    choices: ['latest', 'present']
    type: str
  version:
    description:
      - The version to download when state is 'present'.
    required: false
    type: str
  arch:
    description:
      - Target architecture for the package (e.g., 'x86-64' or 'aarch64').
      - If specified, will attempt to find a package matching this architecture.
      - If not specified or if no architecture-specific package exists, will use the default package.
    required: false
    type: str
    default: x86-64
  url:
    description:
      - Custom base URL to download Nexus from.
      - If the URL ends with '.tar.gz', it will be used directly as the download URL.
      - Otherwise, it will be used as a base URL to find package files.
      - Can only be used when state is 'present' and version is defined.
      - Version parameter is required if URL doesn't end with '.tar.gz'.
    required: false
    type: str
  dest:
    description:
      - Destination directory where the file should be saved.
    required: true
    type: path
  validate_certs:
    description:
      - If False, SSL certificates will not be validated.
    type: bool
    default: true
    required: false
  timeout:
    description:
      - Timeout in seconds for the HTTP request.
      - This value sets both the connect and read timeouts.
    type: int
    default: 120
    required: false
author:
  - "Brian Veltman (@cloudkrafter)"
'''

EXAMPLES = '''
- name: Download the latest Nexus package
  cloudkrafter.nexus.download:
    state: latest
    dest: /path/to/download/dir
    validate_certs: true

- name: Download a specific Nexus version without SSL verification
  cloudkrafter.nexus.download:
    state: present
    version: 3.78.0-1
    dest: /path/to/download/dir
    validate_certs: false

- name: Download a specific Nexus version for ARM64
  cloudkrafter.nexus.download:
    state: present
    version: 3.78.0-1
    dest: /path/to/download/dir
    validate_certs: false
    arch: aarch64

- name: Download from a direct URL
  cloudkrafter.nexus.download:
    state: present
    url: https://example.com/nexus-3.78.0-01-unix.tar.gz
    dest: /path/to/download/dir
    validate_certs: true

- name: Download from a custom URL
  cloudkrafter.nexus.download:
    state: present
    version: 3.78.0-1
    url: https://some-url.tld/files
    dest: /path/to/download/dir
    validate_certs: true
'''

RETURN = '''
download_url:
    description: The URL used for downloading the package.
    type: str
    returned: always
version:
    description: The version of Nexus that was or will be downloaded.
    type: str
    returned: always
destination:
    description: The local path where the package was saved.
    type: str
    returned: always
changed:
    description: Indicates if a change was made (e.g., download occurred).
    type: bool
    returned: always
status_code:
    description: HTTP status code of the download request.
    type: int
    returned: always
'''


import re
import os
import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, open_url


def get_latest_version(validate_certs=True):
    """
    Gets the latest version from Sonatype's API endpoint.

    Args:
        validate_certs (bool): Whether to verify SSL certificates

    Returns:
        str: Latest version in format 'X.Y.Z-N'

    Raises:
        Exception: If version cannot be retrieved
    """
    url = "https://api.github.com/repos/sonatype/nexus-public/releases/latest"
    try:
        response = open_url(
            url,
            validate_certs=validate_certs,
            headers={'Accept': 'application/json'}
        )

        if response.code != 200:
            raise ValueError(
                f"API request failed with status code: {response.code}")

        data = json.loads(response.read().decode('utf-8'))

        raw_version = data.get('name')
        if not raw_version:
            raise ValueError("No release found in API response")

        version = raw_version[8:] if raw_version.startswith(
            'release-') else raw_version

        if not is_valid_version(version):
            raise ValueError(f"Invalid version format: {version}")

        return version

    except Exception as e:
        raise Exception(f"Failed to fetch version from API: {str(e)}")


def is_valid_version(version):
    if version is None:
        return False
    if not isinstance(version, str):
        return False
    pattern = r'^\d+\.\d+\.\d+-\d+$'
    return bool(re.match(pattern, version))


def validate_download_url(url, validate_certs=True):
    """
    Validates if a URL exists by checking HTTP headers.

    Args:
        url (str): URL to validate
        validate_certs (bool): Whether to verify SSL certificates

    Returns:
        tuple: (bool, int) - (is_valid, status_code)
    """
    try:
        response = open_url(
            url,
            method='HEAD',
            validate_certs=validate_certs,
            follow_redirects=True
        )
        return True, response.code
    except Exception:
        return False, None


def get_valid_download_urls(version, arch=None, java_version=None, validate_certs=True, base_url="https://download.sonatype.com/nexus/3/"):
    """
    Returns a list of valid download URLs for a given version and optional parameters.

    Args:
        version (str): Version string (e.g., '3.78.0-01')
        arch (str): Optional architecture (e.g., 'aarch64', 'x86_64')
        java_version (str): Optional Java version (e.g., 'java8', 'java11')
        validate_certs (bool): Whether to verify SSL certificates
        base_url (str): Base URL for downloads

    Returns:
        list: List of valid download URLs ordered by priority

    Raises:
        ValueError: If version is invalid or no valid URLs found
    """
    if not is_valid_version(version):
        raise ValueError(f"Invalid version format: {version}")

    # Get possible package names
    possible_names = get_possible_package_names(version, arch, java_version)

    # Check each possible URL
    valid_urls = []
    for name in possible_names:
        url = base_url + name
        is_valid, status_code = validate_download_url(url, validate_certs)
        if is_valid:
            valid_urls.append(url)

    if not valid_urls:
        raise ValueError(f"No valid download URLs found for version {version}")

    return valid_urls


def get_possible_package_names(version, arch=None, java_version=None):
    """
    Generate possible package name variations based on version, architecture and Java version.

    Args:
        version (str): Version string (e.g., '3.78.0-01')
        arch (str): Optional architecture (e.g., 'aarch64', 'x86_64')
        java_version (str): Optional Java version (e.g., 'java8', 'java11')

    Returns:
        list: List of possible package names in order of specificity
    """
    variants = []

    # Architecture variants (highest priority)
    if arch:
        # Handle arch format variants (x86-64 vs x86_64, aarch64 vs aarch_64)
        arch_variants = []

        # Original provided arch
        arch_variants.append(arch)

        # Add alternative format if using common architectures
        if arch == 'x86-64':
            arch_variants.append('x86_64')
        elif arch == 'x86_64':
            arch_variants.append('x86-64')
        elif arch == 'aarch64':
            arch_variants.append('aarch_64')
        elif arch == 'aarch_64':
            arch_variants.append('aarch64')

        # Generate patterns for all architecture variants
        for arch_var in arch_variants:
            variants.extend([
                f"nexus-{version}-linux-{arch_var}.tar.gz",
                f"nexus-{version}-{arch_var}-linux.tar.gz",
                f"nexus-{arch_var}-linux-{version}.tar.gz",
                f"nexus-linux-{arch_var}-{version}.tar.gz",
                f"nexus-unix-{arch_var}-{version}.tar.gz",
                f"nexus-{arch_var}-unix-{version}.tar.gz",
            ])

    # Java version variants (medium priority)
    if java_version:
        variants.extend([
            f"nexus-unix-{version}-{java_version}.tar.gz",
            f"nexus-linux-{version}-{java_version}.tar.gz",
            f"nexus-{version}-unix-{java_version}.tar.gz",
            f"nexus-{version}-linux-{java_version}.tar.gz",
        ])

    # Base names (lowest priority)
    base_names = [
        f"nexus-{version}-unix.tar.gz",
        f"nexus-{version}-linux.tar.gz",
        f"nexus-unix-{version}.tar.gz",
        f"nexus-linux-{version}.tar.gz"
    ]

    # Return all variants in order of priority
    return variants + base_names


def get_download_url(state, version=None, arch=None, base_url=None, validate_certs=True):
    """
    Determines and returns a single download URL based on state, version and architecture.

    The URL is selected based on the following precedence:
    1. Architecture-specific package (nexus-{arch}-{version}.tar.gz)
    2. Standard linux/unix package (nexus-{version}-linux.tar.gz or nexus-{version}-unix.tar.gz)
    3. Alternative unix package (nexus-linux-{version}.tar.gz or nexus-unix-{version}.tar.gz)
    4. Java version specific package (nexus-{version}-{java_version}-unix.tar.gz)

    Args:
        state (str): Either 'latest' or 'present'
        version (str): Optional version string (required if state is 'present')
        arch (str): Optional target architecture
        base_url (str): Optional URL to download from
        validate_certs (bool): Whether to verify SSL certificates

    Returns:
        str: Single download URL matching the criteria

    Raises:
        ValueError: If parameters are invalid or no unique URL can be determined
    """
    if state not in ['latest', 'present']:
        raise ValueError(f"Invalid state: {state}")

    if state == 'present' and not version:
        raise ValueError("Version must be provided when state is 'present'")

    try:
        # Get version and valid URLs
        version = get_latest_version(
            validate_certs) if state == 'latest' else version
        valid_urls = get_valid_download_urls(
            version,
            arch=arch,
            validate_certs=validate_certs,
            base_url=base_url or "https://download.sonatype.com/nexus/3/"
        )

        # Define URL patterns in order of precedence
        patterns = [
            rf"nexus-{arch}-.*?{version}\.tar\.gz$" if arch else None,
            rf"nexus-{version}-(linux|unix)\.tar\.gz$",
            rf"nexus-(linux|unix)-{version}\.tar\.gz$",
            rf"nexus-{version}-.*?-(linux|unix)\.tar\.gz$"
        ]

        # Filter out None patterns
        patterns = [p for p in patterns if p]

        # Try each pattern in order
        for pattern in patterns:
            matches = [url for url in valid_urls if re.search(
                pattern, url, re.IGNORECASE)]
            if matches:
                if len(matches) > 1:
                    raise ValueError(
                        f"Multiple matches found for pattern {pattern}")
                return matches[0]

        # If no pattern matches but we have exactly one valid URL, return it
        if len(valid_urls) == 1:
            return valid_urls[0]
        else:
            raise ValueError("No valid download URLs found")

    except Exception as e:
        raise ValueError(f"Failed to get download URL: {str(e)}")


def get_dest_path(url, dest):
    """Helper function to get destination path"""
    return os.path.join(dest, url.split('/')[-1])


def download_file(module, url, dest, validate_certs=True):
    """Downloads a file using Ansible's fetch_url utility."""

    destination = get_dest_path(url, dest)

    # Check if file already exists
    if os.path.exists(destination):
        return False, "File already exists", destination, 200

    # Create destination directory if it doesn't exist
    if not os.path.exists(dest):
        try:
            os.makedirs(dest)
        except Exception as e:
            module.fail_json(
                msg=f"Failed to create destination directory: {str(e)}")

    # Download the file
    response, info = fetch_url(
        module, url, method="GET", timeout=module.params['timeout'])
    status_code = info['status']

    if info['status'] != 200:
        module.fail_json(
            msg=f"Failed to download file: {info['msg']}",
            status_code=status_code,
            download_url=url
        )

    try:
        with open(destination, 'wb') as f:
            f.write(response.read())
        return True, "File downloaded successfully", destination, status_code
    except Exception as e:
        module.fail_json(msg=f"Failed to write file: {str(e)}")


def validate_parameters(module, state, version, url):
    """
    Validates module parameters in a specific order.
    Returns (is_valid, error_message) tuple.
    """
    # Direct URL to .tar.gz file check
    is_direct_url = url and url.lower().endswith('.tar.gz')

    # Order of validation checks
    validations = [
        # URL state check
        (
            url and state != 'present',
            "URL can only be used when state is 'present'"
        ),
        # URL version check
        (
            url and not is_direct_url and not version,
            "Version must be provided when using a custom URL that doesn't point directly to a .tar.gz file"
        ),
        # Present state version check
        (
            state == 'present' and not version and not is_direct_url,
            "When state is 'present', the 'version' parameter must be provided unless URL points directly to a .tar.gz file."
        )
    ]

    # Check each validation rule
    for condition, message in validations:
        if condition:
            return False, message

    return True, None


def main():
    module_args = dict(
        state=dict(type='str', required=True, choices=['latest', 'present']),
        version=dict(type='str', required=False),
        arch=dict(type='str', required=False, default='x86-64'),
        url=dict(type='str', required=False),
        timeout=dict(type='int', required=False, default=120),
        dest=dict(type='path', required=True),
        validate_certs=dict(type='bool', required=False, default=True)
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # Get parameters
    state = module.params['state']
    version = module.params.get('version')
    arch = module.params.get('arch')
    url = module.params.get('url')
    dest = module.params['dest']
    validate_certs = module.params['validate_certs']

    # Parameter validation
    is_valid, error_message = validate_parameters(module, state, version, url)
    if not is_valid:
        module.fail_json(msg=error_message)
        return

    # Initialize variables
    download_url = None
    actual_version = None

    try:
        if url:
            if url.lower().endswith('.tar.gz'):
                # Direct URL to a .tar.gz file
                download_url = url

                # Validate that the URL exists
                is_valid, status_code = validate_download_url(download_url, validate_certs)
                if not is_valid:
                    raise ValueError(f"The provided URL {download_url} is not accessible")

                # Try to extract version from filename or use 'custom'
                filename = url.split('/')[-1]
                version_match = re.search(r'nexus-.*?(\d+\.\d+\.\d+-\d+)', filename)
                if version_match:
                    actual_version = version_match.group(1)
                else:
                    actual_version = "custom"
            else:
                base_url = url.rstrip('/') + '/'
                actual_version = version  # We know version is set when url is used
                valid_urls = get_valid_download_urls(
                    actual_version, arch=arch, validate_certs=validate_certs, base_url=base_url)
                if len(valid_urls) == 1:
                    download_url = valid_urls[0]
                else:
                    download_url = get_download_url(
                        state, actual_version, arch=arch, validate_certs=validate_certs, base_url=base_url)
        else:
            # For non-custom URLs, get latest version if needed
            actual_version = version if state == 'present' else get_latest_version(
                validate_certs)
            download_url = get_download_url(
                state, actual_version, arch=arch, validate_certs=validate_certs)

        if not download_url:
            raise ValueError("Failed to determine download URL")

        # Get destination path
        destination = get_dest_path(download_url, dest)

        # Check if file already exists for both check mode and regular mode
        file_exists = os.path.exists(destination)

        # Check mode: report what would be done
        if module.check_mode:
            module.exit_json(
                changed=not file_exists,
                download_url=download_url,
                version=actual_version,
                destination=destination,
                status_code=200 if file_exists else None,
                msg="File would be downloaded, if not in check mode" if not file_exists else "File already exists"
            )
            return

        # Perform the actual download
        changed, msg, destination, status_code = download_file(
            module, download_url, dest, validate_certs)

        module.exit_json(
            changed=changed,
            download_url=download_url,
            version=actual_version,
            msg=msg,
            destination=destination,
            status_code=status_code
        )

    except Exception as e:
        module.fail_json(
            msg=f"Error determining download URL: {str(e)}",
            download_url=download_url,
            version=actual_version
        )


if __name__ == '__main__':
    main()
