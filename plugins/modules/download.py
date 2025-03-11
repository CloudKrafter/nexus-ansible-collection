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
      - Target architecture for the package (e.g., 'x86_64' or 'aarch64').
      - If specified, will attempt to find a package matching this architecture.
      - If not specified or if no architecture-specific package exists, will use the default package.
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
'''

RETURN = '''
download_url:
    description: The URL used for downloading the package.
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
import sys
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.urls import fetch_url


# Try collection import first, then local import, finally direct import
HAS_DEPS = False
try:
    from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
        requests, BeautifulSoup, version, urllib3
    )
    HAS_DEPS = True
except ImportError:
    try:
        # For local development, try to find module_utils in relative path
        module_utils_path = os.path.join(os.path.dirname(__file__), '..', 'module_utils')
        if os.path.exists(module_utils_path):
            sys.path.insert(0, module_utils_path)
            from nexus_utils import requests, BeautifulSoup, version, urllib3
            HAS_DEPS = True
    except ImportError:
        # Direct imports as fallback
        try:
            import requests
            import urllib3
            from bs4 import BeautifulSoup
            from packaging import version
            HAS_DEPS = True

            def check_dependencies():
                return True, ""
        except ImportError as e:
            pass


def get_latest_version(validate_certs=False):
    """
    Scrapes the Sonatype download page to find the latest version.

    Args:
        validate_certs (bool): Whether to verify SSL certificates
    """
    url = "https://help.sonatype.com/en/download-archives---repository-manager-3.html"
    try:
        response = requests.get(url, verify=validate_certs)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for version pattern in text (e.g., "3.78.0-01")
        version_pattern = r'(\d+\.\d+\.\d+-\d+)'
        versions = []

        for text in soup.stripped_strings:
            match = re.search(version_pattern, text)
            if match:
                versions.append(match.group(1))

        if not versions:
            raise ValueError("No version found on download page")

        # Sort versions and get the latest
        latest = sorted(versions, key=lambda x: version.parse(x.split('-')[0]))[-1]
        return latest

    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch download page: {str(e)}")


def is_valid_version(version):
    if version is None:
        return False
    if not isinstance(version, str):
        return False
    pattern = r'^\d+\.\d+\.\d+-\d+$'
    return bool(re.match(pattern, version))


def scrape_download_page(url, validate_certs=True):
    """
    Scrapes the Sonatype download page and returns the parsed content.

    Args:
        url (str): URL to scrape
        validate_certs (bool): Whether to verify SSL certificates

    Returns:
        BeautifulSoup: Parsed HTML content

    Raises:
        Exception: If page fetch fails
    """
    try:
        response = requests.get(url, verify=validate_certs)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch download page: {str(e)}")


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
        response = requests.head(url, verify=validate_certs, allow_redirects=True)
        return response.ok, response.status_code
    except requests.exceptions.RequestException:
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
        variants.extend([
            f"nexus-unix-{arch}-{version}.tar.gz",
            f"nexus-{arch}-unix-{version}.tar.gz",
        ])

    # Java version variants (medium priority)
    if java_version:
        variants.extend([
            f"nexus-unix-{version}-{java_version}.tar.gz",
            f"nexus-{version}-unix-{java_version}.tar.gz",
        ])

    # Base names (lowest priority)
    base_names = [
        f"nexus-{version}-unix.tar.gz",
        f"nexus-unix-{version}.tar.gz"
    ]

    # Return all variants in order of priority
    return variants + base_names


def get_download_url(state, version=None, arch=None, validate_certs=True):
    """
    Determines and returns a single download URL based on state, version and architecture.

    The URL is selected based on the following precedence:
    1. Architecture-specific package (nexus-{arch}-{version}.tar.gz)
    2. Standard unix package (nexus-{version}-unix.tar.gz)
    3. Alternative unix package (nexus-unix-{version}.tar.gz)
    4. Java version specific package (nexus-{version}-{java_version}-unix.tar.gz)

    Args:
        state (str): Either 'latest' or 'present'
        version (str): Optional version string (required if state is 'present')
        arch (str): Optional target architecture
        validate_certs (bool): Whether to verify SSL certificates

    Returns:
        str: Single download URL matching the criteria

    Raises:
        ValueError: If parameters are invalid or no unique URL can be determined
    """
    if state not in ['latest', 'present']:
        raise ValueError(f"Invalid state: {state}")

    try:
        # Get version and valid URLs
        version = get_latest_version(validate_certs) if state == 'latest' else version
        valid_urls = get_valid_download_urls(version, arch=arch, validate_certs=validate_certs)

        # Define URL patterns in order of precedence
        patterns = [
            rf"nexus-{arch}-.*?{version}\.tar\.gz$" if arch else None,
            rf"nexus-{version}-unix\.tar\.gz$",
            rf"nexus-unix-{version}\.tar\.gz$",
            rf"nexus-{version}-.*?-unix\.tar\.gz$"
        ]

        # Filter out None patterns
        patterns = [p for p in patterns if p]

        # Try each pattern in order
        for pattern in patterns:
            matches = [url for url in valid_urls if re.search(pattern, url, re.IGNORECASE)]
            if matches:
                if len(matches) > 1:
                    raise ValueError(f"Multiple matches found for pattern {pattern}")
                return matches[0]

        # If no pattern matches but we have exactly one valid URL, return it
        if len(valid_urls) == 1:
            return valid_urls[0]
        elif len(valid_urls) > 1:
            raise ValueError("Multiple valid URLs found with no specific match")
        else:
            raise ValueError("No valid download URLs found")

    except Exception as e:
        raise ValueError(f"Failed to get download URL: {str(e)}")


def get_dest_path(url, dest):
    """Helper function to get destination path"""
    return os.path.join(dest, url.split('/')[-1])


def download_file(module, url, dest, validate_certs=True):
    """Downloads a file using Ansible's fetch_url utility."""
    if not validate_certs:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    destination = get_dest_path(url, dest)

    # Check if file already exists
    if os.path.exists(destination):
        return False, "File already exists", destination, 200

    # Create destination directory if it doesn't exist
    if not os.path.exists(dest):
        try:
            os.makedirs(dest)
        except Exception as e:
            module.fail_json(msg=f"Failed to create destination directory: {str(e)}")

    # Download the file
    response, info = fetch_url(module, url, method="GET")
    status_code = info['status']

    if info['status'] != 200:
        module.fail_json(msg=f"Failed to download file: {info['msg']}")

    try:
        with open(destination, 'wb') as f:
            f.write(response.read())
        return True, "File downloaded successfully", destination, status_code
    except Exception as e:
        module.fail_json(msg=f"Failed to write file: {str(e)}")


def main():
    module_args = dict(
        state=dict(type='str', required=True, choices=['latest', 'present']),
        version=dict(type='str', required=False),
        arch=dict(type='str', required=False),
        dest=dict(type='path', required=True),
        validate_certs=dict(type='bool', required=False, default=True)
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # Check required libraries early
    if not HAS_DEPS:
        module.fail_json(msg=missing_required_lib('requests, beautifulsoup4, packaging'))

    state = module.params['state']
    version = module.params.get('version')
    arch = module.params.get('arch')
    dest = module.params['dest']
    validate_certs = module.params['validate_certs']

    # Validate parameters
    if state == 'present' and not version:
        module.fail_json(msg="When state is 'present', the 'version' parameter must be provided.")

    try:
        download_url = get_download_url(state, version, arch=arch, validate_certs=validate_certs)
    except Exception as e:
        module.fail_json(msg=f"Error determining download URL: {str(e)}")

    # Get destination path
    destination = get_dest_path(download_url, dest)

    # Check if file already exists for both check mode and regular mode
    file_exists = os.path.exists(destination)

    # Check mode: report what would be done
    if module.check_mode:
        module.exit_json(
            changed=not file_exists,
            download_url=download_url,
            destination=destination,
            status_code=200 if file_exists else None,
            msg="File would be downloaded, if not in check mode" if not file_exists else "File already exists"
        )

    # Perform the actual download
    changed, msg, destination, status_code = download_file(module, download_url, dest, validate_certs)

    module.exit_json(
        changed=changed,
        download_url=download_url,
        msg=msg,
        destination=destination,
        status_code=status_code
    )


if __name__ == '__main__':
    main()
