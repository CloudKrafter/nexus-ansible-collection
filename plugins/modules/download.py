#!/usr/bin/python
import requests
from bs4 import BeautifulSoup
from packaging import version
import re
import os
import urllib3
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url

DOCUMENTATION = '''
---
module: download
short_description: Download Nexus package
description:
  - This module downloads a specified Nexus package from Sonatype's Nexus repository.
version_added: "1.20"
options:
  state:
    description:
      - Determines whether to download the latest version or a specific version.
    required: true
    choices: ['latest', 'present']
  version:
    description:
      - The version to download when state is 'present'.
    required: false
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
  validate_certs:
    description:
      - If False, SSL certificates will not be validated.
    type: bool
    default: true
    required: false
author: "Brian Veltman"
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
download_dest:
    description: The local path where the package was saved.
    type: str
    returned: always
changed:
    description: Indicates if a change was made (e.g., download occurred).
    type: bool
    returned: always
'''

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

def get_version_download_url(version, arch=None, validate_certs=True):
    """
    Scrapes the download page to find the specific URL for a version.
    
    Args:
        version (str): Version string in format X.Y.Z-NN
        arch (str): Optional target architecture
        validate_certs (bool): Whether to verify SSL certificates
    
    Returns:
        str: Download URL for the specific version
    """
    url = "https://help.sonatype.com/en/download-archives---repository-manager-3.html"
    try:
        response = requests.get(url, verify=validate_certs)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Store all matching links
        matching_links = []

        # Look for download links containing the version
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if version in href and 'unix' in href.lower():
                matching_links.append(href)
        
        if not matching_links:
            raise ValueError(f"No download URL found for version {version}")
        
        # If architecture is specified, try to find a matching package
        if arch:
            for link in matching_links:
                if arch.lower() in link.lower():
                    return link
            
            # If no architecture-specific package found, warn and use first match
            return matching_links[0]
        
        # If no architecture specified, return first match
        return matching_links[0]

    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch download page: {str(e)}")

def get_download_url(state, version=None, arch=None, validate_certs=True):
    """
    Determines the download URL based on state and version.
    
    Args:
        state (str): Either 'latest' or 'present'
        version (str): Optional version string (required if state is 'present')
        arch (str): Optional target architecture
        validate_certs (bool): Whether to verify SSL certificates
    
    Returns:
        str: Download URL for the specified version
    
    Raises:
        ValueError: If version format is invalid or version not found
    """
    try:
        if state == 'latest':
            version = get_latest_version(validate_certs=validate_certs)
        
        # Validate version format
        if not re.match(r'^\d+\.\d+\.\d+-\d+$', version):
            raise ValueError(f"Invalid version format: {version}")
            
        return get_version_download_url(version, arch=arch, validate_certs=validate_certs)
        
    except Exception as e:
        raise Exception(f"Error determining download URL: {str(e)}")

def get_dest_path(url, dest):
    """Helper function to get destination path"""
    return os.path.join(dest, url.split('/')[-1])

def download_file(module, url, dest, validate_certs=True):
    """Downloads a file using Ansible's fetch_url utility."""
    if not validate_certs:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    download_dest = get_dest_path(url, dest)
    
    # Check if file already exists
    if os.path.exists(download_dest):
        return False, "File already exists", download_dest

    # Create destination directory if it doesn't exist
    if not os.path.exists(dest):
        try:
            os.makedirs(dest)
        except Exception as e:
            module.fail_json(msg=f"Failed to create destination directory: {str(e)}")

    # Download the file
    response, info = fetch_url(module, url, method="GET")
    
    if info['status'] != 200:
        module.fail_json(msg=f"Failed to download file: {info['msg']}")
    
    try:
        with open(download_dest, 'wb') as f:
            f.write(response.read())
        return True, "File downloaded successfully", download_dest
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
    download_dest = get_dest_path(download_url, dest)
    
    # Check if file already exists for both check mode and regular mode
    file_exists = os.path.exists(download_dest)
    
    # Check mode: report what would be done
    if module.check_mode:
        module.exit_json(
            changed=not file_exists,
            download_url=download_url,
            download_dest=download_dest,
            msg="File would be downloaded, if not in check mode." if not file_exists else "File already exists"
        )
    
    # Perform the actual download
    changed, msg, download_dest = download_file(module, download_url, dest, validate_certs)
    
    module.exit_json(
        changed=changed,
        download_url=download_url,
        msg=msg,
        download_dest=download_dest
    )

if __name__ == '__main__':
    main()
