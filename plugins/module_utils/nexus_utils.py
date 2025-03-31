# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import re
import base64
import json
from ansible.module_utils.urls import (
    fetch_url,
    open_url
)


class NexusError(Exception):
    """Base exception for Nexus operations"""
    pass


class RepositoryError(NexusError):
    """Repository related errors"""
    pass


class ComponentError(NexusError):
    """Component related errors"""
    pass


def split_repository_url(repository):
    """
    Splits the repository URL into parts to identify the repository name and repository base URL.

    Args:
        repository (str): URL of the repository (e.g., https://nexus.example.com/repository/my-repo)

    Returns:
        tuple: (base_url, repository_name)
               base_url: The base URL of the Nexus instance (e.g., https://nexus.example.com)
               repository_name: The name of the repository (e.g., my-repo)

    Raises:
        ValueError: If the repository URL is invalid or doesn't match expected format.
    """
    if not repository:
        raise RepositoryError("Repository URL cannot be empty")

    # Remove trailing slash if present
    repository = repository.rstrip('/')

    # Match pattern: protocol://hostname[:port]/repository/repo-name
    pattern = r'^(https?://[^/]+)/repository/([^/]+)$'
    match = re.match(pattern, repository)

    if not match:
        raise RepositoryError(
            "Invalid repository URL format. Expected: http(s)://hostname[:port]/repository/repo-name"
        )

    base_url = match.group(1)
    repository_name = match.group(2)

    return base_url, repository_name


def create_auth_headers(username=None, password=None, for_upload=False):
    """
    Creates authentication headers for requests

    Args:
        username (str, optional): Username for basic auth
        password (str, optional): Password for basic auth
        for_upload (bool): Whether headers are for upload (defaults to False)

    Returns:
        dict: Headers dictionary with auth and content type

    Raises:
        ValueError: If invalid auth combination is provided
    """
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Only set multipart content type for actual upload requests
    if for_upload:
        headers['Content-Type'] = 'multipart/form-data'

    if username and password:
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers['Authorization'] = f'Basic {auth}'

    return headers


def get_repository_details(repository_name, base_url, headers, module):
    """
    Get repository format and type from Nexus API.

    Args:
        repository_name (str): Name of the repository
        base_url (str): Base URL of Nexus instance
        headers (dict): Request headers including authentication
        module (AnsibleModule): Module instance for fetch_url

    Returns:
        tuple: (format, type) of the repository (e.g., 'raw', 'hosted')

    Raises:
        RepositoryError: If repository doesn't exist or can't be accessed
    """
    url = f"{base_url}/service/rest/v1/repositories/{repository_name}"

    response, info = fetch_url(
        module=module,
        url=url,
        headers=headers,
        method='GET',
        timeout=module.params['timeout']
    )

    if info['status'] != 200:
        raise RepositoryError(
            f"Failed to get repository details: HTTP {info['status']} - {info.get('msg', 'Unknown error')}"
        )

    try:
        content = json.loads(response.read())
        return content.get('format'), content.get('type')
    except Exception as e:
        raise RepositoryError(f"Failed to parse repository details: {str(e)}")


def check_component_exists(base_url, repository_name, name, dest, headers, validate_certs, timeout):
    """
    Checks if a component already exists in the repository.

    Args:
        base_url (str): Base URL of the Nexus instance
        repository_name (str): Name of the repository to check
        name (str): Name of the component to check
        dest (str): Destination directory in repository
        headers (dict): Request headers including authentication
        validate_certs (bool): Whether to validate SSL certificates
        timeout (int): Request timeout in seconds

    Returns:
        tuple: (exists, component_id)
               exists (bool): True if component exists, False otherwise
               component_id (str): ID of the component if found, None otherwise

    Raises:
        ComponentError: If the search request fails

    Note:
        This function uses the search API to find the component in the repository.
        This api endpoint is known to be slow and inefficient, and should be used with caution.
        When issues occur, use the component API to get the list of components and search for the component in the list.
    """

    url = f"{base_url}/service/rest/v1/search/assets"
    dest = dest.strip('/')
    full_path = f"/{dest}/{name}"

    # Build query parameters
    params = {
        'repository': repository_name,
        'name': full_path,
        'sort': 'version',
        'direction': 'desc'
    }

    # Convert params to URL query string
    query_string = '&'.join(f"{k}={v}" for k, v in params.items())
    search_url = f"{url}?{query_string}"

    try:
        response = open_url(
            search_url,
            headers=headers,
            validate_certs=validate_certs,
            timeout=timeout,
            method='GET'
        )

        if response.code != 200:
            raise ComponentError(
                f"Failed to search for component: HTTP {response.code}"
            )

        # Parse response
        content = json.loads(response.read().decode('utf-8'))

        # Check if any items match our criteria
        items = content.get('items', [])
        for item in items:
            if item.get('path') == full_path:
                return True, item.get('id')

        return False, None

    except Exception as e:
        raise ComponentError(f"Error checking component existence: {str(e)}")


def delete_component_by_id(base_url, component_id, headers, validate_certs, timeout):
    """
    Delete a component from the repository by its ID.

    Args:
        base_url (str): Base URL of the Nexus instance
        component_id (str): ID of the component to delete
        headers (dict): Request headers including authentication
        validate_certs (bool): Whether to validate SSL certificates
        timeout (int): Request timeout in seconds

    Returns:
        bool: True if deletion was successful, False otherwise

    Raises:
        ComponentError: If deletion fails
    """
    url = f"{base_url}/service/rest/v1/components/{component_id}"

    try:
        response = open_url(
            url,
            headers=headers,
            validate_certs=validate_certs,
            timeout=timeout,
            method='DELETE'
        )

        if response.code in [200, 204]:
            return True
        else:
            error_msg = response.read().decode('utf-8')
            raise ComponentError(f"Deletion failed: {error_msg}")

    except Exception as e:
        raise ComponentError(f"Deletion failed: {str(e)}")


def build_upload_url(base_url, repository_name):
    """
    Constructs the upload URL for the Nexus Repository Manager API.

    Args:
        base_url (str): Base URL of the Nexus instance
        repository_name (str): Name of the repository

    Returns:
        str: Complete upload URL with parameters

    Raises:
        ValueError: If base_url or repository_name is empty/invalid
    """

    if not base_url:
        raise ValueError("Base URL cannot be empty")
    if not repository_name:
        raise ValueError("Repository name cannot be empty")

    # Remove trailing slashes
    base_url = base_url.rstrip('/')

    # Construct URL with repository parameter
    url = f"{base_url}/service/rest/v1/components"

    # Add query parameters
    params = {
        'repository': repository_name
    }

    # Convert params to URL query string
    query_string = '&'.join(f"{k}={v}" for k, v in params.items())

    return f"{url}?{query_string}"
