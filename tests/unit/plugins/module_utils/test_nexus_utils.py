#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from unittest.mock import MagicMock, patch
import pytest
import json
from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    split_repository_url,
    create_auth_headers,
    get_repository_details,
    build_upload_url,
    check_component_exists,
    delete_component_by_id,
    RepositoryError,
    ComponentError
)


class TestNexusModuleUtils:
    """Tests for nexus_utils module"""

    @pytest.mark.parametrize('repository,expected', [
        (
            'https://nexus.example.com/repository/my-repo',
            ('https://nexus.example.com', 'my-repo')
        ),
        (
            'http://localhost:8081/repository/maven-releases',
            ('http://localhost:8081', 'maven-releases')
        ),
        (
            'https://nexus.example.com:8443/repository/raw-hosted/',
            ('https://nexus.example.com:8443', 'raw-hosted')
        ),
        (
            'https://nexus.com/repository/maven-releases',
            ('https://nexus.com', 'maven-releases')
        ),
        (
            'http://nexus.example.com/repository/maven-releases/',
            ('http://nexus.example.com', 'maven-releases')
        )
    ])
    def test_split_repository_url_valid(self, repository, expected):
        """Test split_repository_url with valid URLs"""
        result = split_repository_url(repository)
        assert result == expected

    @pytest.mark.parametrize('repository,error_msg', [
        (
            None,
            "^Repository URL cannot be empty$"
        ),
        (
            '',
            "^Repository URL cannot be empty$"
        ),
        (
            'https://nexus.example.com',
            "^Invalid repository URL format"
        ),
        (
            'https://nexus.example.com/repos/my-repo',
            "^Invalid repository URL format"
        ),
        (
            'ftp://nexus.example.com/repository/my-repo',
            "^Invalid repository URL format"
        ),
    ])
    def test_split_repository_url_invalid(self, repository, error_msg):
        """Test split_repository_url with invalid URLs"""
        with pytest.raises(RepositoryError, match=error_msg):
            split_repository_url(repository)

    def test_create_auth_headers(self):
        """Test authentication header creation"""

        # Test basic auth
        basic_headers = create_auth_headers(username="user", password="pass")
        assert basic_headers['Authorization'].startswith('Basic ')
        assert 'accept' in basic_headers
        assert basic_headers['Content-Type'] == 'application/json'

        # Test basic auth with upload content type
        basic_headers_upload = create_auth_headers(
            username="user", password="pass", for_upload=True)
        assert basic_headers_upload['Authorization'].startswith('Basic ')
        assert basic_headers_upload['Content-Type'] == 'multipart/form-data'

        # Test no auth
        no_auth_headers = create_auth_headers()
        assert 'Authorization' not in no_auth_headers
        assert no_auth_headers['Content-Type'] == 'application/json'

        # Test no auth with upload content type
        no_auth_headers_upload = create_auth_headers(for_upload=True)
        assert 'Authorization' not in no_auth_headers_upload
        assert no_auth_headers_upload['Content-Type'] == 'multipart/form-data'

    def test_get_repository_details(self):
        """Test repository details retrieval"""
        # Setup mock module
        mock_module = MagicMock()
        mock_module.params = {'timeout': 30}

        # Setup test data
        repository_name = "maven-releases"
        base_url = "https://nexus.example.com"
        headers = create_auth_headers(username="user", password="pass")

        # Setup mock response for successful case
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'format': 'maven2',
            'type': 'hosted'
        }).encode()

        # Test successful retrieval
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.fetch_url') as mock_fetch:
            mock_fetch.return_value = (mock_response, {'status': 200})

            repo_format, repo_type = get_repository_details(
                repository_name=repository_name,
                base_url=base_url,
                headers=headers,
                module=mock_module
            )

            # Verify results
            assert repo_format == 'maven2'
            assert repo_type == 'hosted'
            mock_fetch.assert_called_once_with(
                module=mock_module,
                url=f"{base_url}/service/rest/v1/repositories/{repository_name}",
                headers=headers,
                method='GET',
                timeout=30
            )

    def test_get_repository_details_error_cases(self):
        """Test repository details retrieval error cases"""
        # Setup mock module
        mock_module = MagicMock()
        mock_module.params = {'timeout': 30}

        # Setup test data
        repository_name = "nonexistent-repo"
        base_url = "https://nexus.example.com"
        headers = create_auth_headers(username="user", password="pass")

        # Test 404 error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.fetch_url') as mock_fetch:
            mock_fetch.return_value = (
                None, {'status': 404, 'msg': 'Not Found'})

            with pytest.raises(RepositoryError, match="Failed to get repository details: HTTP 404 - Not Found"):
                get_repository_details(
                    repository_name, base_url, headers, mock_module)

        # Test invalid JSON response
        mock_response = MagicMock()
        mock_response.read.return_value = "Invalid JSON"

        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.fetch_url') as mock_fetch:
            mock_fetch.return_value = (mock_response, {'status': 200})

            with pytest.raises(RepositoryError, match="Failed to parse repository details"):
                get_repository_details(
                    repository_name, base_url, headers, mock_module)

        # Test connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.fetch_url') as mock_fetch:
            mock_fetch.return_value = (
                None, {'status': -1, 'msg': 'Connection refused'})

            with pytest.raises(RepositoryError, match="Failed to get repository details: HTTP -1 - Connection refused"):
                get_repository_details(
                    repository_name, base_url, headers, mock_module)

    def test_build_upload_url(self):
        """Test URL construction for uploads"""
        base_url = "https://nexus.example.com"
        repo_name = "test-repo"

        # Test basic URL construction
        expected = "https://nexus.example.com/service/rest/v1/components?repository=test-repo"
        assert build_upload_url(base_url, repo_name) == expected

        # Test with trailing slash in base_url
        assert build_upload_url(base_url + "/", repo_name) == expected

        # Test with empty values
        with pytest.raises(ValueError):
            build_upload_url("", repo_name)
        with pytest.raises(ValueError):
            build_upload_url(base_url, "")

    def test_check_component_exists(self):
        """Test component existence checking"""

        # Setup test data
        base_url = "https://nexus.example.com"
        repository_name = "raw-hosted"
        name = "test-component.txt"
        dest = "/dest"
        headers = create_auth_headers(username="user", password="pass")
        validate_certs = True
        timeout = 30

        # Test case: Component exists
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.read.return_value = json.dumps({
                'items': [{
                    'path': '/dest/test-component.txt',
                    'id': 'cmF3LWhvc3RlZDo0ZjFiYmNkZA'
                }]
            }).encode()
            mock_open.return_value = mock_response

            exists, component_id = check_component_exists(
                base_url=base_url,
                repository_name=repository_name,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert exists is True
            assert component_id == 'cmF3LWhvc3RlZDo0ZjFiYmNkZA'
            mock_open.assert_called_once_with(
                'https://nexus.example.com/service/rest/v1/search/assets?repository=raw-hosted&name=/dest/test-component.txt&sort=version&direction=desc',
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout,
                method='GET'
            )

        # Test case: Component doesn't exist
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.read.return_value = json.dumps({
                'items': []
            }).encode()
            mock_open.return_value = mock_response

            exists, component_id = check_component_exists(
                base_url=base_url,
                repository_name=repository_name,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert exists is False
            assert component_id is None

        # Test case: HTTP error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 404
            mock_open.return_value = mock_response

            with pytest.raises(ComponentError, match="Failed to search for component: HTTP 404"):
                check_component_exists(
                    base_url=base_url,
                    repository_name=repository_name,
                    name=name,
                    dest=dest,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

        # Test case: Connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_open.side_effect = Exception("Connection refused")

            with pytest.raises(ComponentError, match="Error checking component existence: Connection refused"):
                check_component_exists(
                    base_url=base_url,
                    repository_name=repository_name,
                    name=name,
                    dest=dest,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

    def test_check_component_exists_multiple_items(self):
        """Test component existence checking with multiple items"""
        # Setup test data
        base_url = "https://nexus.example.com"
        repository_name = "raw-hosted"
        name = "test-component.txt"
        dest = "/dest"
        headers = create_auth_headers(username="user", password="pass")
        validate_certs = True
        timeout = 30

        # Test case: Multiple items with one match
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.read.return_value = json.dumps({
                'items': [
                    {
                        'path': '/other/path/file.txt',
                        'id': 'other-id'
                    },
                    {
                        'path': '/dest/test-component.txt',
                        'id': 'correct-id'
                    },
                    {
                        'path': '/another/path/test-component.txt',
                        'id': 'another-id'
                    }
                ]
            }).encode()
            mock_open.return_value = mock_response

            exists, component_id = check_component_exists(
                base_url=base_url,
                repository_name=repository_name,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert exists is True
            assert component_id == 'correct-id'

    def test_delete_component_by_id(self):
        """Test component deletion by ID"""
        # Setup test data
        base_url = "https://nexus.example.com"
        component_id = "cmF3LWhvc3RlZDo0ZjFiYmNkZA"
        headers = create_auth_headers(username="user", password="pass")
        validate_certs = True
        timeout = 30

        # Test successful deletion
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 204
            mock_open.return_value = mock_response

            result = delete_component_by_id(
                base_url=base_url,
                component_id=component_id,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert result is True
            mock_open.assert_called_once_with(
                f"{base_url}/service/rest/v1/components/{component_id}",
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout,
                method='DELETE'
            )

        # Test failed deletion (HTTP error)
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 404
            mock_response.read.return_value = b"Component not found"
            mock_open.return_value = mock_response

            with pytest.raises(ComponentError, match="Deletion failed: Component not found"):
                delete_component_by_id(
                    base_url=base_url,
                    component_id=component_id,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

        # Test connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils.open_url') as mock_open:
            mock_open.side_effect = Exception("Connection refused")

            with pytest.raises(ComponentError, match="Deletion failed: Connection refused"):
                delete_component_by_id(
                    base_url=base_url,
                    component_id=component_id,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )
