#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from unittest.mock import patch, MagicMock
import os
import pytest
from ansible_collections.cloudkrafter.nexus.plugins.modules.download import (
    is_valid_version, get_latest_version, get_possible_package_names,
    validate_download_url, get_valid_download_urls, main, get_dest_path, download_file, get_download_url
)


@pytest.mark.parametrize('version,expected', [
    ('3.78.0-01', True),        # Valid version
    ('3.78.1-02', True),        # Valid version
    ('3.0.0-01', True),         # Valid version
    ('3.78.0', False),          # Missing build number
    ('3.78-01', False),         # Missing minor version
    ('3.78.0.1-01', False),     # Extra version number
    ('3.78.0-1', True),         # Single digit build number
    ('invalid', False),         # Invalid version
    ('', False),                # Empty string
    (None, False),              # None value
    (123, False),               # Integer
    (3.78, False),              # Float
    ([], False),                # List
    ({}, False),                # Dictionary
    (True, False),              # Boolean
    (b'3.78.0-01', False),      # Bytes
])
def test_is_valid_version(version, expected):
    """Test version string validation"""
    result = is_valid_version(version)
    assert result == expected


def setup_ansible_module_mock(mock_module, params=None):
    """Helper to setup common AnsibleModule mock attributes"""
    mock_instance = MagicMock()
    mock_module.return_value = mock_instance
    mock_instance.params = params or {}
    mock_instance.check_mode = False

    # Don't set side effects that raise SystemExit
    mock_instance.exit_json = MagicMock()
    mock_instance.fail_json = MagicMock()

    return mock_instance


class TestNexusDownloadModule:
    def setup_method(self):
        self.module_args = {
            'state': 'latest',
            'dest': '/tmp/nexus',
            'validate_certs': True,
            'version': None,
            'arch': None
        }

    @patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.open_url')
    def test_get_latest_version(self, mock_open_url):
        """Test getting latest version from GitHub API"""

        #################################
        # Test case for succesful response
        #################################

        # Setup mock response
        mock_response = MagicMock()
        mock_response.code = 200
        mock_response.read.return_value = b'{"name": "release-3.78.0-01"}'
        mock_open_url.return_value = mock_response

        # Test successful case
        result = get_latest_version(validate_certs=True)
        assert result == '3.78.0-01'
        mock_open_url.assert_called_once_with(
            "https://api.github.com/repos/sonatype/nexus-public/releases/latest",
            validate_certs=True,
            headers={'Accept': 'application/json'}
        )

        #################################
        # Test case for empty release name
        #################################

        # Reset mock for empty response test
        mock_open_url.reset_mock()
        mock_empty_response = MagicMock()
        mock_empty_response.code = 200
        mock_empty_response.read.return_value = b'{"name": ""}'  # Empty name
        mock_open_url.return_value = mock_empty_response

        # Test empty release name
        with pytest.raises(Exception, match="Failed to fetch version from API: No release found in API response"):
            get_latest_version(validate_certs=True)

        # Reset mock for missing name field test
        mock_open_url.reset_mock()
        mock_missing_name_response = MagicMock()
        mock_missing_name_response.code = 200
        mock_missing_name_response.read.return_value = b'{}'  # Missing name field
        mock_open_url.return_value = mock_missing_name_response

        # Test missing name field
        with pytest.raises(Exception, match="Failed to fetch version from API: No release found in API response"):
            get_latest_version(validate_certs=True)

        #################################
        # Test case for invalid version in response
        #################################

        # Reset mock for invalid version format test
        mock_open_url.reset_mock()
        mock_invalid_version_response = MagicMock()
        mock_invalid_version_response.code = 200
        mock_invalid_version_response.read.return_value = b'{"name": "release-invalid"}'  # Invalid version format
        mock_open_url.return_value = mock_invalid_version_response

        # Test invalid version format
        with pytest.raises(Exception, match="Failed to fetch version from API: Invalid version format: invalid"):
            get_latest_version(validate_certs=True)

        # Reset mock for non-release version format test
        mock_open_url.reset_mock()
        mock_non_release_response = MagicMock()
        mock_non_release_response.code = 200
        mock_non_release_response.read.return_value = b'{"name": "non-release-3.78.0-01"}'  # Wrong prefix
        mock_open_url.return_value = mock_non_release_response

        # Test non-release version format
        with pytest.raises(Exception, match="Failed to fetch version from API: Invalid version format: non-release-3.78.0-01"):
            get_latest_version(validate_certs=True)

        #################################
        # Test case for API non-200 status code
        #################################

        # Reset mock for API error test (non-200 status code)
        mock_open_url.reset_mock()
        mock_error_response = MagicMock()
        mock_error_response.code = 403
        mock_open_url.return_value = mock_error_response

        # Test API error with non-200 status code
        with pytest.raises(Exception, match="Failed to fetch version from API: API request failed with status code: 403"):
            get_latest_version(validate_certs=True)

        # Reset mock for error test
        mock_open_url.reset_mock()
        mock_open_url.side_effect = Exception("Connection error")

        # Test API error
        with pytest.raises(Exception, match="Failed to fetch version from API"):
            get_latest_version(validate_certs=True)


@pytest.mark.parametrize('version,arch,java_version,expected', [
    (
        '3.78.0-01',
        None,
        None,
        [
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        'aarch64',
        None,
        [
            'nexus-unix-aarch64-3.78.0-01.tar.gz',
            'nexus-aarch64-unix-3.78.0-01.tar.gz',
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        None,
        'java11',
        [
            'nexus-unix-3.78.0-01-java11.tar.gz',
            'nexus-3.78.0-01-unix-java11.tar.gz',
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        'aarch64',
        'java11',
        [
            'nexus-unix-aarch64-3.78.0-01.tar.gz',
            'nexus-aarch64-unix-3.78.0-01.tar.gz',
            'nexus-unix-3.78.0-01-java11.tar.gz',
            'nexus-3.78.0-01-unix-java11.tar.gz',
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz'
        ]
    ),
])
def test_get_possible_package_names(version, arch, java_version, expected):
    """Test generation of possible package names"""
    result = get_possible_package_names(version, arch, java_version)
    assert result == expected


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.open_url')
def test_validate_download_url(mock_open_url):
    """Test URL validation using HEAD requests"""
    # Setup mock responses
    mock_response_valid = MagicMock()
    mock_response_valid.code = 200
    mock_response_invalid = MagicMock()
    mock_response_invalid.code = 404

    # Test valid URL
    mock_open_url.return_value = mock_response_valid
    is_valid, status_code = validate_download_url("https://download.sonatype.com/nexus/3/test.tar.gz")
    assert is_valid is True
    assert status_code == 200

    # Reset mock for invalid URL test
    mock_open_url.reset_mock()
    mock_open_url.side_effect = Exception("404 Not Found")

    # Test invalid URL
    is_valid, status_code = validate_download_url("https://download.sonatype.com/nexus/3/nonexistent.tar.gz")
    assert is_valid is False
    assert status_code is None

    # Reset mock for connection error test
    mock_open_url.reset_mock()
    mock_open_url.side_effect = Exception("Connection error")

    # Test connection error
    is_valid, status_code = validate_download_url("https://invalid.url")
    assert is_valid is False
    assert status_code is None


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.validate_download_url')
def test_get_valid_download_urls(mock_validate):
    """Test getting valid download URLs by checking headers"""
    # Setup mock responses for different URLs
    mock_validate.side_effect = [
        (True, 200),   # First URL is valid
        (False, 404),  # Second URL is invalid
        (True, 200),   # Third URL is valid
        (False, 404),  # Fourth URL is invalid
    ]

    # Test successful case
    base_url = "https://download.sonatype.com/nexus/3/"
    result = get_valid_download_urls('3.78.1-02', arch='aarch64', base_url=base_url)

    # Verify we got valid URLs
    assert len(result) == 2
    assert all(url.startswith(base_url) for url in result)
    assert all('3.78.1-02' in url for url in result)

    # Test invalid version
    mock_validate.reset_mock()
    with pytest.raises(ValueError, match="Invalid version format"):
        get_valid_download_urls('invalid')

    # Test when no valid URLs found
    mock_validate.reset_mock()
    mock_validate.side_effect = [(False, 404)] * 10  # All URLs return 404
    with pytest.raises(ValueError, match="No valid download URLs found"):
        get_valid_download_urls('3.78.1-02')


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.AnsibleModule')
def test_main_parameters(mock_module):
    """Test main function parameter validation"""
    # Setup module mock
    module_instance = setup_ansible_module_mock(mock_module)

    # Test missing version in present state
    module_instance.params = {
        'state': 'present',
        'dest': '/tmp',
        'validate_certs': True,
        'version': None
    }

    # Run main and verify error
    main()
    module_instance.fail_json.assert_called_once_with(
        msg="When state is 'present', the 'version' parameter must be provided."
    )

    # Reset mock for next test
    module_instance.fail_json.reset_mock()

    # Test URL with latest state
    module_instance.params = {
        'state': 'latest',
        'url': 'http://example.com',
        'dest': '/tmp',
        'validate_certs': True
    }
    main()
    module_instance.fail_json.assert_called_once_with(
        msg="URL can only be used when state is 'present'"
    )


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.os')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.fetch_url')
def test_download_file(mock_fetch, mock_os, tmp_path):
    """Test file download functionality"""
    # Setup module mock
    module = MagicMock()
    module.params = {'timeout': 30}

    url = "https://example.com/nexus.tar.gz"
    dest = str(tmp_path)
    dest_file = f"{dest}/nexus.tar.gz"

    # Mock os.path functions
    mock_os.path.exists.side_effect = [False, False]  # For dest dir and file
    mock_os.path.join = os.path.join  # Use real join function
    mock_os.makedirs = MagicMock()  # Mock makedirs

    # Setup successful download
    mock_response = MagicMock()
    mock_response.read.return_value = b"test content"
    mock_fetch.return_value = (mock_response, {'status': 200})

    # Test successful download
    changed, msg, dest_path, status = download_file(module, url, dest)
    assert changed is True
    assert status == 200
    assert "successfully" in msg
    mock_os.makedirs.assert_called_once_with(dest)

    # Reset mocks for existing file test
    mock_os.reset_mock()
    mock_fetch.reset_mock()
    mock_os.path.exists.side_effect = [True]  # File exists

    # Test existing file
    changed, msg, dest_path, status = download_file(module, url, dest)
    assert changed is False
    assert "exists" in msg
    assert not mock_fetch.called

    # Reset mocks for download failure test
    mock_os.reset_mock()
    mock_fetch.reset_mock()
    mock_os.path.exists.side_effect = [False, False]  # File doesn't exist
    mock_fetch.return_value = (None, {'status': 404, 'msg': 'Not found'})
    module.fail_json.side_effect = Exception("Download failed")

    # Test download failure
    with pytest.raises(Exception) as exc:
        download_file(module, url, dest)
    assert "Download failed" in str(exc.value)

    # Reset mocks for write failure test
    mock_os.reset_mock()
    mock_fetch.reset_mock()
    mock_os.path.exists.side_effect = [False, False]  # File and dir don't exist
    mock_response = MagicMock()
    mock_response.read.return_value = b"test content"
    mock_fetch.return_value = (mock_response, {'status': 200})

    # Reset module mock for write failure test
    module = MagicMock()
    module.params = {'timeout': 30}
    module.fail_json = MagicMock()

    # Mock open to raise an IOError when writing
    mock_open = MagicMock()
    mock_open.side_effect = IOError("Permission denied")

    with patch('builtins.open', mock_open):
        # Test file write failure
        download_file(module, url, dest)

        # Verify fail_json was called with correct message
        module.fail_json.assert_called_once_with(
            msg="Failed to write file: Permission denied"
        )


def test_get_dest_path():
    """Test destination path generation"""
    url = "https://example.com/path/to/nexus-3.78.0-01-unix.tar.gz"
    dest = "/tmp/nexus"

    result = get_dest_path(url, dest)
    assert result == "/tmp/nexus/nexus-3.78.0-01-unix.tar.gz"


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_download_url')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_latest_version')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.open_url')
def test_url_resolution(mock_open_url, mock_get_latest, mock_get_url):
    """Test URL resolution logic"""
    # Setup mock responses
    mock_response = MagicMock()
    mock_response.code = 200
    mock_open_url.return_value = mock_response
    mock_open_url.exceptions = type('Exceptions', (), {'RequestException': Exception})

    # Setup version and URL mocks
    mock_get_latest.return_value = '3.78.0-01'
    mock_get_url.return_value = 'https://example.com/nexus-3.78.0-01-unix.tar.gz'

    # Test URL validation with custom base URL
    base_url = 'https://custom.example.com/'
    version = '3.78.0-01'
    arch = 'aarch64'

    # Test URL validation
    valid_urls = get_valid_download_urls(
        version=version,
        arch=arch,
        base_url=base_url,
        validate_certs=True
    )

    assert len(valid_urls) > 0
    assert mock_open_url.called
    assert all(url.startswith(base_url) for url in valid_urls)


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.open_url')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.validate_download_url')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_valid_download_urls')
def test_error_handling(mock_get_valid_urls, mock_validate, mock_open_url):
    """Test error handling in various scenarios"""
    mock_open_url.exceptions = type('Exceptions', (), {
        'RequestException': Exception
    })

    # Test directory creation failure
    module = MagicMock()
    module.fail_json = MagicMock(side_effect=Exception("Failed to create directory"))

    with pytest.raises(Exception, match="Failed to create directory"):
        download_file(
            module=module,
            url="https://example.com/file.tar.gz",
            dest="/root/forbidden"
        )

    # Test invalid version format
    with pytest.raises(ValueError, match="Invalid version format"):
        get_valid_download_urls("invalid-version")

    mock_validate.return_value = (True, 200)

    # Test get_download_url with invalid state
    with pytest.raises(ValueError, match="Invalid state"):
        get_download_url(state='invalid', version='3.78.0-01')

    # Test get_download_url with missing version in present state
    with pytest.raises(ValueError, match="Version must be provided"):
        get_download_url(state='present')
