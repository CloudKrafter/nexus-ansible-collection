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


@pytest.mark.parametrize('arch_input,expected_variants', [
    ('x86-64', ['x86-64', 'x86_64']),
    ('x86_64', ['x86_64', 'x86-64']),
    ('aarch64', ['aarch64', 'aarch_64']),
    ('aarch_64', ['aarch_64', 'aarch64']),
    ('arm64', ['arm64']),  # Non-standard arch should have just one variant
])
def test_architecture_variants(arch_input, expected_variants):
    """Test that architecture variants are properly handled"""
    result = get_possible_package_names('3.78.0-01', arch=arch_input)

    # Check that package names for all expected variants are generated
    for variant in expected_variants:
        assert any(variant in name for name in result), f"Missing {variant} in result"

    # Make sure we have the specific packages we test for in other tests
    # For example, check for linux-x86_64 pattern when x86_64 is an expected variant
    if 'x86_64' in expected_variants:
        assert any('linux-x86_64' in name for name in result)
    if 'x86-64' in expected_variants:
        assert any('linux-x86-64' in name for name in result)


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
        # Invalid version format
        mock_invalid_version_response.read.return_value = b'{"name": "release-invalid"}'
        mock_open_url.return_value = mock_invalid_version_response

        # Test invalid version format
        with pytest.raises(Exception, match="Failed to fetch version from API: Invalid version format: invalid"):
            get_latest_version(validate_certs=True)

        # Reset mock for non-release version format test
        mock_open_url.reset_mock()
        mock_non_release_response = MagicMock()
        mock_non_release_response.code = 200
        # Wrong prefix
        mock_non_release_response.read.return_value = b'{"name": "non-release-3.78.0-01"}'
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

    @patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.download_file')
    @patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_download_url')
    @patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_latest_version')
    @patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.AnsibleModule')
    def test_main_check_mode(self, mock_module, mock_get_latest, mock_get_url, mock_download):
        """Test main function check mode behavior"""
        # Setup module mock with check mode
        module_instance = setup_ansible_module_mock(mock_module)
        module_instance.check_mode = True

        # Reset and setup download mock
        mock_download.reset_mock()
        mock_download.return_value = (
            True, "File downloaded successfully", "/tmp/nexus.tar.gz", 200)

        # Setup URL mock
        mock_get_url.reset_mock()
        mock_get_url.return_value = 'https://example.com/nexus-3.78.0-01-unix.tar.gz'

        # Test check mode with non-existent file
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = False
            module_instance.params = {
                'state': 'present',
                'version': '3.78.0-01',
                'dest': '/tmp',
                'validate_certs': True,
                'timeout': 30,
                'arch': None,
                'url': None
            }

            # Reset all call counts
            mock_download.called = False
            module_instance.exit_json.reset_mock()

            main()

            # Verify behavior when file doesn't exist
            assert not mock_download.called, "download_file should not be called in check mode"
            module_instance.exit_json.assert_called_once_with(
                changed=True,
                download_url='https://example.com/nexus-3.78.0-01-unix.tar.gz',
                version='3.78.0-01',
                destination='/tmp/nexus-3.78.0-01-unix.tar.gz',
                status_code=None,
                msg="File would be downloaded, if not in check mode"
            )

            # Test check mode with existing file
            mock_exists.return_value = True
            module_instance.exit_json.reset_mock()
            mock_download.called = False

            main()

            # Verify behavior when file exists
            assert not mock_download.called, "download_file should not be called in check mode"
            module_instance.exit_json.assert_called_once_with(
                changed=False,
                download_url='https://example.com/nexus-3.78.0-01-unix.tar.gz',
                version='3.78.0-01',
                destination='/tmp/nexus-3.78.0-01-unix.tar.gz',
                status_code=200,
                msg="File already exists"
            )


@pytest.mark.parametrize('version,arch,java_version,expected', [
    (
        '3.78.0-01',
        None,
        None,
        [
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-3.78.0-01-linux.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz',
            'nexus-linux-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        'aarch64',
        None,
        [
            # aarch64 variants
            'nexus-3.78.0-01-linux-aarch64.tar.gz',
            'nexus-3.78.0-01-aarch64-linux.tar.gz',
            'nexus-aarch64-linux-3.78.0-01.tar.gz',
            'nexus-linux-aarch64-3.78.0-01.tar.gz',
            'nexus-unix-aarch64-3.78.0-01.tar.gz',
            'nexus-aarch64-unix-3.78.0-01.tar.gz',
            # aarch_64 variants
            'nexus-3.78.0-01-linux-aarch_64.tar.gz',
            'nexus-3.78.0-01-aarch_64-linux.tar.gz',
            'nexus-aarch_64-linux-3.78.0-01.tar.gz',
            'nexus-linux-aarch_64-3.78.0-01.tar.gz',
            'nexus-unix-aarch_64-3.78.0-01.tar.gz',
            'nexus-aarch_64-unix-3.78.0-01.tar.gz',
            # Base names without arch or java version
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-3.78.0-01-linux.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz',
            'nexus-linux-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        None,
        'java11',
        [
            'nexus-unix-3.78.0-01-java11.tar.gz',
            'nexus-linux-3.78.0-01-java11.tar.gz',
            'nexus-3.78.0-01-unix-java11.tar.gz',
            'nexus-3.78.0-01-linux-java11.tar.gz',
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-3.78.0-01-linux.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz',
            'nexus-linux-3.78.0-01.tar.gz'
        ]
    ),
    (
        '3.78.0-01',
        'aarch64',
        'java11',
        [
            # aarch64 and aarch_64 variants
            'nexus-3.78.0-01-linux-aarch64.tar.gz',
            'nexus-3.78.0-01-aarch64-linux.tar.gz',
            'nexus-aarch64-linux-3.78.0-01.tar.gz',
            'nexus-linux-aarch64-3.78.0-01.tar.gz',
            'nexus-unix-aarch64-3.78.0-01.tar.gz',
            'nexus-aarch64-unix-3.78.0-01.tar.gz',
            # aarch_64 variants
            'nexus-3.78.0-01-linux-aarch_64.tar.gz',
            'nexus-3.78.0-01-aarch_64-linux.tar.gz',
            'nexus-aarch_64-linux-3.78.0-01.tar.gz',
            'nexus-linux-aarch_64-3.78.0-01.tar.gz',
            'nexus-unix-aarch_64-3.78.0-01.tar.gz',
            'nexus-aarch_64-unix-3.78.0-01.tar.gz',
            # Java version variants
            'nexus-unix-3.78.0-01-java11.tar.gz',
            'nexus-linux-3.78.0-01-java11.tar.gz',
            'nexus-3.78.0-01-unix-java11.tar.gz',
            'nexus-3.78.0-01-linux-java11.tar.gz',
            # Base names without arch or java version
            'nexus-3.78.0-01-unix.tar.gz',
            'nexus-3.78.0-01-linux.tar.gz',
            'nexus-unix-3.78.0-01.tar.gz',
            'nexus-linux-3.78.0-01.tar.gz'
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
    is_valid, status_code = validate_download_url(
        "https://download.sonatype.com/nexus/3/test.tar.gz")
    assert is_valid is True
    assert status_code == 200

    # Reset mock for invalid URL test
    mock_open_url.reset_mock()
    mock_open_url.side_effect = Exception("404 Not Found")

    # Test invalid URL
    is_valid, status_code = validate_download_url(
        "https://download.sonatype.com/nexus/3/nonexistent.tar.gz")
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
    def side_effect_func(url, *args, **kwargs):
        # Return True for specific patterns, False for others
        if "aarch64" in url or "aarch_64" in url:
            return (True, 200)
        return (False, 404)

    mock_validate.side_effect = side_effect_func

    # Test successful case
    base_url = "https://download.sonatype.com/nexus/3/"
    result = get_valid_download_urls(
        '3.78.1-02', arch='aarch64', base_url=base_url, validate_certs=True)

    # Verify we got valid URLs
    assert len(result) > 0
    assert all(url.startswith(base_url) for url in result)
    assert all('3.78.1-02' in url for url in result)
    assert any('aarch64' in url or 'aarch_64' in url for url in result)

    # Test invalid version
    mock_validate.reset_mock()
    with pytest.raises(ValueError, match="Invalid version format"):
        get_valid_download_urls('invalid')

    # Test when no valid URLs found
    mock_validate.reset_mock()
    mock_validate.side_effect = lambda url, *args, **kwargs: (False, 404)  # All URLs return 404
    with pytest.raises(ValueError, match="No valid download URLs found"):
        get_valid_download_urls('3.78.1-02')


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.download_file')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_download_url')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_latest_version')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.AnsibleModule')
def test_main(mock_module, mock_get_latest, mock_get_url, mock_download):
    """Test main function logic and parameter handling"""

    #################################
    # Setup common mocks
    #################################
    module_instance = setup_ansible_module_mock(mock_module)
    mock_get_latest.return_value = '3.78.0-01'
    mock_get_url.return_value = 'https://example.com/nexus-3.78.0-01-unix.tar.gz'
    mock_download.return_value = (
        True, "File downloaded successfully", "/tmp/nexus.tar.gz", 200)

    #################################
    # Test state=present with version
    #################################
    module_instance.params = {
        'state': 'present',
        'version': '3.78.0-01',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30,
        'arch': None
    }

    main()
    mock_get_url.assert_called_with(
        'present',  # state as positional arg
        '3.78.0-01',  # version as positional arg
        arch=None,  # arch as keyword arg
        validate_certs=True  # validate_certs as keyword arg
    )

    module_instance.exit_json.assert_called_with(
        changed=True,
        download_url='https://example.com/nexus-3.78.0-01-unix.tar.gz',
        version='3.78.0-01',
        msg="File downloaded successfully",
        destination="/tmp/nexus.tar.gz",
        status_code=200
    )

    #################################
    # Test state=latest
    #################################
    module_instance.reset_mock()
    module_instance.params = {
        'state': 'latest',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30
    }

    main()
    assert mock_get_latest.called
    module_instance.exit_json.assert_called_with(
        changed=True,
        download_url='https://example.com/nexus-3.78.0-01-unix.tar.gz',
        version='3.78.0-01',
        msg="File downloaded successfully",
        destination="/tmp/nexus.tar.gz",
        status_code=200
    )

    #################################
    # Test missing version in present state
    #################################
    module_instance.reset_mock()
    module_instance.params = {
        'state': 'present',
        'dest': '/tmp',
        'validate_certs': True
    }

    main()
    module_instance.fail_json.assert_called_with(
        msg="When state is 'present', the 'version' parameter must be provided unless URL points directly to a .tar.gz file."
    )

    #################################
    # Test custom URL handling
    #################################
    module_instance.reset_mock()
    mock_get_url.reset_mock()
    mock_get_latest.reset_mock()
    mock_download.reset_mock()  # Reset download mock before custom URL test

    # Setup mock for get_valid_download_urls
    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_valid_download_urls') as mock_get_valid_urls:
        # Test single URL case
        mock_get_valid_urls.return_value = [
            'http://custom.example.com/nexus-3.78.0-01-unix.tar.gz']
        module_instance.params = {
            'state': 'present',
            'version': '3.78.0-01',
            'url': 'http://custom.example.com',
            'dest': '/tmp',
            'validate_certs': True,
            'timeout': 30,
            'arch': 'x86-64'
        }

        main()

        # Verify correct URL handling
        mock_get_valid_urls.assert_called_once_with(
            '3.78.0-01',
            arch='x86-64',
            validate_certs=True,
            base_url='http://custom.example.com/'
        )

        # Verify download was attempted with correct URL
        assert mock_download.call_count == 1, "download_file should be called exactly once"
        mock_download.assert_called_once_with(
            module_instance,
            'http://custom.example.com/nexus-3.78.0-01-unix.tar.gz',
            '/tmp',
            True
        )

    #################################
    # Test URL with latest state
    #################################
    module_instance.reset_mock()
    module_instance.check_mode = False
    module_instance.params = {
        'state': 'latest',
        'url': 'http://example.com',
        'dest': '/tmp',
        'validate_certs': True
    }

    main()
    module_instance.fail_json.assert_called_with(
        msg="URL can only be used when state is 'present'"
    )

    #################################
    # Test error handling
    #################################
    module_instance.reset_mock()
    mock_get_url.side_effect = ValueError("Failed to determine download URL")
    module_instance.params = {
        'state': 'present',
        'version': '3.78.0-01',
        'dest': '/tmp',
        'validate_certs': True
    }

    main()
    module_instance.fail_json.assert_called_with(
        msg="Error determining download URL: Failed to determine download URL",
        download_url=None,
        version='3.78.0-01'
    )

    #################################
    # Test missing version with custom URL
    #################################
    module_instance.reset_mock()
    module_instance.params = {
        'state': 'present',
        'url': 'http://custom.example.com',  # Custom URL without version
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30,
        'arch': None
    }

    main()
    module_instance.fail_json.assert_called_with(
        msg="Version must be provided when using a custom URL that doesn't point directly to a .tar.gz file"
    )

    #################################
    # Test download URL determination failure
    #################################
    module_instance.reset_mock()
    mock_get_url.reset_mock()
    mock_get_latest.reset_mock()

    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_valid_download_urls') as mock_get_valid_urls:
        # Setup to return no download URL
        mock_get_valid_urls.return_value = []
        module_instance.params = {
            'state': 'present',
            'version': '3.78.0-01',
            'url': 'http://custom.example.com',
            'dest': '/tmp',
            'validate_certs': True,
            'timeout': 30,
            'arch': 'x86-64'
        }

        main()

        # Verify error handling when no download URL is found
        module_instance.fail_json.assert_called_with(
            msg="Error determining download URL: Failed to determine download URL",
            download_url=None,
            version='3.78.0-01'
        )

    #################################
    # Test generic exception handling
    #################################
    module_instance.reset_mock()
    mock_get_url.reset_mock()
    mock_get_latest.reset_mock()
    mock_download.reset_mock()

    # Setup module parameters
    module_instance.params = {
        'state': 'present',
        'version': '3.78.0-01',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30,
        'arch': None
    }

    # Simulate a generic exception
    mock_get_latest.side_effect = Exception("Unexpected error occurred")

    main()

    # Verify error handling
    module_instance.fail_json.assert_called_with(
        msg="Error determining download URL: Failed to determine download URL",
        download_url=None,
        version='3.78.0-01'
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
    mock_os.path.exists.side_effect = [
        False, False]  # File and dir don't exist
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
    mock_open_url.exceptions = type(
        'Exceptions', (), {'RequestException': Exception})

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
    module.fail_json = MagicMock(
        side_effect=Exception("Failed to create directory"))

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


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.get_valid_download_urls')
def test_get_download_url(mock_get_valid_urls):
    """Test URL resolution in get_download_url function"""

    #################################
    # Test successful case with single URL
    #################################
    mock_get_valid_urls.return_value = [
        'https://example.com/nexus-3.78.0-01-unix.tar.gz']

    result = get_download_url(
        state='present',
        version='3.78.0-01',
        arch='x86-64',
        validate_certs=True
    )
    assert result == 'https://example.com/nexus-3.78.0-01-unix.tar.gz'

    #################################
    # Test multiple URLs with pattern matching
    #################################
    mock_get_valid_urls.return_value = [
        'https://example.com/nexus-x86-64-3.78.0-01.tar.gz',
        'https://example.com/nexus-3.78.0-01-unix.tar.gz',
        'https://example.com/nexus-unix-3.78.0-01.tar.gz'
    ]

    result = get_download_url(
        state='present',
        version='3.78.0-01',
        arch='x86-64',
        validate_certs=True
    )
    assert result == 'https://example.com/nexus-x86-64-3.78.0-01.tar.gz'

    #################################
    # Test multiple matches error
    #################################
    mock_get_valid_urls.return_value = [
        'https://example.com/nexus-x86-64-3.78.0-01.tar.gz',
        'https://mirror.example.com/nexus-x86-64-3.78.0-01.tar.gz'
    ]

    with pytest.raises(ValueError, match="Multiple matches found for pattern"):
        get_download_url(
            state='present',
            version='3.78.0-01',
            arch='x86-64',
            validate_certs=True
        )

    #################################
    # Test no valid URLs found
    #################################
    mock_get_valid_urls.return_value = []

    with pytest.raises(ValueError, match="No valid download URLs found"):
        get_download_url(
            state='present',
            version='3.78.0-01',
            validate_certs=True
        )

    #################################
    # Test custom base URL
    #################################
    mock_get_valid_urls.return_value = [
        'https://custom.example.com/nexus-3.78.0-01-unix.tar.gz']

    result = get_download_url(
        state='present',
        version='3.78.0-01',
        base_url='https://custom.example.com/',
        validate_certs=True
    )
    assert result == 'https://custom.example.com/nexus-3.78.0-01-unix.tar.gz'

    #################################
    # Test URL pattern preference order
    #################################
    mock_get_valid_urls.return_value = [
        'https://example.com/nexus-unix-3.78.0-01.tar.gz',
        'https://example.com/nexus-3.78.0-01-unix.tar.gz',
        'https://example.com/nexus-x86-64-3.78.0-01.tar.gz'
    ]

    # Should prefer arch-specific URL
    result = get_download_url(
        state='present',
        version='3.78.0-01',
        arch='x86-64',
        validate_certs=True
    )
    assert result == 'https://example.com/nexus-x86-64-3.78.0-01.tar.gz'

    #################################
    # Test single URL with no pattern match
    #################################
    mock_get_valid_urls.return_value = [
        # URL doesn't match any pattern
        'https://example.com/nexus-special-3.78.0-01.tar.gz'
    ]

    # Should return the single URL even though it doesn't match patterns
    result = get_download_url(
        state='present',
        version='3.78.0-01',
        arch='x86-64',
        validate_certs=True
    )
    assert result == 'https://example.com/nexus-special-3.78.0-01.tar.gz'

    #################################
    # Test multiple URLs with no pattern matches
    #################################
    mock_get_valid_urls.return_value = [
        'https://example.com/nexus-special-3.78.0-01.tar.gz',
        'https://example.com/nexus-custom-3.78.0-01.tar.gz'
    ]

    # Should raise error when multiple URLs exist but none match patterns
    with pytest.raises(ValueError, match="No valid download URLs found"):
        get_download_url(
            state='present',
            version='3.78.0-01',
            arch='x86-64',
            validate_certs=True
        )


@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.download_file')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.validate_download_url')
@patch('ansible_collections.cloudkrafter.nexus.plugins.modules.download.AnsibleModule')
def test_direct_url_download(mock_module, mock_validate, mock_download):
    """Test direct URL download functionality"""
    # Setup module mock
    module_instance = setup_ansible_module_mock(mock_module)

    # Setup validation mock to return success
    mock_validate.return_value = (True, 200)

    # Setup download mock
    mock_download.return_value = (
        True, "File downloaded successfully", "/tmp/custom-nexus.tar.gz", 200)

    #################################
    # Test direct .tar.gz URL
    #################################
    module_instance.params = {
        'state': 'present',
        'url': 'https://custom-server.com/path/nexus-3.78.0-01-unix.tar.gz',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30
    }

    main()

    # Verify URL was validated
    mock_validate.assert_called_with(
        'https://custom-server.com/path/nexus-3.78.0-01-unix.tar.gz',
        True
    )

    # Verify direct URL was used (no URL resolution needed)
    mock_download.assert_called_with(
        module_instance,
        'https://custom-server.com/path/nexus-3.78.0-01-unix.tar.gz',
        '/tmp',
        True
    )

    # Verify version was extracted from filename
    module_instance.exit_json.assert_called_with(
        changed=True,
        download_url='https://custom-server.com/path/nexus-3.78.0-01-unix.tar.gz',
        version='3.78.0-01',  # Extracted from filename
        msg="File downloaded successfully",
        destination="/tmp/custom-nexus.tar.gz",
        status_code=200
    )

    #################################
    # Test custom .tar.gz URL without extractable version
    #################################
    module_instance.reset_mock()
    mock_validate.reset_mock()
    mock_download.reset_mock()

    # Setup for custom filename without version
    module_instance.params = {
        'state': 'present',
        'url': 'https://custom-server.com/path/custom-nexus.tar.gz',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30
    }

    main()

    # Verify version is set to "custom" when not extractable
    module_instance.exit_json.assert_called_with(
        changed=True,
        download_url='https://custom-server.com/path/custom-nexus.tar.gz',
        version='custom',  # Default when version not extractable
        msg="File downloaded successfully",
        destination="/tmp/custom-nexus.tar.gz",
        status_code=200
    )

    #################################
    # Test direct URL validation failure
    #################################
    module_instance.reset_mock()
    mock_validate.reset_mock()
    mock_download.reset_mock()

    # Setup for URL validation failure
    mock_validate.return_value = (False, 404)
    module_instance.params = {
        'state': 'present',
        'url': 'https://custom-server.com/path/nonexistent.tar.gz',
        'dest': '/tmp',
        'validate_certs': True,
        'timeout': 30
    }

    main()

    # Verify failure handling
    module_instance.fail_json.assert_called_with(
        msg="Error determining download URL: The provided URL https://custom-server.com/path/nonexistent.tar.gz is not accessible",
        download_url='https://custom-server.com/path/nonexistent.tar.gz',
        version=None
    )

    #################################
    # Test direct URL with latest state (should fail)
    #################################
    module_instance.reset_mock()
    module_instance.params = {
        'state': 'latest',
        'url': 'https://custom-server.com/path/nexus.tar.gz',
        'dest': '/tmp',
        'validate_certs': True
    }

    main()

    module_instance.fail_json.assert_called_with(
        msg="URL can only be used when state is 'present'"
    )
