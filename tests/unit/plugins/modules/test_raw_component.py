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
from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import (
    split_repository_url,
    create_auth_headers,
    get_repository_details,
    build_upload_url,
    check_artifact_exists,
    perform_upload,
    RepositoryError,
    ArtifactError
)


class TestUploadArtifactModule:
    """Tests for raw_component module"""

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
        basic_headers_upload = create_auth_headers(username="user", password="pass", for_upload=True)
        assert basic_headers_upload['Authorization'].startswith('Basic ')
        assert basic_headers_upload['Content-Type'] == 'multipart/form-data'

        # Test token auth
        token_headers = create_auth_headers(token="my-token")
        assert token_headers['Authorization'] == 'Bearer my-token'
        assert token_headers['Content-Type'] == 'application/json'

        # Test token auth with upload content type
        token_headers_upload = create_auth_headers(token="my-token", for_upload=True)
        assert token_headers_upload['Authorization'] == 'Bearer my-token'
        assert token_headers_upload['Content-Type'] == 'multipart/form-data'

        # Test no auth
        no_auth_headers = create_auth_headers()
        assert 'Authorization' not in no_auth_headers
        assert no_auth_headers['Content-Type'] == 'application/json'

        # Test no auth with upload content type
        no_auth_headers_upload = create_auth_headers(for_upload=True)
        assert 'Authorization' not in no_auth_headers_upload
        assert no_auth_headers_upload['Content-Type'] == 'multipart/form-data'

        # Test mutual exclusivity
        with pytest.raises(ValueError):
            create_auth_headers(username="user", password="pass", token="token")

    def test_get_repository_details(self):
        """Test repository details retrieval"""
        # Setup mock module
        mock_module = MagicMock()
        mock_module.params = {'timeout': 30}

        # Setup test data
        repository_name = "maven-releases"
        base_url = "https://nexus.example.com"
        headers = {'Authorization': 'Bearer test-token'}

        # Setup mock response for successful case
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'format': 'maven2',
            'type': 'hosted'
        }).encode()

        # Test successful retrieval
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.fetch_url') as mock_fetch:
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
        headers = {'Authorization': 'Bearer test-token'}

        # Test 404 error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.fetch_url') as mock_fetch:
            mock_fetch.return_value = (None, {'status': 404, 'msg': 'Not Found'})

            with pytest.raises(RepositoryError, match="Failed to get repository details: HTTP 404 - Not Found"):
                get_repository_details(repository_name, base_url, headers, mock_module)

        # Test invalid JSON response
        mock_response = MagicMock()
        mock_response.read.return_value = "Invalid JSON"

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.fetch_url') as mock_fetch:
            mock_fetch.return_value = (mock_response, {'status': 200})

            with pytest.raises(RepositoryError, match="Failed to parse repository details"):
                get_repository_details(repository_name, base_url, headers, mock_module)

        # Test connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.fetch_url') as mock_fetch:
            mock_fetch.return_value = (None, {'status': -1, 'msg': 'Connection refused'})

            with pytest.raises(RepositoryError, match="Failed to get repository details: HTTP -1 - Connection refused"):
                get_repository_details(repository_name, base_url, headers, mock_module)

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

    def test_check_artifact_exists(self):
        """Test artifact existence checking"""

        # Setup test data
        base_url = "https://nexus.example.com"
        repository_name = "raw-hosted"
        name = "test-artifact.txt"
        dest = "/dest"
        headers = {'Authorization': 'Bearer test-token'}
        validate_certs = True
        timeout = 30

        # Test case: Artifact exists
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.read.return_value = json.dumps({
                'items': [{
                    'path': '/dest/test-artifact.txt'
                }]
            }).encode()
            mock_open.return_value = mock_response

            exists = check_artifact_exists(
                base_url=base_url,
                repository_name=repository_name,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert exists is True
            mock_open.assert_called_once_with(
                'https://nexus.example.com/service/rest/v1/search/assets?repository=raw-hosted&name=/dest/test-artifact.txt&sort=version&direction=desc',
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout,
                method='GET'
            )

        # Test case: Artifact doesn't exist
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.read.return_value = json.dumps({
                'items': []
            }).encode()
            mock_open.return_value = mock_response

            exists = check_artifact_exists(
                base_url=base_url,
                repository_name=repository_name,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert exists is False

        # Test case: HTTP error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open:
            mock_response = MagicMock()
            mock_response.code = 404
            mock_open.return_value = mock_response

            with pytest.raises(ArtifactError, match="Failed to search for artifact: HTTP 404"):
                check_artifact_exists(
                    base_url=base_url,
                    repository_name=repository_name,
                    name=name,
                    dest=dest,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

        # Test case: Connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open:
            mock_open.side_effect = Exception("Connection refused")

            with pytest.raises(ArtifactError, match="Error checking artifact existence: Connection refused"):
                check_artifact_exists(
                    base_url=base_url,
                    repository_name=repository_name,
                    name=name,
                    dest=dest,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

    def test_perform_upload(self, tmp_path):
        """Test artifact upload functionality"""
        # Setup test data
        url = "https://nexus.example.com/service/rest/v1/components?repository=raw-hosted"
        name = "test-file.txt"
        dest = "/path/to/dest"
        headers = {'Authorization': 'Bearer test-token'}
        validate_certs = True
        timeout = 30

        # Create a temporary test file
        test_file = tmp_path / "test-file.txt"
        test_file.write_text("test content")
        src = str(test_file)

        # Test successful upload
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open_url:
            mock_response = MagicMock()
            mock_response.code = 201
            mock_response.read.return_value = b"Upload successful"
            mock_open_url.return_value = mock_response

            success, status_code, message = perform_upload(
                url=url,
                src=src,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert success is True
            assert status_code == 201
            assert message == "Upload successful"

            # Verify the multipart form data
            call_args = mock_open_url.call_args
            assert call_args is not None
            called_url, called_kwargs = call_args[0][0], call_args[1]

            assert called_url == url
            assert called_kwargs['method'] == 'POST'
            assert called_kwargs['validate_certs'] == validate_certs
            assert called_kwargs['timeout'] == timeout
            assert 'multipart/form-data' in called_kwargs['headers']['Content-Type']

        # Test upload failure
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open_url:
            mock_response = MagicMock()
            mock_response.code = 400
            mock_response.read.return_value = b"Bad request"
            mock_open_url.return_value = mock_response

            success, status_code, message = perform_upload(
                url=url,
                src=src,
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

            assert success is False
            assert status_code == 400
            assert "Upload failed" in message

        # Test missing source file
        with pytest.raises(ArtifactError, match="Source file not found"):
            perform_upload(
                url=url,
                src="/nonexistent/file.txt",
                name=name,
                dest=dest,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout
            )

        # Test connection error
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.open_url') as mock_open_url:
            mock_open_url.side_effect = Exception("Connection refused")

            with pytest.raises(ArtifactError, match="Upload failed: Connection refused"):
                perform_upload(
                    url=url,
                    src=src,
                    name=name,
                    dest=dest,
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout
                )

    def test_main_function(self, tmp_path):
        """Test main function with various scenarios"""
        # Create a test file
        test_file = tmp_path / "test-artifact.txt"
        test_file.write_text("test content")

        # Basic module parameters
        module_params = {
            'repository': 'https://nexus.example.com/repository/raw-hosted',
            'name': 'test-artifact.txt',
            'src': str(test_file),
            'dest': '/upload/path',
            'validate_certs': False,
            'timeout': 30,
            'username': 'testuser',
            'password': 'testpass',
            'token': None
        }

        # Mock AnsibleModule
        mock_module = MagicMock()
        mock_module.params = module_params
        mock_module.check_mode = False
        mock_module.exit_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            # Mock repository details
            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                # Mock artifact existence check
                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_artifact_exists') as mock_check_exists:
                    mock_check_exists.return_value = False

                    # Mock perform_upload
                    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.perform_upload') as mock_upload:
                        mock_upload.return_value = (True, 201, "Upload successful")

                        # Test successful upload
                        from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
                        main()

                        # Verify module exit
                        mock_module.exit_json.assert_called_once()
                        call_args = mock_module.exit_json.call_args[1]
                        assert call_args['changed'] is True
                        assert call_args['msg'] == "Artifact upload successful"
                        assert call_args['status_code'] == 201

        # Test existing artifact
        mock_module.check_mode = False
        mock_module.exit_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_artifact_exists') as mock_check_exists:
                    mock_check_exists.return_value = True

                    main()

                    # Verify no upload when artifact exists
                    mock_module.exit_json.assert_called_once()
                    call_args = mock_module.exit_json.call_args[1]
                    assert call_args['changed'] is False
                    assert call_args['msg'] == "Artifact already exists in repository"

        # Test repository error
        mock_module.fail_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.side_effect = RepositoryError("Repository not found")

                main()

                # Verify error handling
                mock_module.fail_json.assert_called_once()
                call_args = mock_module.fail_json.call_args[1]
                assert call_args['msg'] == "Repository not found"
                assert call_args['error']['type'] == 'artifact'

    def test_main_error_handling(self, tmp_path):
        """Test main function error handling"""
        mock_module, test_file = self._setup_mock_module(tmp_path)
        mock_module.check_mode = False

        # Test RepositoryError handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
             patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:

            mock_repo_details.side_effect = RepositoryError("Repository not accessible")

            from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "Repository not accessible"
            assert call_args['error']['type'] == 'artifact'
            assert call_args['error']['details'] == "Repository not accessible"

        # Reset mocks
        mock_module.fail_json.reset_mock()

        # Test ArtifactError handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
             patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details', return_value=('raw', 'hosted')), \
             patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_artifact_exists') as mock_check:

            mock_check.side_effect = ArtifactError("Failed to check artifact")

            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "Failed to check artifact"
            assert call_args['error']['type'] == 'artifact'
            assert call_args['error']['details'] == "Failed to check artifact"

        # Reset mocks
        mock_module.fail_json.reset_mock()

        # Test unexpected exception handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
             patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:

            mock_repo_details.side_effect = Exception("Unexpected error occurred")

            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "An unexpected error occurred: Unexpected error occurred"
            assert call_args['error']['type'] == 'unexpected'
            assert call_args['error']['details'] == "Unexpected error occurred"

    def _setup_mock_module(self, tmp_path):
        """Helper to setup mock module with test parameters"""
        test_file = tmp_path / "test-artifact.txt"
        test_file.write_text("test content")

        module_params = {
            'repository': 'https://nexus.example.com/repository/raw-hosted',
            'name': 'test-artifact.txt',
            'src': str(test_file),
            'dest': '/upload/path',
            'validate_certs': False,
            'timeout': 30,
            'username': 'testuser',
            'password': 'testpass',
            'token': None
        }

        mock_module = MagicMock()
        mock_module.params = module_params
        mock_module.fail_json = MagicMock()
        mock_module.exit_json = MagicMock()

        return mock_module, test_file


# TODO: test aliases for raw_component module

# class TestUploadArtifactCheckMode:
#     """Tests for raw_component module check mode behavior"""

#     @pytest.fixture(autouse=True)
#     def setup_imports(self):
#         """Setup imports for each test"""
#         if 'ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component' in sys.modules:
#             del sys.modules['ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component']

#     def _setup_mock_module(self, tmp_path):
#         """Helper to setup mock module with test parameters"""
#         # Create test file content directly without opening file
#         test_file = tmp_path / "test-artifact.txt"
#         test_file.write_text("test content")

#         module_params = {
#             'repository': 'https://nexus.example.com/repository/raw-hosted',
#             'name': 'test-artifact.txt',
#             'src': str(test_file),
#             'dest': '/upload/path',
#             'validate_certs': False,
#             'timeout': 30,
#             'username': 'testuser',
#             'password': 'testpass',
#             'token': None
#         }

#         # Setup mock module
#         mock_module = MagicMock()
#         mock_module.params = module_params
#         mock_module.check_mode = True

#         # Mock file operations
#         mock_file = mock_open(read_data="test content")
#         mock_module.mock_add_spec(['exit_json', 'fail_json', 'params', 'check_mode'])

#         return mock_module, test_file

#     def test_check_mode_existing_artifact(self, tmp_path):
#         """Test check mode when artifact exists"""
#         mock_module, test_file = self._setup_mock_module(tmp_path)

#         with patch('builtins.open', mock_open(read_data="test content")), \
#              patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
#              patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details', return_value=('raw', 'hosted')), \
#              patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_artifact_exists', return_value=True):

#             from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
#             main()

#             mock_module.exit_json.assert_called_once()
#             call_args = mock_module.exit_json.call_args[1]
#             assert call_args['changed'] is False
#             assert "exists" in call_args['msg']
#             assert call_args['exists'] is True

#     def test_check_mode_new_artifact(self, tmp_path):
#         """Test check mode when artifact doesn't exist"""
#         mock_module, test_file = self._setup_mock_module(tmp_path)

#         with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
#              patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details', return_value=('raw', 'hosted')), \
#              patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_artifact_exists', return_value=False):

#             from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
#             main()

#             mock_module.exit_json.assert_called_once()
#             call_args = mock_module.exit_json.call_args[1]
#             assert call_args['changed'] is True
#             assert "would be uploaded (check mode)" in call_args['msg']
#             assert 'base_url' in call_args
#             assert 'repository_name' in call_args
#             assert call_args['details']['repository_format'] == 'raw'
#             assert call_args['details']['repository_type'] == 'hosted'
