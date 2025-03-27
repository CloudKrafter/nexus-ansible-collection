#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from unittest.mock import MagicMock, patch
import pytest
from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import (
    perform_upload
)
from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    create_auth_headers,
    ComponentError,
    RepositoryError
)


class TestRawComponentModule:
    """Tests for raw_component module"""

    def test_perform_upload(self, tmp_path):
        """Test component upload functionality"""
        # Setup test data
        url = "https://nexus.example.com/service/rest/v1/components?repository=raw-hosted"
        name = "test-file.txt"
        dest = "/path/to/dest"
        headers = create_auth_headers(username="user", password="pass")
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
        with pytest.raises(ComponentError, match="Source file not found"):
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

            with pytest.raises(ComponentError, match="Upload failed: Connection refused"):
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
        test_file = tmp_path / "test-component.txt"
        test_file.write_text("test content")

        # Basic module parameters
        module_params = {
            'state': 'present',
            'repository': 'https://nexus.example.com/repository/raw-hosted',
            'name': 'test-component.txt',
            'src': str(test_file),
            'dest': '/upload/path',
            'validate_certs': False,
            'timeout': 30,
            'username': 'testuser',
            'password': 'testpass'
        }

        # Mock AnsibleModule
        mock_module = MagicMock()
        mock_module.params = module_params
        mock_module.check_mode = False
        mock_module.exit_json.reset_mock()
        mock_module.fail_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            # Mock repository details
            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                # Mock component existence check
                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:
                    mock_check_exists.return_value = (False, None)

                    # Mock perform_upload
                    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.perform_upload') as mock_upload:
                        mock_upload.return_value = (
                            True, 201, "Upload successful")

                        # Test successful upload
                        from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
                        main()

                        # Verify module exit
                        mock_module.exit_json.assert_called_once()
                        call_args = mock_module.exit_json.call_args[1]
                        assert call_args['changed'] is True
                        assert call_args['msg'] == "Component upload successful"
                        assert call_args['status_code'] == 201

        # Test existing component
        mock_module.check_mode = False
        mock_module.exit_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:
                    mock_check_exists.return_value = (
                        True, 'cmF3LWhvc3RlZDo0ZjFiYmNkZA')

                    main()

                    # Verify no upload when component exists
                    mock_module.exit_json.assert_called_once()
                    call_args = mock_module.exit_json.call_args[1]
                    assert call_args['changed'] is False
                    assert call_args['msg'] == "Component already exists in repository"
                    assert call_args['details']['component_id'] == 'cmF3LWhvc3RlZDo0ZjFiYmNkZA'

        # Test successful component deletion
        mock_module.params['state'] = 'absent'
        mock_module.check_mode = False
        mock_module.exit_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:
                    mock_check_exists.return_value = (True, 'component-id-123')

                    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.delete_component_by_id') as mock_delete:
                        mock_delete.return_value = True

                        from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
                        main()

                        # Verify successful deletion
                        mock_module.exit_json.assert_called_once()
                        call_args = mock_module.exit_json.call_args[1]
                        assert call_args['changed'] is True
                        assert call_args['msg'] == "Component deleted successfully"
                        assert call_args['details']['component_id'] == 'component-id-123'

        # Test deletion of non-existent component
        mock_module.exit_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:
                    mock_check_exists.return_value = (False, None)

                    main()

                    # Verify no deletion attempted
                    mock_module.exit_json.assert_called_once()
                    call_args = mock_module.exit_json.call_args[1]
                    assert call_args['changed'] is False
                    assert call_args['msg'] == "Component does not exist in repository"

        # Test failed deletion
        mock_module.exit_json.reset_mock()
        mock_module.fail_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.return_value = ('raw', 'hosted')

                with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:
                    mock_check_exists.return_value = (True, 'component-id-123')

                    with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.delete_component_by_id') as mock_delete:
                        mock_delete.return_value = False

                        main()

                        # Verify failed deletion
                        mock_module.fail_json.assert_called_once()
                        call_args = mock_module.fail_json.call_args[1]
                        assert call_args['changed'] is False
                        assert call_args['msg'] == "Failed to delete component"

        # Test repository error
        mock_module.fail_json.reset_mock()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module:
            mock_ansible_module.return_value = mock_module

            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:
                mock_repo_details.side_effect = RepositoryError(
                    "Repository not found")

                main()

                # Verify error handling
                mock_module.fail_json.assert_called_once()
                call_args = mock_module.fail_json.call_args[1]
                assert call_args['msg'] == "Repository not found"
                assert call_args['error']['type'] == 'component'

    def test_main_error_handling(self, tmp_path):
        """Test main function error handling"""
        mock_module, test_file = self._setup_mock_module(tmp_path)
        mock_module.check_mode = False

        # Test RepositoryError handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:

            mock_repo_details.side_effect = RepositoryError(
                "Repository not accessible")

            from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main
            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "Repository not accessible"
            assert call_args['error']['type'] == 'component'
            assert call_args['error']['details'] == "Repository not accessible"

        # Reset mocks
        mock_module.fail_json.reset_mock()

        # Test ComponentError handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details', return_value=('raw', 'hosted')), \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check:

            mock_check.side_effect = ComponentError(
                "Failed to check component")

            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "Failed to check component"
            assert call_args['error']['type'] == 'component'
            assert call_args['error']['details'] == "Failed to check component"

        # Reset mocks
        mock_module.fail_json.reset_mock()

        # Test unexpected exception handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule', return_value=mock_module), \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details:

            mock_repo_details.side_effect = Exception(
                "Unexpected error occurred")

            main()

            mock_module.fail_json.assert_called_once()
            call_args = mock_module.fail_json.call_args[1]
            assert call_args['msg'] == "An unexpected error occurred: Unexpected error occurred"
            assert call_args['error']['type'] == 'unexpected'
            assert call_args['error']['details'] == "Unexpected error occurred"

    def _setup_mock_module(self, tmp_path):
        """Helper to setup mock module with test parameters"""
        test_file = tmp_path / "test-component.txt"
        test_file.write_text("test content")

        module_params = {
            'repository': 'https://nexus.example.com/repository/raw-hosted',
            'name': 'test-component.txt',
            'src': str(test_file),
            'dest': '/upload/path',
            'validate_certs': False,
            'timeout': 30,
            'username': 'testuser',
            'password': 'testpass'
        }

        mock_module = MagicMock()
        mock_module.params = module_params
        mock_module.fail_json = MagicMock()
        mock_module.exit_json = MagicMock()

        return mock_module, test_file

    def test_check_mode(self, tmp_path):
        """Test check mode behavior for both present and absent states"""
        from ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component import main

        # Create a test file
        test_file = tmp_path / "test-component.txt"
        test_file.write_text("test content")

        # Basic module parameters
        module_params = {
            'state': 'present',
            'repository': 'https://nexus.example.com/repository/raw-hosted',
            'name': 'test-component.txt',
            'src': str(test_file),
            'dest': '/upload/path',
            'validate_certs': False,
            'timeout': 30,
            'username': 'testuser',
            'password': 'testpass'
        }

        # Test check mode for state=present, component doesn't exist
        mock_module = MagicMock()
        mock_module.params = module_params.copy()
        mock_module.check_mode = True

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:

            mock_ansible_module.return_value = mock_module
            mock_repo_details.return_value = ('raw', 'hosted')
            mock_check_exists.return_value = (False, None)

            main()

            # Verify check mode behavior for upload
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is True
            assert call_args['msg'] == "Component would be uploaded (check mode)"
            assert not call_args['exists']

        # Test check mode for state=present, component exists
        mock_module.exit_json.reset_mock()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:

            mock_ansible_module.return_value = mock_module
            mock_repo_details.return_value = ('raw', 'hosted')
            mock_check_exists.return_value = (True, 'test-component-id')

            main()

            # Verify check mode behavior for existing component
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is False
            assert call_args['msg'] == "Component already exists in repository"
            assert call_args['exists'] is True
            assert call_args['details']['component_id'] == 'test-component-id'

        # Test check mode for state=absent, component exists
        mock_module.params['state'] = 'absent'
        mock_module.exit_json.reset_mock()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:

            mock_ansible_module.return_value = mock_module
            mock_repo_details.return_value = ('raw', 'hosted')
            mock_check_exists.return_value = (True, 'test-component-id')

            main()

            # Verify check mode behavior for deletion
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is True
            assert call_args['msg'] == "Component would have been deleted (if not in check mode)"
            assert call_args['exists'] is True
            assert call_args['details']['component_id'] == 'test-component-id'

        # Test check mode for state=absent, component doesn't exist
        mock_module.exit_json.reset_mock()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.get_repository_details') as mock_repo_details, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.raw_component.check_component_exists') as mock_check_exists:

            mock_ansible_module.return_value = mock_module
            mock_repo_details.return_value = ('raw', 'hosted')
            mock_check_exists.return_value = (False, None)

            main()

            # Verify check mode behavior for non-existent component
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is False
            assert call_args['msg'] == "Component does not exist in repository"
            assert not call_args['exists']
