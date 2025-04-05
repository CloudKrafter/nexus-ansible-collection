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
from ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens import (
    get_token_settings,
    update_token_settings
)
from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    RepositoryError
)


class TestConfigUserTokensModule:
    """Tests for user_tokens module"""

    def test_get_token_settings(self):
        """Test getting token settings from Nexus API"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "enabled": True,
            "protectContent": True,
            "expirationEnabled": True,
            "expirationDays": 30
        }).encode('utf-8')

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            # Test successful API call
            result = get_token_settings(
                base_url='http://nexus.example.com',
                headers={'accept': 'application/json'},
                validate_certs=True,
                timeout=30
            )

            # Verify API call
            mock_open_url.assert_called_once_with(
                'http://nexus.example.com/service/rest/v1/security/user-tokens',
                headers={'accept': 'application/json'},
                validate_certs=True,
                timeout=30,
                method='GET'
            )

            # Verify response parsing
            assert result['enabled'] is True
            assert result['protectContent'] is True
            assert result['expirationEnabled'] is True
            assert result['expirationDays'] == 30

        # Test error handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.open_url') as mock_open_url:
            mock_open_url.side_effect = Exception("API Error")

            with pytest.raises(RepositoryError) as excinfo:
                get_token_settings(
                    base_url='http://nexus.example.com',
                    headers={'accept': 'application/json'},
                    validate_certs=True,
                    timeout=30
                )

            assert "Failed to get token settings: API Error" in str(excinfo.value)

    def test_update_token_settings(self):
        """Test updating token settings via Nexus API"""
        # Setup test data
        test_settings = {
            "enabled": True,
            "protectContent": True,
            "expirationEnabled": True,
            "expirationDays": 90
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            test_settings).encode('utf-8')

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            # Test successful API call
            result = update_token_settings(
                base_url='http://nexus.example.com',
                settings=test_settings,
                headers={
                    'accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                validate_certs=True,
                timeout=30
            )

            # Verify API call
            mock_open_url.assert_called_once_with(
                'http://nexus.example.com/service/rest/v1/security/user-tokens',
                data=json.dumps(test_settings).encode('utf-8'),
                headers={
                    'accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                validate_certs=True,
                timeout=30,
                method='PUT'
            )

            # Verify response parsing
            assert result['enabled'] is True
            assert result['protectContent'] is True
            assert result['expirationEnabled'] is True
            assert result['expirationDays'] == 90

        # Test error handling
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.open_url') as mock_open_url:
            mock_open_url.side_effect = Exception("API Error")

            with pytest.raises(RepositoryError) as excinfo:
                update_token_settings(
                    base_url='http://nexus.example.com',
                    settings=test_settings,
                    headers={'accept': 'application/json'},
                    validate_certs=True,
                    timeout=30
                )

            assert "Failed to update token settings: API Error" in str(
                excinfo.value)

    def test_main_function(self):
        """Test main function execution paths"""
        # Mock module setup
        module_args = {
            'state': 'present',
            'required_for_auth': True,
            'expire_tokens': True,
            'expiration_days': 90,
            'url': 'http://nexus.example.com',
            'username': 'admin',
            'password': 'password123',
            'validate_certs': True,
            'timeout': 30
        }

        # Create fresh mock module for each test
        def setup_mock_module():
            mock_module = MagicMock()
            mock_module.params = module_args.copy()
            mock_module.check_mode = False
            mock_module.fail_json.reset_mock()
            mock_module.exit_json.reset_mock()
            return mock_module

        # Mock API responses
        current_settings = {
            "enabled": False,
            "protectContent": False,
            "expirationEnabled": False,
            "expirationDays": 30
        }

        updated_settings = {
            "enabled": True,
            "protectContent": True,
            "expirationEnabled": True,
            "expirationDays": 90
        }

        # Test successful update
        mock_module = setup_mock_module()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.get_token_settings') as mock_get_settings, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.update_token_settings') as mock_update_settings:

            mock_ansible_module.return_value = mock_module
            mock_get_settings.return_value = current_settings
            mock_update_settings.return_value = updated_settings

            from ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens import main
            main()

            mock_module.fail_json.assert_not_called()
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is True
            assert call_args['settings'] == current_settings

        # Test no changes needed
        mock_module = setup_mock_module()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.get_token_settings') as mock_get_settings:

            mock_ansible_module.return_value = mock_module
            mock_get_settings.return_value = updated_settings

            main()

            mock_module.fail_json.assert_not_called()
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is False
            assert call_args['settings'] == updated_settings

        # Test check mode
        mock_module = setup_mock_module()
        mock_module.check_mode = True
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.get_token_settings') as mock_get_settings:

            mock_ansible_module.return_value = mock_module
            mock_get_settings.return_value = current_settings

            main()

            mock_module.fail_json.assert_not_called()
            mock_module.exit_json.assert_called_once()
            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is True
            assert call_args['settings'] == current_settings

        # Test error handling
        mock_module = setup_mock_module()
        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.config_user_tokens.get_token_settings') as mock_get_settings:

            mock_ansible_module.return_value = mock_module
            mock_get_settings.side_effect = Exception("Test error")

            main()

            mock_module.exit_json.assert_not_called()
            mock_module.fail_json.assert_called_once_with(msg="Test error")
