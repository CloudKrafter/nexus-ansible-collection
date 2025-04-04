#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import pytest
from unittest.mock import MagicMock, patch

from ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info import (
    get_node_id,
    get_system_info,
    format_node_info,
    main
)
from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import RepositoryError


class TestNexusInfoModule:
    """Tests for nexus_info module"""

    def test_get_node_id(self):
        """Test getting node ID"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "nodeId": "1656c370-0cd3-4867-a077-f64ba13e4ec3"
        }).encode('utf-8')
        # Mock the headers with Nexus server information
        mock_response.headers = {
            'Server': 'Nexus/3.79.0-09 (COMMUNITY)'
        }

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            result = get_node_id(
                base_url='http://localhost:8081',
                headers={'accept': 'application/json'},
                validate_certs=True
            )

            # Assert the structure and content of the result
            assert result == {
                'node_id': '1656c370-0cd3-4867-a077-f64ba13e4ec3',
                'version': '3.79.0-09',
                'edition': 'COMMUNITY'
            }

            mock_open_url.assert_called_once_with(
                'http://localhost:8081/service/rest/v1/system/node',
                headers={'accept': 'application/json'},
                validate_certs=True,
                method='GET'
            )

    def test_get_node_id_no_server_header(self):
        """Test getting node ID with missing server header"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "nodeId": "1656c370-0cd3-4867-a077-f64ba13e4ec3"
        }).encode('utf-8')
        # Empty headers
        mock_response.headers = {}

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            result = get_node_id(
                base_url='http://localhost:8081',
                headers={'accept': 'application/json'},
                validate_certs=True
            )

            # Assert default values are returned when header is missing
            assert result == {
                'node_id': '1656c370-0cd3-4867-a077-f64ba13e4ec3',
                'version': 'unknown',
                'edition': 'unknown'
            }

    def test_get_system_info(self):
        """Test getting system information"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "nexus-status": {
                "1656c370-0cd3-4867-a077-f64ba13e4ec3": {
                    "edition": "OSS",
                    "version": "3.77.1-01"
                }
            }
        }).encode('utf-8')

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            result = get_system_info(
                base_url='http://localhost:8081',
                headers={'accept': 'application/json'},
                validate_certs=True
            )

            assert result["nexus-status"]["1656c370-0cd3-4867-a077-f64ba13e4ec3"]["edition"] == "OSS"
            mock_open_url.assert_called_once()

    def test_format_node_info(self):
        """Test formatting node information"""
        node_id = "1656c370-0cd3-4867-a077-f64ba13e4ec3"
        system_info = {
            "nexus-status": {
                node_id: {
                    "edition": "OSS",
                    "version": "3.77.1-01"
                }
            },
            "system-network": {
                node_id: {
                    "lo": {
                        "up": True,
                        "mtu": 65536
                    }
                }
            }
        }

        result = format_node_info(node_id, system_info)

        assert result["node_id"] == node_id
        assert result["node_info"]["nexus-status"]["edition"] == "OSS"
        assert result["node_info"]["system-network"]["lo"]["mtu"] == 65536

    def test_main_function(self):
        """Test main function execution"""
        module_args = {
            'url': 'http://localhost:8081',
            'username': 'admin',
            'password': 'admin123',
            'validate_certs': True
        }

        mock_module = MagicMock()
        mock_module.params = module_args
        mock_module.check_mode = False

        node_id = "1656c370-0cd3-4867-a077-f64ba13e4ec3"
        system_info = {
            "nexus-status": {
                node_id: {
                    "edition": "OSS",
                    "version": "3.77.1-01"
                }
            }
        }

        with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.AnsibleModule') as mock_ansible_module, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.get_node_id') as mock_get_node_id, \
                patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.get_system_info') as mock_get_system_info:

            mock_ansible_module.return_value = mock_module
            mock_get_node_id.return_value = node_id
            mock_get_system_info.return_value = system_info

            main()

            mock_module.fail_json.assert_not_called()
            mock_module.exit_json.assert_called_once()

            call_args = mock_module.exit_json.call_args[1]
            assert call_args['changed'] is False
            assert call_args['ansible_facts']['nexus_info']['node_id'] == node_id
            assert call_args['ansible_facts']['nexus_info']['node_info']['nexus-status']['edition'] == "OSS"

    def test_error_handling(self):
        """Test error handling in API calls"""
        with pytest.raises(RepositoryError) as excinfo:
            with patch('ansible_collections.cloudkrafter.nexus.plugins.modules.nexus_info.open_url') as mock_open_url:
                mock_open_url.side_effect = Exception("API Error")

                get_node_id(
                    base_url='http://localhost:8081',
                    headers={'accept': 'application/json'},
                    validate_certs=True
                )

        assert "Failed to get node ID: API Error" in str(excinfo.value)
