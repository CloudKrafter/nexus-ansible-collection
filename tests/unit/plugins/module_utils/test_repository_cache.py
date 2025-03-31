#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from datetime import (
    datetime,
    timedelta
)
from unittest.mock import MagicMock, patch

import pytest

from ansible_collections.cloudkrafter.nexus.plugins.module_utils.repository_cache import RepositoryCache


class TestRepositoryCache:
    """Test cases for RepositoryCache utility"""

    @pytest.fixture
    def cache(self):
        """Fixture to provide clean cache instance"""
        cache = RepositoryCache()
        cache._cache = {}
        cache._last_update = None
        return cache

    @pytest.fixture
    def mock_repo_data(self):
        """Fixture providing sample repository data"""
        return [
            {
                "name": "test-repo",
                "format": "npm",
                "type": "proxy",
                "url": "http://localhost:8081/repository/test-repo",
                "online": True
            }
        ]

    def test_singleton_pattern(self):
        """Test that RepositoryCache is a singleton"""
        cache1 = RepositoryCache()
        cache2 = RepositoryCache()
        assert cache1 is cache2

    def test_needs_refresh_initial(self, cache):
        """Test _needs_refresh returns True on initial state"""
        assert cache._needs_refresh() is True

    def test_needs_refresh_recent(self, cache):
        """Test _needs_refresh returns False for recent updates"""
        cache._last_update = datetime.now()
        assert cache._needs_refresh() is False

    def test_needs_refresh_expired(self, cache):
        """Test _needs_refresh returns True for expired cache"""
        cache._last_update = datetime.now() - timedelta(seconds=301)  # TTL + 1
        assert cache._needs_refresh() is True

    def test_get_repository_with_format_and_type(self, cache):
        """Test getting repository with format and type filtering"""
        # Setup cache with multiple repositories
        cache._cache = {
            "http://localhost:8081:npm:proxy:test-repo": {
                "name": "test-repo",
                "format": "npm",
                "type": "proxy"
            },
            "http://localhost:8081:npm:hosted:test-repo": {
                "name": "test-repo",
                "format": "npm",
                "type": "hosted"
            }
        }
        cache._last_update = datetime.now()

        # Test specific format and type
        result = cache.get_repository(
            "http://localhost:8081",
            "test-repo",
            format="npm",
            type="proxy",
            headers={},
            validate_certs=True,
            timeout=30
        )

        assert result["type"] == "proxy"
        assert result["format"] == "npm"
        assert result["name"] == "test-repo"

    def test_get_repository_no_match(self, cache, mock_repo_data):
        """Test getting non-existent repository"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            mock_repo_data).encode('utf-8')

        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.repository_cache.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            result = cache.get_repository(
                "http://localhost:8081",
                "non-existent",
                format="maven",
                type="proxy",
                headers={"accept": "application/json"},
                validate_certs=True,
                timeout=30
            )

            assert result is None

    def test_get_repository_refresh(self, cache, mock_repo_data):
        """Test getting repository with cache refresh"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            mock_repo_data).encode('utf-8')

        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.repository_cache.open_url') as mock_open_url:
            mock_open_url.return_value = mock_response

            result = cache.get_repository(
                base_url="http://localhost:8081",
                name="test-repo",
                format="npm",
                type="proxy",
                headers={"accept": "application/json"},
                validate_certs=True,
                timeout=30
            )

            # Verify result
            assert result["name"] == "test-repo"
            assert result["format"] == "npm"
            assert result["type"] == "proxy"

            # Verify API call
            mock_open_url.assert_called_once_with(
                'http://localhost:8081/service/rest/v1/repositorySettings',
                headers={"accept": "application/json"},
                validate_certs=True,
                timeout=30,
                method='GET'
            )

    def test_refresh_cache_error(self, cache):
        """Test cache invalidation on refresh error"""
        cache._cache = {
            "http://localhost:8081:npm:proxy:test-repo": {
                "name": "test-repo",
                "format": "npm",
                "type": "proxy"
            }
        }
        cache._last_update = datetime.now()

        with patch('ansible_collections.cloudkrafter.nexus.plugins.module_utils.repository_cache.open_url') as mock_open_url:
            mock_open_url.side_effect = Exception("API Error")

            with pytest.raises(Exception) as excinfo:
                cache._refresh_cache(
                    base_url="http://localhost:8081",
                    headers={},
                    validate_certs=True,
                    timeout=30
                )

            assert "API Error" in str(excinfo.value)
            assert cache._cache == {}
            assert cache._last_update is None
