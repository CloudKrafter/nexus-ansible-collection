#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import pytest
from ansible.errors import AnsibleFilterError
from ansible_collections.cloudkrafter.nexus.plugins.filter.normalize_repositories import (
    FilterModule,
    get_nested_value,
    merge_defaults,
    normalize_and_clean_repositories_with_explicit_cleanup
)


class TestNormalizeRepositoriesFilter:
    """Tests for normalize_repositories filter"""

    def setup_method(self):
        """Set up test fixtures"""
        # Minimal defaults for testing
        self.global_defaults = {
            "online": True,
            "storage": {
                "blobStoreName": "default"
            }
        }

        self.type_defaults = {
            "proxy": {
                "httpClient": {
                    "authentication": None
                }
            },
            "hosted": {},
            "group": {}
        }

        self.format_defaults = {
            "maven": {
                "maven": {
                    "versionPolicy": "RELEASE",
                    "layoutPolicy": "STRICT"
                }
            }
        }

        self.legacy_field_map = {
            "write_policy": "storage.writePolicy",
            "blob_store": "storage.blobStoreName"
        }

    def test_get_nested_value_no_default_shadowing(self):
        """Test that get_nested_value doesn't shadow the 'default' filter"""
        # This test ensures the parameter is named 'default_value' not 'default'
        data = {"level1": {"level2": {"level3": "value"}}}

        # Test retrieval with default_value parameter
        result = get_nested_value(data, "level1.level2.level3", default_value="fallback")
        assert result == "value"

        # Test missing key with default_value
        result = get_nested_value(data, "level1.missing.key", default_value="fallback")
        assert result == "fallback"

        # Test with None as default_value
        result = get_nested_value(data, "missing.path", default_value=None)
        assert result is None

    def test_normalize_repositories_with_maven_central(self):
        """Test normalize_repositories with maven-central repository"""
        # This is the problematic repository mentioned in the issue
        maven_central_repo = {
            "name": "maven-central",
            "format": "maven2",
            "type": "proxy",
            "remoteUrl": "https://repo1.maven.org/maven2/",
            "online": True
        }

        result = normalize_and_clean_repositories_with_explicit_cleanup(
            [maven_central_repo],
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == "maven-central"
        assert result[0]["online"] is True

    def test_normalize_repositories_with_none_input(self):
        """Test that None input returns empty list"""
        result = normalize_and_clean_repositories_with_explicit_cleanup(
            None,
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert result == []

    def test_normalize_repositories_with_single_dict(self):
        """Test that single dict input is converted to list"""
        single_repo = {
            "name": "test-repo",
            "format": "maven2",
            "type": "hosted"
        }

        result = normalize_and_clean_repositories_with_explicit_cleanup(
            single_repo,
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "hosted",
            "maven",
            self.legacy_field_map
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == "test-repo"

    def test_normalize_repositories_with_empty_list(self):
        """Test that empty list returns empty list"""
        result = normalize_and_clean_repositories_with_explicit_cleanup(
            [],
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert result == []

    def test_normalize_repositories_with_multiple_repos(self):
        """Test normalization with multiple repositories"""
        repos = [
            {
                "name": "maven-central",
                "format": "maven2",
                "type": "proxy",
                "remoteUrl": "https://repo1.maven.org/maven2/"
            },
            {
                "name": "maven-releases",
                "format": "maven2",
                "type": "hosted"
            }
        ]

        result = normalize_and_clean_repositories_with_explicit_cleanup(
            repos,
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "maven-central"
        assert result[1]["name"] == "maven-releases"

    def test_normalize_repositories_invalid_input_type(self):
        """Test that invalid input type raises AnsibleFilterError"""
        with pytest.raises(AnsibleFilterError, match="normalize_repositories expected a list"):
            normalize_and_clean_repositories_with_explicit_cleanup(
                "invalid string input",
                self.global_defaults,
                self.type_defaults,
                self.format_defaults,
                "proxy",
                "maven",
                self.legacy_field_map
            )

    def test_normalize_repositories_invalid_repo_type(self):
        """Test that non-dict repository raises AnsibleFilterError"""
        with pytest.raises(AnsibleFilterError, match="Each repository entry must be a dict"):
            normalize_and_clean_repositories_with_explicit_cleanup(
                ["not a dict", "also not a dict"],
                self.global_defaults,
                self.type_defaults,
                self.format_defaults,
                "proxy",
                "maven",
                self.legacy_field_map
            )

    def test_normalize_repositories_with_legacy_fields(self):
        """Test that legacy fields are properly normalized and cleaned"""
        repo = {
            "name": "test-repo",
            "format": "maven2",
            "type": "hosted",
            "blob_store": "custom-blob",  # legacy field
            "write_policy": "ALLOW"  # legacy field
        }

        result = normalize_and_clean_repositories_with_explicit_cleanup(
            [repo],
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "hosted",
            "maven",
            self.legacy_field_map
        )

        assert isinstance(result, list)
        assert len(result) == 1
        # Legacy fields should be removed after normalization
        assert "blob_store" not in result[0]
        assert "write_policy" not in result[0]
        # But their normalized versions should exist
        assert "storage" in result[0]
        assert result[0]["storage"]["blobStoreName"] == "custom-blob"

    def test_filter_module_registration(self):
        """Test that the filter is properly registered"""
        filter_module = FilterModule()
        filters = filter_module.filters()

        assert "normalize_repositories" in filters
        assert callable(filters["normalize_repositories"])
        assert filters["normalize_repositories"] == normalize_and_clean_repositories_with_explicit_cleanup

    def test_merge_defaults_with_proxy_auth(self):
        """Test merge_defaults handles proxy authentication correctly"""
        repo = {
            "name": "test-proxy",
            "format": "maven2",
            "type": "proxy",
            "remoteUrl": "https://example.com/repo",
            "httpClient": {
                "authentication": {
                    "username": "user",
                    "password": "pass"
                }
            }
        }

        result = merge_defaults(
            repo,
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert "httpClient" in result
        assert "authentication" in result["httpClient"]
        assert result["httpClient"]["authentication"]["type"] == "username"

    def test_normalize_repositories_comprehensive_maven_central(self):
        """Comprehensive test with realistic maven-central configuration"""
        # This test simulates the actual problematic case from the CI
        maven_central = {
            "name": "maven-central",
            "format": "maven2",
            "type": "proxy",
            "remoteUrl": "https://repo1.maven.org/maven2/",
            "online": True,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": True
            },
            "proxy": {
                "remoteUrl": "https://repo1.maven.org/maven2/",
                "contentMaxAge": 1440,
                "metadataMaxAge": 1440
            },
            "negativeCache": {
                "enabled": True,
                "timeToLive": 1440
            },
            "httpClient": {
                "blocked": False,
                "autoBlock": True
            },
            "maven": {
                "versionPolicy": "RELEASE",
                "layoutPolicy": "STRICT"
            }
        }

        result = normalize_and_clean_repositories_with_explicit_cleanup(
            [maven_central],
            self.global_defaults,
            self.type_defaults,
            self.format_defaults,
            "proxy",
            "maven",
            self.legacy_field_map
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == "maven-central"
        assert result[0]["format"] == "maven2"
        assert result[0]["type"] == "proxy"
        assert result[0]["online"] is True
        # Verify maven settings are uppercase as per UPPERCASE_FIELDS
        assert result[0]["maven"]["versionPolicy"] == "RELEASE"
        assert result[0]["maven"]["layoutPolicy"] == "STRICT"
