# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from datetime import (
    datetime,
    timedelta
)
import json
from ansible.module_utils.urls import (
    open_url
)


class RepositoryCache:
    """Cache for repository configurations"""
    _instance = None
    _cache = {}
    _last_update = None
    _cache_ttl = 300  # 5 minutes

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RepositoryCache, cls).__new__(cls)
        return cls._instance

    def get_repository(self, base_url, name, type=None, format=None, headers=None, validate_certs=True, timeout=30):
        """Get repository from cache or API"""
        # Check if cache needs refresh
        if self._needs_refresh():
            self._refresh_cache(base_url, headers, validate_certs, timeout)

        # Look for repository in cache
        for cache_key, repo in self._cache.items():
            if (repo['name'] == name and
                (format is None or repo['format'] == format) and
                    (type is None or repo['type'] == type)):
                return repo

        return None

    def _needs_refresh(self):
        """Check if cache needs to be refreshed"""
        if not self._last_update:
            return True

        return datetime.now() - self._last_update > timedelta(seconds=self._cache_ttl)

    def _refresh_cache(self, base_url, headers, validate_certs, timeout):
        """Refresh cache from API"""
        url = f"{base_url}/service/rest/v1/repositorySettings"

        try:
            response = open_url(
                url,
                headers=headers,
                validate_certs=validate_certs,
                timeout=timeout,
                method='GET'
            )
            repositories = json.loads(response.read())

            # Update cache
            self._cache = {
                f"{base_url}:{repo['format']}:{repo['type']}:{repo['name']}": repo
                for repo in repositories
            }
            self._last_update = datetime.now()
        except Exception:
            # On failure, invalidate cache
            self._cache = {}
            self._last_update = None
            raise
