#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''
---
module: gather_info
short_description: Gather Nexus system information of a single node
description:
  - Queries Sonatype Nexus REST API to retrieve system node ID and detailed system information.
  - Useful for collecting version, edition, and network details about a single Nexus node.
version_added: "1.23.0"
options:
  url:
    description:
      - Base URL of the Nexus instance (e.g. https://localhost:9091).
      - Do not use an URL that points to a load balancer, as this module is designed to query a single node.
    required: true
    type: str
  username:
    description:
      - Username to authenticate with Nexus.
    required: true
    type: str
  password:
    description:
      - Password to authenticate with Nexus.
    required: true
    type: str
  validate_certs:
    description:
      - Whether to validate SSL certificates.
    required: false
    type: bool
    default: true
author:
  - "Brian Veltman (@cloudkrafter)"
'''

EXAMPLES = '''
- name: Gather Nexus information
  cloudkrafter.nexus.gather_info:
    url: "https://localhost:9091"
    username: "admin"
    password: "admin123"
    validate_certs: false
  register: nexus_instance

- debug:
    var: nexus_instance.node
'''

RETURN = '''
node:
  description: Aggregated Nexus node information
  returned: always
  type: dict
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils._text import to_native

from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    create_auth_headers,
    RepositoryError
)
import json


def get_node_id(base_url, headers, validate_certs):
    """Get the Nexus node ID."""
    url = f"{base_url}/service/rest/v1/system/node"

    try:
        response = open_url(
            url,
            headers=headers,
            validate_certs=validate_certs,
            method='GET'
        )
        result = json.loads(response.read())

        # Extract version info from headers
        server_header = response.headers.get('Server', '')
        edition = 'unknown'
        version_part = 'unknown'

        if 'Nexus/' in server_header:
            # Split "Nexus/3.79.0-09 (COMMUNITY)" into parts
            version_part = server_header.split('Nexus/')[1].split(' ')[0]
            edition_match = server_header.find('(')
            if edition_match != -1:
                edition = server_header[edition_match + 1:].rstrip(')')

        return {
            'node_id': result.get('nodeId'),
            'version': version_part,
            'edition': edition
        }
    except Exception as e:
        raise RepositoryError(f"Failed to get node ID: {to_native(e)}") from e


def get_system_info(base_url, headers, validate_certs):
    """Get detailed system information."""
    url = f"{base_url}/service/rest/beta/system/information"

    try:
        response = open_url(
            url,
            headers=headers,
            validate_certs=validate_certs,
            method='GET'
        )
        return json.loads(response.read())
    except Exception as e:
        # Return None if the endpoint fails
        return None


def format_node_info(node_data, system_info=None):
    """Format system information for the specific node."""
    node_info = {
        'node_id': node_data['node_id'],
        'version': node_data['version'],
        'edition': node_data['edition']
    }

    # Only include detailed info if system_info call succeeded
    if system_info:
        node_info['details'] = {}
        for section, data in system_info.items():
            if node_data['node_id'] in data:
                # Extract node-specific data
                node_info['details'][section] = data[node_data['node_id']]

    return node_info


def main():
    """Main entry point."""
    module_args = dict(
        url=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Setup authentication
    headers = create_auth_headers(
        username=module.params['username'],
        password=module.params['password']
    )

    try:
        # Get node ID first
        node_data = get_node_id(
            base_url=module.params['url'],
            headers=headers,
            validate_certs=module.params['validate_certs']
        )

        # Get system information
        system_info = get_system_info(
            base_url=module.params['url'],
            headers=headers,
            validate_certs=module.params['validate_certs']
        )

        # Format information for the specific node
        node_info = format_node_info(node_data, system_info)

        # Return facts
        module.exit_json(
            changed=False,
            node=node_info
        )

    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
