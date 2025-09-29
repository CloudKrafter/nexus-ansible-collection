#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: config_user_tokens
short_description: Manage Nexus user token settings
description:
  - Configure user token settings in Nexus Repository Manager
  - Enable/disable user tokens
  - Enable/disable user token requirement to access protected content
  - Configure token expiration
version_added: "1.23.0"
options:
  state:
    description:
      - Desired state of user token settings
      - Whether to enable (present) or disable (absent) user tokens.
    type: str
    choices: [ 'present', 'absent', 'enabled', 'disabled' ]
    default: present
  required_for_auth:
    description:
      - Whether to require user tokens for repository authentication
    type: bool
    default: false
  expire_tokens:
    description:
      - Enable or disable token expiration
    type: bool
    default: false
  expiration_days:
    description:
      - Number of days before tokens expire
      - Only used when expire_tokens is true
    type: int
    default: 30
  url:
    description:
      - Nexus instance URL
    type: str
    required: true
  username:
    description:
      - Nexus username
    type: str
    required: true
  password:
    description:
      - Nexus password
    type: str
    required: true
  validate_certs:
    description:
      - Verify SSL certificate
    type: bool
    default: true
  timeout:
    description:
      - Timeout for HTTP requests
    type: int
    default: 30
author:
  - "Brian Veltman (@cloudkrafter)"
'''

EXAMPLES = '''
- name: Enable user tokens with 90 days expiration
  cloudkrafter.nexus.config_user_tokens:
    state: present
    expire_tokens: true
    expiration_days: 90
    url: https://nexus.example.com
    username: username
    password: password

- name: Enable user tokens and require tokens for repository authentication
  cloudkrafter.nexus.config_user_tokens:
    state: present
    required_for_auth: true
    url: https://nexus.example.com
    username: username
    password: password

- name: Disable user tokens
  cloudkrafter.nexus.config_user_tokens:
    state: absent
    url: https://nexus.example.com
    username: username
    password: password

'''

RETURN = '''
changed:
    description: Whether the token settings were changed
    type: bool
    returned: always
settings:
    description: Current user token settings
    type: dict
    returned: always
    contains:
        enabled:
            description: Whether user tokens are enabled
            type: bool
            returned: always
        required_for_auth:
            description: Whether content is protected
            type: bool
            returned: always
        expiration_enabled:
            description: Whether token expiration is enabled
            type: bool
            returned: always
        expiration_days:
            description: Days until tokens expire
            type: int
            returned: always
'''


from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    create_auth_headers,
    RepositoryError
)
import json
from ansible.module_utils.urls import open_url
from ansible.module_utils.basic import AnsibleModule


def get_token_settings(base_url, headers, validate_certs, timeout):
    """Get current user token settings"""
    url = f"{base_url}/service/rest/v1/security/user-tokens"

    try:
        response = open_url(
            url,
            headers=headers,
            validate_certs=validate_certs,
            timeout=timeout,
            method='GET'
        )
        return json.loads(response.read())
    except Exception as e:
        raise RepositoryError(f"Failed to get token settings: {str(e)}")


def update_token_settings(base_url, settings, headers, validate_certs, timeout):
    """Update user token settings"""
    url = f"{base_url}/service/rest/v1/security/user-tokens"

    try:
        response = open_url(
            url,
            data=json.dumps(settings).encode('utf-8'),
            headers=headers,
            validate_certs=validate_certs,
            timeout=timeout,
            method='PUT'
        )
        return json.loads(response.read())
    except Exception as e:
        raise RepositoryError(f"Failed to update token settings: {str(e)}")


def main():
    """Main entry point"""
    module_args = dict(
        state=dict(type='str', choices=[
                   'present', 'absent', 'enabled', 'disabled'], default='present'),
        required_for_auth=dict(type='bool', default=False),
        expire_tokens=dict(type='bool', default=False),
        expiration_days=dict(type='int', default=30),
        url=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True),
        timeout=dict(type='int', default=30)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False,
        settings={}
    )

    # Setup authentication
    headers = create_auth_headers(
        username=module.params['username'],
        password=module.params['password']
    )

    try:
        # Get current settings
        current = get_token_settings(
            base_url=module.params['url'],
            headers=headers,
            validate_certs=module.params['validate_certs'],
            timeout=module.params['timeout']
        )

        # Define desired state
        desired = {
            # enabled: true when params['state'] is 'present' or 'enabled'. When params['state'] is 'absent' or 'disabled' it needs to be false
            'enabled': module.params['state'] in ['present', 'enabled'],
            'protectContent': module.params['required_for_auth'],
            'expirationEnabled': module.params['expire_tokens'],
            'expirationDays': module.params['expiration_days']
        }

        # Check if update needed
        needs_update = (
            current['enabled'] != desired['enabled'] or
            current['protectContent'] != desired['protectContent'] or
            current['expirationEnabled'] != desired['expirationEnabled'] or
            current['expirationDays'] != desired['expirationDays']
        )

        result['settings'] = current

        if needs_update:
            result['changed'] = True
            if not module.check_mode:
                updated = update_token_settings(
                    base_url=module.params['url'],
                    settings=desired,
                    headers=headers,
                    validate_certs=module.params['validate_certs'],
                    timeout=module.params['timeout']
                )
                result['settings'].update({
                    'enabled': updated['enabled'],
                    'required_for_auth': updated['protectContent'],
                    'expiration_enabled': updated['expirationEnabled'],
                    'expiration_days': updated['expirationDays']
                })

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
