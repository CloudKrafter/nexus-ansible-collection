#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2025, Brian Veltman <info@cloudkrafter.org>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''
---
module: raw_component
short_description: Upload or delete a component in a RAW repository
description:
  - This module uploads or deletes a given raw component in a Nexus repository.
  - The module supports basic authentication.
version_added: "1.21.0"
options:
  repository:
    description:
      - The URL of the repository to upload the component to.
    required: true
    type: str
  name:
    description:
      - Name of the component once uploaded.
    required: true
    type: str
    aliases: [ filename ]
  dest:
    description:
      - Destination directory inside the repository where the file should be saved.
    required: false
    type: str
    default: /
    aliases: [ directory ]
  src:
    description:
      - Path to the file to be uploaded. (required if state is present).
    required: false
    type: path
    aliases: [ file ]
  state:
    description:
      - If present, the component will be uploaded if it doesn't exist.
      - If absent, the component will be deleted if it exists.
    type: str
    choices: [ present, absent ]
    default: present
    required: false
  validate_certs:
    description:
      - If False, SSL certificates will not be validated.
    type: bool
    default: true
    required: false
  timeout:
    description:
      - Timeout in seconds for the HTTP request.
      - This value sets both the connect and read timeouts.
    type: int
    default: 120
    required: false
  username:
    description:
      - Username for basic authentication.
    type: str
    required: false
  password:
    description:
      - Password for basic authentication.
    type: str
    required: false
author:
  - "Brian Veltman (@cloudkrafter)"
notes:
    - This module can be used on the Ansible controller by delegating the task to localhost.
'''

EXAMPLES = '''
- name: Upload a file to the /parentDirectory directory inside a repository
  cloudkrafter.nexus.raw_component:
    state: present
    name: some-package.tar.gz
    repository: https://nexus-instance.local/repository/some-repo
    dest: /parentDirectory
    src: /path/to/file-to-be-uploaded.tar.gz
    username: user
    password: password

- name: Delete a component from a repository
  cloudkrafter.nexus.raw_component:
    state: absent
    name: some-package.tar.gz
    repository: https://nexus-instance.local/repository/some-repo
    dest: /parentDirectory
    username: user
    password: password
'''

RETURN = '''
changed:
    description: Indicates if a change was made (e.g., upload occurred).
    type: bool
    returned: always
status_code:
    description: HTTP status code of the request.
    type: int
    returned: always
'''


import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import (
    open_url
)
from ansible_collections.cloudkrafter.nexus.plugins.module_utils.nexus_utils import (
    split_repository_url,
    create_auth_headers,
    build_upload_url,
    get_repository_details,
    check_component_exists,
    delete_component_by_id,
    RepositoryError,
    ComponentError
)


def perform_upload(url, src, name, dest, headers, validate_certs, timeout):
    """
    Performs the actual file upload to Nexus repository.

    Args:
        url (str): Upload URL for the repository
        src (str): Path to source file
        name (str): Name of the component
        dest (str): Destination directory in repository
        headers (dict): Request headers including authentication
        validate_certs (bool): Whether to validate SSL certificates
        timeout (int): Request timeout in seconds

    Returns:
        tuple: (success, status_code, message)

    Raises:
        ComponentError: If upload fails
    """
    try:
        # Ensure source file exists and is readable
        if not os.path.isfile(src):
            raise ComponentError(f"Source file not found: {src}")

        # Clean up destination path
        dest = dest.strip('/')

        # Read file content
        with open(src, 'rb') as f:
            file_data = f.read()

            # Prepare multipart form data
            boundary = 'nexus-upload-boundary'
            crlf = '\r\n'
            payload = []

            # Add directory field
            payload.append(f'--{boundary}')
            payload.append(
                'Content-Disposition: form-data; name="raw.directory"')
            payload.append('')
            payload.append(dest)

            # Add filename field
            payload.append(f'--{boundary}')
            payload.append(
                'Content-Disposition: form-data; name="raw.asset1.filename"')
            payload.append('')
            payload.append(name)

            # Add file content
            payload.append(f'--{boundary}')
            payload.append(
                f'Content-Disposition: form-data; name="raw.asset1"; filename="{name}"')
            payload.append('Content-Type: application/octet-stream')
            payload.append('')

            # Convert payload to bytes
            payload_bytes = (crlf.join(payload) + crlf).encode('utf-8')

            # Add file content and final boundary
            post_data = payload_bytes + file_data + \
                f'{crlf}--{boundary}--{crlf}'.encode('utf-8')

            # Update headers for multipart upload
            upload_headers = headers.copy()
            upload_headers['Content-Type'] = f'multipart/form-data; boundary={boundary}'
            upload_headers['Content-Length'] = str(len(post_data))

            # Perform upload
            response = open_url(
                url,
                data=post_data,
                headers=upload_headers,
                method='POST',
                validate_certs=validate_certs,
                timeout=timeout
            )

            status_code = response.code

            if status_code in [200, 201, 204]:
                return True, status_code, "Upload successful"
            else:
                error_msg = response.read().decode('utf-8')
                return False, status_code, f"Upload failed: {error_msg}"

    except Exception as e:
        raise ComponentError(f"Upload failed: {str(e)}")


def main():
    """Main function for the Ansible module"""
    module_args = dict(
        state=dict(type='str', choices=[
                   'present', 'absent'], default='present'),
        repository=dict(type='str', required=True),
        name=dict(type='str', aliases=['filename'], required=True),
        src=dict(type='path', aliases=['file']),
        dest=dict(type='str', aliases=['directory'],
                  required=False, default='/'),
        validate_certs=dict(type='bool', required=False, default=True),
        timeout=dict(type='int', required=False, default=120),
        username=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['src']],
            ['state', 'absent', ['name']]
        ]
    )

    result = dict(
        changed=False,
        exists=False,
        repository=module.params['repository'],
        name=module.params['name'],
        src=module.params['src'],
        dest=module.params['dest'],
        timeout=module.params['timeout'],
        validate_certs=module.params['validate_certs'],
        msg="",
        error=None,
        details={}
    )

    try:
        # Split repository URL into components
        base_url, repo_name = split_repository_url(module.params['repository'])
        result.update({
            'base_url': base_url,
            'repository_name': repo_name
        })

        # Create auth headers
        headers = create_auth_headers(
            username=module.params.get('username'),
            password=module.params.get('password'),
            for_upload=False
        )

        # Get repository details
        repo_format, repo_type = get_repository_details(
            repository_name=repo_name,
            base_url=base_url,
            headers=headers,
            module=module
        )
        result['details'].update({
            'repository_format': repo_format,
            'repository_type': repo_type
        })

        # Check if component exists
        exists, component_id = check_component_exists(
            base_url=base_url,
            repository_name=repo_name,
            name=module.params['name'],
            dest=module.params['dest'],
            headers=headers,
            validate_certs=module.params['validate_certs'],
            timeout=module.params['timeout']
        )
        result['exists'] = exists
        if component_id:
            result['details']['component_id'] = component_id

        # Handle state-based operations
        if module.params['state'] == 'present':
            if exists:
                result.update({
                    'changed': False,
                    'msg': "Component already exists in repository"
                })
                return module.exit_json(**result)

            if module.check_mode:
                result.update({
                    'changed': True,
                    'msg': "Component would be uploaded (check mode)"
                })
                return module.exit_json(**result)

            # Proceed with upload
            upload_url = build_upload_url(base_url, repo_name)
            result['details']['upload_url'] = upload_url

            upload_headers = create_auth_headers(
                username=module.params.get('username'),
                password=module.params.get('password'),
                for_upload=True
            )

            success, status_code, message = perform_upload(
                url=upload_url,
                src=module.params['src'],
                name=module.params['name'],
                dest=module.params['dest'],
                headers=upload_headers,
                validate_certs=module.params['validate_certs'],
                timeout=module.params['timeout']
            )

            result.update({
                'changed': success,
                'status_code': status_code,
                'msg': "Component upload successful" if success else message
            })

            if success:
                return module.exit_json(**result)
        else:
            if not exists:
                result.update({
                    'changed': False,
                    'msg': "Component does not exist in repository"
                })
                return module.exit_json(**result)

            if module.check_mode:
                result.update({
                    'changed': True,
                    'msg': "Component would have been deleted (if not in check mode)"
                })
                return module.exit_json(**result)

            # Proceed with deletion
            if delete_component_by_id(
                base_url=base_url,
                component_id=component_id,
                headers=headers,
                validate_certs=module.params['validate_certs'],
                timeout=module.params['timeout']
            ):
                result.update({
                    'changed': True,
                    'msg': "Component deleted successfully"
                })
                return module.exit_json(**result)
            else:
                result.update({
                    'changed': False,
                    'msg': "Failed to delete component"
                })
                module.fail_json(**result)

    except (RepositoryError, ComponentError) as e:
        result.update({
            'msg': str(e),
            'error': {'type': 'component', 'details': str(e)}
        })
        return module.fail_json(**result)
    except Exception as e:
        result.update({
            'msg': f"An unexpected error occurred: {str(e)}",
            'error': {'type': 'unexpected', 'details': str(e)}
        })
        return module.fail_json(**result)


if __name__ == '__main__':
    main()
