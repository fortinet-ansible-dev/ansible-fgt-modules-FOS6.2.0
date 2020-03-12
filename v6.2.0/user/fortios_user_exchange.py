#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_user_exchange
short_description: Configure MS Exchange server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and exchange category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
version_added: "2.9"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
        description:
            - FortiOS or FortiGate IP address.
        type: str
        required: false
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: false
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    user_exchange:
        description:
            - Configure MS Exchange server entries.
        default: null
        type: dict
        suboptions:
            addr_type:
                description:
                    - Indicate whether the server IP-address is IPv4 or IPv6.
                type: str
                choices:
                    - ipv4
                    - ipv6
            auth_level:
                description:
                    - Authentication security level used to connect to the server.
                type: str
                choices:
                    - low
                    - medium
                    - normal
                    - high
            connect_protocol:
                description:
                    - Connection protocol used to connect to MS Exchange service.
                type: str
                choices:
                    - rpc-over-tcp
                    - rpc-over-http
            domain_name:
                description:
                    - MS Exchange server fully qualified domain name.
                type: str
            ip:
                description:
                    - Server IPv4 address.
                type: str
            ip6:
                description:
                    - Server IPv6 address.
                type: str
            name:
                description:
                    - MS Exchange server entry name.
                required: true
                type: str
            password:
                description:
                    - Password for the specified username.
                type: str
            server_name:
                description:
                    - MS Exchange server hostname.
                type: str
            username:
                description:
                    - User name used to sign in to the server. Must have proper permissions for service.
                type: str
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
   ssl_verify: "False"
  tasks:
  - name: Configure MS Exchange server entries.
    fortios_user_exchange:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      user_exchange:
        addr_type: "ipv4"
        auth_level: "low"
        connect_protocol: "rpc-over-tcp"
        domain_name: "<your_own_value>"
        ip: "<your_own_value>"
        ip6: "<your_own_value>"
        name: "default_name_9"
        password: "<your_own_value>"
        server_name: "<your_own_value>"
        username: "<your_own_value>"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def filter_user_exchange_data(json):
    option_list = ['addr_type', 'auth_level', 'connect_protocol',
                   'domain_name', 'ip', 'ip6',
                   'name', 'password', 'server_name',
                   'username']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def user_exchange(data, fos):
    vdom = data['vdom']
    state = data['state']
    user_exchange_data = data['user_exchange']
    filtered_data = underscore_to_hyphen(filter_user_exchange_data(user_exchange_data))

    if state == "present":
        return fos.set('user',
                       'exchange',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('user',
                          'exchange',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos):

    if data['user_exchange']:
        resp = user_exchange(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "user_exchange": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "addr_type": {"required": False, "type": "str",
                              "choices": ["ipv4", "ipv6"]},
                "auth_level": {"required": False, "type": "str",
                               "choices": ["low", "medium", "normal",
                                           "high"]},
                "connect_protocol": {"required": False, "type": "str",
                                     "choices": ["rpc-over-tcp", "rpc-over-http"]},
                "domain_name": {"required": True, "type": "str"},
                "ip": {"required": False, "type": "str"},
                "ip6": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "password": {"required": True, "type": "str"},
                "server_name": {"required": True, "type": "str"},
                "username": {"required": True, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    # legacy_mode refers to using fortiosapi instead of HTTPAPI
    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_user(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_user(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
