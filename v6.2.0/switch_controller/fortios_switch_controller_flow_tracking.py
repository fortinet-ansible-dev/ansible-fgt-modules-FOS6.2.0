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
module: fortios_switch_controller_flow_tracking
short_description: Configure FortiSwitch flow tracking and export via ipfix/netflow in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and flow_tracking category.
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
    switch_controller_flow_tracking:
        description:
            - Configure FortiSwitch flow tracking and export via ipfix/netflow.
        default: null
        type: dict
        suboptions:
            aggregates:
                description:
                    - Configure aggregates in which all traffic sessions matching the IP Address will be grouped into the same flow.
                type: list
                suboptions:
                    id:
                        description:
                            - Aggregate id.
                        required: true
                        type: int
                    ip:
                        description:
                            - IP address to group all matching traffic sessions to a flow.
                        type: str
            collector_ip:
                description:
                    - Configure collector ip address.
                type: str
            collector_port:
                description:
                    - Configure collector port number(0-65535).
                type: int
            format:
                description:
                    - Configure flow tracking protocol.
                type: str
                choices:
                    - netflow1
                    - netflow5
                    - netflow9
                    - ipfix
            level:
                description:
                    - Configure flow tracking level.
                type: str
                choices:
                    - vlan
                    - ip
                    - port
                    - proto
            max_export_pkt_size:
                description:
                    - Configure flow max export packet size (512-9216).
                type: int
            sample_mode:
                description:
                    - Configure sample mode for the flow tracking.
                type: str
                choices:
                    - local
                    - perimeter
                    - device-ingress
            sample_rate:
                description:
                    - Configure sample rate for the perimeter and device-ingress sampling(0 - 99999).
                type: int
            timeout_general:
                description:
                    - Configure flow session general timeout (60-604800).
                type: int
            timeout_icmp:
                description:
                    - Configure flow session ICMP timeout (60-604800).
                type: int
            timeout_max:
                description:
                    - Configure flow session max timeout (60-604800).
                type: int
            timeout_tcp:
                description:
                    - Configure flow session TCP timeout (60-604800).
                type: int
            timeout_tcp_fin:
                description:
                    - Configure flow session TCP FIN timeout (60-604800).
                type: int
            timeout_tcp_rst:
                description:
                    - Configure flow session TCP RST timeout (60-604800).
                type: int
            timeout_udp:
                description:
                    - Configure flow session UDP timeout (60-604800).
                type: int
            transport:
                description:
                    - Configure L4 transport protocol for exporting packets.
                type: str
                choices:
                    - udp
                    - tcp
                    - sctp
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
  - name: Configure FortiSwitch flow tracking and export via ipfix/netflow.
    fortios_switch_controller_flow_tracking:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      switch_controller_flow_tracking:
        aggregates:
         -
            id:  "4"
            ip: "<your_own_value>"
        collector_ip: "<your_own_value>"
        collector_port: "7"
        format: "netflow1"
        level: "vlan"
        max_export_pkt_size: "10"
        sample_mode: "local"
        sample_rate: "12"
        timeout_general: "13"
        timeout_icmp: "14"
        timeout_max: "15"
        timeout_tcp: "16"
        timeout_tcp_fin: "17"
        timeout_tcp_rst: "18"
        timeout_udp: "19"
        transport: "udp"
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


def filter_switch_controller_flow_tracking_data(json):
    option_list = ['aggregates', 'collector_ip', 'collector_port',
                   'format', 'level', 'max_export_pkt_size',
                   'sample_mode', 'sample_rate', 'timeout_general',
                   'timeout_icmp', 'timeout_max', 'timeout_tcp',
                   'timeout_tcp_fin', 'timeout_tcp_rst', 'timeout_udp',
                   'transport']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def switch_controller_flow_tracking(data, fos):
    vdom = data['vdom']
    switch_controller_flow_tracking_data = data['switch_controller_flow_tracking']
    filtered_data = underscore_to_hyphen(filter_switch_controller_flow_tracking_data(switch_controller_flow_tracking_data))

    return fos.set('switch-controller',
                   'flow-tracking',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_switch_controller(data, fos):

    if data['switch_controller_flow_tracking']:
        resp = switch_controller_flow_tracking(data, fos)

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
        "switch_controller_flow_tracking": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "aggregates": {"required": False, "type": "list",
                               "options": {
                                   "id": {"required": True, "type": "int"},
                                   "ip": {"required": True, "type": "str"}
                               }},
                "collector_ip": {"required": False, "type": "str"},
                "collector_port": {"required": False, "type": "int"},
                "format": {"required": False, "type": "str",
                           "choices": ["netflow1", "netflow5", "netflow9",
                                       "ipfix"]},
                "level": {"required": False, "type": "str",
                          "choices": ["vlan", "ip", "port",
                                      "proto"]},
                "max_export_pkt_size": {"required": False, "type": "int"},
                "sample_mode": {"required": False, "type": "str",
                                "choices": ["local", "perimeter", "device-ingress"]},
                "sample_rate": {"required": False, "type": "int"},
                "timeout_general": {"required": False, "type": "int"},
                "timeout_icmp": {"required": False, "type": "int"},
                "timeout_max": {"required": False, "type": "int"},
                "timeout_tcp": {"required": False, "type": "int"},
                "timeout_tcp_fin": {"required": False, "type": "int"},
                "timeout_tcp_rst": {"required": False, "type": "int"},
                "timeout_udp": {"required": False, "type": "int"},
                "transport": {"required": False, "type": "str",
                              "choices": ["udp", "tcp", "sctp"]}

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

            is_error, has_changed, result = fortios_switch_controller(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_switch_controller(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
