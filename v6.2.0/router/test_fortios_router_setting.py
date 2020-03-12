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
# along with Ansible.  If not, see <https://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
from mock import ANY
from ansible.module_utils.network.fortios.fortios import FortiOSHandler

try:
    from ansible.modules.network.fortios import fortios_router_setting
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_router_setting.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_router_setting_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'router_setting': {
            'bgp_debug_flags': 'test_value_3,',
            'hostname': 'myhostname4',
            'igmp_debug_flags': 'test_value_5,',
            'imi_debug_flags': 'test_value_6,',
            'isis_debug_flags': 'test_value_7,',
            'ospf6_debug_events_flags': 'test_value_8,',
            'ospf6_debug_ifsm_flags': 'test_value_9,',
            'ospf6_debug_lsa_flags': 'test_value_10,',
            'ospf6_debug_nfsm_flags': 'test_value_11,',
            'ospf6_debug_nsm_flags': 'test_value_12,',
            'ospf6_debug_packet_flags': 'test_value_13,',
            'ospf6_debug_route_flags': 'test_value_14,',
            'ospf_debug_events_flags': 'test_value_15,',
            'ospf_debug_ifsm_flags': 'test_value_16,',
            'ospf_debug_lsa_flags': 'test_value_17,',
            'ospf_debug_nfsm_flags': 'test_value_18,',
            'ospf_debug_nsm_flags': 'test_value_19,',
            'ospf_debug_packet_flags': 'test_value_20,',
            'ospf_debug_route_flags': 'test_value_21,',
            'pimdm_debug_flags': 'test_value_22,',
            'pimsm_debug_joinprune_flags': 'test_value_23,',
            'pimsm_debug_simple_flags': 'test_value_24,',
            'pimsm_debug_timer_flags': 'test_value_25,',
            'rip_debug_flags': 'test_value_26,',
            'ripng_debug_flags': 'test_value_27,',
            'show_filter': 'test_value_28'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_router_setting.fortios_router(input_data, fos_instance)

    expected_data = {
        'bgp-debug-flags': 'test_value_3,',
        'hostname': 'myhostname4',
        'igmp-debug-flags': 'test_value_5,',
        'imi-debug-flags': 'test_value_6,',
        'isis-debug-flags': 'test_value_7,',
        'ospf6-debug-events-flags': 'test_value_8,',
        'ospf6-debug-ifsm-flags': 'test_value_9,',
        'ospf6-debug-lsa-flags': 'test_value_10,',
        'ospf6-debug-nfsm-flags': 'test_value_11,',
        'ospf6-debug-nsm-flags': 'test_value_12,',
        'ospf6-debug-packet-flags': 'test_value_13,',
        'ospf6-debug-route-flags': 'test_value_14,',
        'ospf-debug-events-flags': 'test_value_15,',
        'ospf-debug-ifsm-flags': 'test_value_16,',
        'ospf-debug-lsa-flags': 'test_value_17,',
        'ospf-debug-nfsm-flags': 'test_value_18,',
        'ospf-debug-nsm-flags': 'test_value_19,',
        'ospf-debug-packet-flags': 'test_value_20,',
        'ospf-debug-route-flags': 'test_value_21,',
        'pimdm-debug-flags': 'test_value_22,',
        'pimsm-debug-joinprune-flags': 'test_value_23,',
        'pimsm-debug-simple-flags': 'test_value_24,',
        'pimsm-debug-timer-flags': 'test_value_25,',
        'rip-debug-flags': 'test_value_26,',
        'ripng-debug-flags': 'test_value_27,',
        'show-filter': 'test_value_28'
    }

    set_method_mock.assert_called_with('router', 'setting', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_router_setting_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'router_setting': {
            'bgp_debug_flags': 'test_value_3,',
            'hostname': 'myhostname4',
            'igmp_debug_flags': 'test_value_5,',
            'imi_debug_flags': 'test_value_6,',
            'isis_debug_flags': 'test_value_7,',
            'ospf6_debug_events_flags': 'test_value_8,',
            'ospf6_debug_ifsm_flags': 'test_value_9,',
            'ospf6_debug_lsa_flags': 'test_value_10,',
            'ospf6_debug_nfsm_flags': 'test_value_11,',
            'ospf6_debug_nsm_flags': 'test_value_12,',
            'ospf6_debug_packet_flags': 'test_value_13,',
            'ospf6_debug_route_flags': 'test_value_14,',
            'ospf_debug_events_flags': 'test_value_15,',
            'ospf_debug_ifsm_flags': 'test_value_16,',
            'ospf_debug_lsa_flags': 'test_value_17,',
            'ospf_debug_nfsm_flags': 'test_value_18,',
            'ospf_debug_nsm_flags': 'test_value_19,',
            'ospf_debug_packet_flags': 'test_value_20,',
            'ospf_debug_route_flags': 'test_value_21,',
            'pimdm_debug_flags': 'test_value_22,',
            'pimsm_debug_joinprune_flags': 'test_value_23,',
            'pimsm_debug_simple_flags': 'test_value_24,',
            'pimsm_debug_timer_flags': 'test_value_25,',
            'rip_debug_flags': 'test_value_26,',
            'ripng_debug_flags': 'test_value_27,',
            'show_filter': 'test_value_28'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_router_setting.fortios_router(input_data, fos_instance)

    expected_data = {
        'bgp-debug-flags': 'test_value_3,',
        'hostname': 'myhostname4',
        'igmp-debug-flags': 'test_value_5,',
        'imi-debug-flags': 'test_value_6,',
        'isis-debug-flags': 'test_value_7,',
        'ospf6-debug-events-flags': 'test_value_8,',
        'ospf6-debug-ifsm-flags': 'test_value_9,',
        'ospf6-debug-lsa-flags': 'test_value_10,',
        'ospf6-debug-nfsm-flags': 'test_value_11,',
        'ospf6-debug-nsm-flags': 'test_value_12,',
        'ospf6-debug-packet-flags': 'test_value_13,',
        'ospf6-debug-route-flags': 'test_value_14,',
        'ospf-debug-events-flags': 'test_value_15,',
        'ospf-debug-ifsm-flags': 'test_value_16,',
        'ospf-debug-lsa-flags': 'test_value_17,',
        'ospf-debug-nfsm-flags': 'test_value_18,',
        'ospf-debug-nsm-flags': 'test_value_19,',
        'ospf-debug-packet-flags': 'test_value_20,',
        'ospf-debug-route-flags': 'test_value_21,',
        'pimdm-debug-flags': 'test_value_22,',
        'pimsm-debug-joinprune-flags': 'test_value_23,',
        'pimsm-debug-simple-flags': 'test_value_24,',
        'pimsm-debug-timer-flags': 'test_value_25,',
        'rip-debug-flags': 'test_value_26,',
        'ripng-debug-flags': 'test_value_27,',
        'show-filter': 'test_value_28'
    }

    set_method_mock.assert_called_with('router', 'setting', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_router_setting_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'router_setting': {
            'bgp_debug_flags': 'test_value_3,',
            'hostname': 'myhostname4',
            'igmp_debug_flags': 'test_value_5,',
            'imi_debug_flags': 'test_value_6,',
            'isis_debug_flags': 'test_value_7,',
            'ospf6_debug_events_flags': 'test_value_8,',
            'ospf6_debug_ifsm_flags': 'test_value_9,',
            'ospf6_debug_lsa_flags': 'test_value_10,',
            'ospf6_debug_nfsm_flags': 'test_value_11,',
            'ospf6_debug_nsm_flags': 'test_value_12,',
            'ospf6_debug_packet_flags': 'test_value_13,',
            'ospf6_debug_route_flags': 'test_value_14,',
            'ospf_debug_events_flags': 'test_value_15,',
            'ospf_debug_ifsm_flags': 'test_value_16,',
            'ospf_debug_lsa_flags': 'test_value_17,',
            'ospf_debug_nfsm_flags': 'test_value_18,',
            'ospf_debug_nsm_flags': 'test_value_19,',
            'ospf_debug_packet_flags': 'test_value_20,',
            'ospf_debug_route_flags': 'test_value_21,',
            'pimdm_debug_flags': 'test_value_22,',
            'pimsm_debug_joinprune_flags': 'test_value_23,',
            'pimsm_debug_simple_flags': 'test_value_24,',
            'pimsm_debug_timer_flags': 'test_value_25,',
            'rip_debug_flags': 'test_value_26,',
            'ripng_debug_flags': 'test_value_27,',
            'show_filter': 'test_value_28'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_router_setting.fortios_router(input_data, fos_instance)

    expected_data = {
        'bgp-debug-flags': 'test_value_3,',
        'hostname': 'myhostname4',
        'igmp-debug-flags': 'test_value_5,',
        'imi-debug-flags': 'test_value_6,',
        'isis-debug-flags': 'test_value_7,',
        'ospf6-debug-events-flags': 'test_value_8,',
        'ospf6-debug-ifsm-flags': 'test_value_9,',
        'ospf6-debug-lsa-flags': 'test_value_10,',
        'ospf6-debug-nfsm-flags': 'test_value_11,',
        'ospf6-debug-nsm-flags': 'test_value_12,',
        'ospf6-debug-packet-flags': 'test_value_13,',
        'ospf6-debug-route-flags': 'test_value_14,',
        'ospf-debug-events-flags': 'test_value_15,',
        'ospf-debug-ifsm-flags': 'test_value_16,',
        'ospf-debug-lsa-flags': 'test_value_17,',
        'ospf-debug-nfsm-flags': 'test_value_18,',
        'ospf-debug-nsm-flags': 'test_value_19,',
        'ospf-debug-packet-flags': 'test_value_20,',
        'ospf-debug-route-flags': 'test_value_21,',
        'pimdm-debug-flags': 'test_value_22,',
        'pimsm-debug-joinprune-flags': 'test_value_23,',
        'pimsm-debug-simple-flags': 'test_value_24,',
        'pimsm-debug-timer-flags': 'test_value_25,',
        'rip-debug-flags': 'test_value_26,',
        'ripng-debug-flags': 'test_value_27,',
        'show-filter': 'test_value_28'
    }

    set_method_mock.assert_called_with('router', 'setting', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_router_setting_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'router_setting': {
            'random_attribute_not_valid': 'tag',
            'bgp_debug_flags': 'test_value_3,',
            'hostname': 'myhostname4',
            'igmp_debug_flags': 'test_value_5,',
            'imi_debug_flags': 'test_value_6,',
            'isis_debug_flags': 'test_value_7,',
            'ospf6_debug_events_flags': 'test_value_8,',
            'ospf6_debug_ifsm_flags': 'test_value_9,',
            'ospf6_debug_lsa_flags': 'test_value_10,',
            'ospf6_debug_nfsm_flags': 'test_value_11,',
            'ospf6_debug_nsm_flags': 'test_value_12,',
            'ospf6_debug_packet_flags': 'test_value_13,',
            'ospf6_debug_route_flags': 'test_value_14,',
            'ospf_debug_events_flags': 'test_value_15,',
            'ospf_debug_ifsm_flags': 'test_value_16,',
            'ospf_debug_lsa_flags': 'test_value_17,',
            'ospf_debug_nfsm_flags': 'test_value_18,',
            'ospf_debug_nsm_flags': 'test_value_19,',
            'ospf_debug_packet_flags': 'test_value_20,',
            'ospf_debug_route_flags': 'test_value_21,',
            'pimdm_debug_flags': 'test_value_22,',
            'pimsm_debug_joinprune_flags': 'test_value_23,',
            'pimsm_debug_simple_flags': 'test_value_24,',
            'pimsm_debug_timer_flags': 'test_value_25,',
            'rip_debug_flags': 'test_value_26,',
            'ripng_debug_flags': 'test_value_27,',
            'show_filter': 'test_value_28'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_router_setting.fortios_router(input_data, fos_instance)

    expected_data = {
        'bgp-debug-flags': 'test_value_3,',
        'hostname': 'myhostname4',
        'igmp-debug-flags': 'test_value_5,',
        'imi-debug-flags': 'test_value_6,',
        'isis-debug-flags': 'test_value_7,',
        'ospf6-debug-events-flags': 'test_value_8,',
        'ospf6-debug-ifsm-flags': 'test_value_9,',
        'ospf6-debug-lsa-flags': 'test_value_10,',
        'ospf6-debug-nfsm-flags': 'test_value_11,',
        'ospf6-debug-nsm-flags': 'test_value_12,',
        'ospf6-debug-packet-flags': 'test_value_13,',
        'ospf6-debug-route-flags': 'test_value_14,',
        'ospf-debug-events-flags': 'test_value_15,',
        'ospf-debug-ifsm-flags': 'test_value_16,',
        'ospf-debug-lsa-flags': 'test_value_17,',
        'ospf-debug-nfsm-flags': 'test_value_18,',
        'ospf-debug-nsm-flags': 'test_value_19,',
        'ospf-debug-packet-flags': 'test_value_20,',
        'ospf-debug-route-flags': 'test_value_21,',
        'pimdm-debug-flags': 'test_value_22,',
        'pimsm-debug-joinprune-flags': 'test_value_23,',
        'pimsm-debug-simple-flags': 'test_value_24,',
        'pimsm-debug-timer-flags': 'test_value_25,',
        'rip-debug-flags': 'test_value_26,',
        'ripng-debug-flags': 'test_value_27,',
        'show-filter': 'test_value_28'
    }

    set_method_mock.assert_called_with('router', 'setting', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
