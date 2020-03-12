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
    from ansible.modules.network.fortios import fortios_firewall_consolidated_policy
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_firewall_consolidated_policy.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_firewall_consolidated_policy_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_consolidated_policy': {
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'application-list': 'test_value_4',
        'av-profile': 'test_value_5',
        'cifs-profile': 'test_value_6',
        'comments': 'test_value_7',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_10',
        'diffservcode-rev': 'test_value_11',
        'dlp-sensor': 'test_value_12',
        'dnsfilter-profile': 'test_value_13',
        'emailfilter-profile': 'test_value_14',
        'fixedport': 'enable',
        'http-policy-redirect': 'enable',
        'icap-profile': 'test_value_17',
        'inbound': 'enable',
        'inspection-mode': 'proxy',
        'ippool': 'enable',
        'ips-sensor': 'test_value_21',
        'logtraffic': 'all',
        'logtraffic-start': 'enable',
        'name': 'default_name_24',
                'nat': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_27',
                'policyid': '28',
                'profile-group': 'test_value_29',
                'profile-protocol-options': 'test_value_30',
                'profile-type': 'single',
                'schedule': 'test_value_32',
                'session-ttl': '33',
                'ssh-filter-profile': 'test_value_34',
                'ssh-policy-redirect': 'enable',
                'ssl-ssh-profile': 'test_value_36',
                'status': 'enable',
                'tcp-mss-receiver': '38',
                'tcp-mss-sender': '39',
                'traffic-shaper': 'test_value_40',
                'traffic-shaper-reverse': 'test_value_41',
                'utm-status': 'enable',
                'uuid': 'test_value_43',
                'voip-profile': 'test_value_44',
                'vpntunnel': 'test_value_45',
                'waf-profile': 'test_value_46',
                'webfilter-profile': 'test_value_47'
    }

    set_method_mock.assert_called_with('firewall.consolidated', 'policy', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_firewall_consolidated_policy_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_consolidated_policy': {
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'application-list': 'test_value_4',
        'av-profile': 'test_value_5',
        'cifs-profile': 'test_value_6',
        'comments': 'test_value_7',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_10',
        'diffservcode-rev': 'test_value_11',
        'dlp-sensor': 'test_value_12',
        'dnsfilter-profile': 'test_value_13',
        'emailfilter-profile': 'test_value_14',
        'fixedport': 'enable',
        'http-policy-redirect': 'enable',
        'icap-profile': 'test_value_17',
        'inbound': 'enable',
        'inspection-mode': 'proxy',
        'ippool': 'enable',
        'ips-sensor': 'test_value_21',
        'logtraffic': 'all',
        'logtraffic-start': 'enable',
        'name': 'default_name_24',
                'nat': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_27',
                'policyid': '28',
                'profile-group': 'test_value_29',
                'profile-protocol-options': 'test_value_30',
                'profile-type': 'single',
                'schedule': 'test_value_32',
                'session-ttl': '33',
                'ssh-filter-profile': 'test_value_34',
                'ssh-policy-redirect': 'enable',
                'ssl-ssh-profile': 'test_value_36',
                'status': 'enable',
                'tcp-mss-receiver': '38',
                'tcp-mss-sender': '39',
                'traffic-shaper': 'test_value_40',
                'traffic-shaper-reverse': 'test_value_41',
                'utm-status': 'enable',
                'uuid': 'test_value_43',
                'voip-profile': 'test_value_44',
                'vpntunnel': 'test_value_45',
                'waf-profile': 'test_value_46',
                'webfilter-profile': 'test_value_47'
    }

    set_method_mock.assert_called_with('firewall.consolidated', 'policy', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_firewall_consolidated_policy_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'firewall_consolidated_policy': {
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    delete_method_mock.assert_called_with('firewall.consolidated', 'policy', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_firewall_consolidated_policy_deletion_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'firewall_consolidated_policy': {
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    delete_method_mock.assert_called_with('firewall.consolidated', 'policy', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_firewall_consolidated_policy_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_consolidated_policy': {
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'application-list': 'test_value_4',
        'av-profile': 'test_value_5',
        'cifs-profile': 'test_value_6',
        'comments': 'test_value_7',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_10',
        'diffservcode-rev': 'test_value_11',
        'dlp-sensor': 'test_value_12',
        'dnsfilter-profile': 'test_value_13',
        'emailfilter-profile': 'test_value_14',
        'fixedport': 'enable',
        'http-policy-redirect': 'enable',
        'icap-profile': 'test_value_17',
        'inbound': 'enable',
        'inspection-mode': 'proxy',
        'ippool': 'enable',
        'ips-sensor': 'test_value_21',
        'logtraffic': 'all',
        'logtraffic-start': 'enable',
        'name': 'default_name_24',
                'nat': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_27',
                'policyid': '28',
                'profile-group': 'test_value_29',
                'profile-protocol-options': 'test_value_30',
                'profile-type': 'single',
                'schedule': 'test_value_32',
                'session-ttl': '33',
                'ssh-filter-profile': 'test_value_34',
                'ssh-policy-redirect': 'enable',
                'ssl-ssh-profile': 'test_value_36',
                'status': 'enable',
                'tcp-mss-receiver': '38',
                'tcp-mss-sender': '39',
                'traffic-shaper': 'test_value_40',
                'traffic-shaper-reverse': 'test_value_41',
                'utm-status': 'enable',
                'uuid': 'test_value_43',
                'voip-profile': 'test_value_44',
                'vpntunnel': 'test_value_45',
                'waf-profile': 'test_value_46',
                'webfilter-profile': 'test_value_47'
    }

    set_method_mock.assert_called_with('firewall.consolidated', 'policy', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_firewall_consolidated_policy_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_consolidated_policy': {
            'random_attribute_not_valid': 'tag',
            'action': 'accept',
            'application_list': 'test_value_4',
            'av_profile': 'test_value_5',
            'cifs_profile': 'test_value_6',
            'comments': 'test_value_7',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_10',
            'diffservcode_rev': 'test_value_11',
            'dlp_sensor': 'test_value_12',
            'dnsfilter_profile': 'test_value_13',
            'emailfilter_profile': 'test_value_14',
            'fixedport': 'enable',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_17',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_21',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_24',
            'nat': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_27',
            'policyid': '28',
            'profile_group': 'test_value_29',
            'profile_protocol_options': 'test_value_30',
            'profile_type': 'single',
            'schedule': 'test_value_32',
            'session_ttl': '33',
            'ssh_filter_profile': 'test_value_34',
            'ssh_policy_redirect': 'enable',
            'ssl_ssh_profile': 'test_value_36',
            'status': 'enable',
            'tcp_mss_receiver': '38',
            'tcp_mss_sender': '39',
            'traffic_shaper': 'test_value_40',
            'traffic_shaper_reverse': 'test_value_41',
            'utm_status': 'enable',
            'uuid': 'test_value_43',
            'voip_profile': 'test_value_44',
            'vpntunnel': 'test_value_45',
            'waf_profile': 'test_value_46',
            'webfilter_profile': 'test_value_47'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_consolidated_policy.fortios_firewall_consolidated(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'application-list': 'test_value_4',
        'av-profile': 'test_value_5',
        'cifs-profile': 'test_value_6',
        'comments': 'test_value_7',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_10',
        'diffservcode-rev': 'test_value_11',
        'dlp-sensor': 'test_value_12',
        'dnsfilter-profile': 'test_value_13',
        'emailfilter-profile': 'test_value_14',
        'fixedport': 'enable',
        'http-policy-redirect': 'enable',
        'icap-profile': 'test_value_17',
        'inbound': 'enable',
        'inspection-mode': 'proxy',
        'ippool': 'enable',
        'ips-sensor': 'test_value_21',
        'logtraffic': 'all',
        'logtraffic-start': 'enable',
        'name': 'default_name_24',
                'nat': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_27',
                'policyid': '28',
                'profile-group': 'test_value_29',
                'profile-protocol-options': 'test_value_30',
                'profile-type': 'single',
                'schedule': 'test_value_32',
                'session-ttl': '33',
                'ssh-filter-profile': 'test_value_34',
                'ssh-policy-redirect': 'enable',
                'ssl-ssh-profile': 'test_value_36',
                'status': 'enable',
                'tcp-mss-receiver': '38',
                'tcp-mss-sender': '39',
                'traffic-shaper': 'test_value_40',
                'traffic-shaper-reverse': 'test_value_41',
                'utm-status': 'enable',
                'uuid': 'test_value_43',
                'voip-profile': 'test_value_44',
                'vpntunnel': 'test_value_45',
                'waf-profile': 'test_value_46',
                'webfilter-profile': 'test_value_47'
    }

    set_method_mock.assert_called_with('firewall.consolidated', 'policy', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
