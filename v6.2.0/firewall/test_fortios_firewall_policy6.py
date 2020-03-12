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
    from ansible.modules.network.fortios import fortios_firewall_policy6
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_firewall_policy6.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_firewall_policy6_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_policy6': {
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'anti-replay': 'enable',
        'application-list': 'test_value_5',
        'av-profile': 'test_value_6',
        'cifs-profile': 'test_value_7',
        'comments': 'test_value_8',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_11',
        'diffservcode-rev': 'test_value_12',
        'dlp-sensor': 'test_value_13',
        'dnsfilter-profile': 'test_value_14',
        'dsri': 'enable',
                'dstaddr-negate': 'enable',
                'emailfilter-profile': 'test_value_17',
                'firewall-session-dirty': 'check-all',
                'fixedport': 'enable',
                'global-label': 'test_value_20',
                'http-policy-redirect': 'enable',
                'icap-profile': 'test_value_22',
                'inbound': 'enable',
                'inspection-mode': 'proxy',
                'ippool': 'enable',
                'ips-sensor': 'test_value_26',
                'label': 'test_value_27',
                'logtraffic': 'all',
                'logtraffic-start': 'enable',
                'name': 'default_name_30',
                'nat': 'enable',
                'natinbound': 'enable',
                'natoutbound': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_35',
                'policyid': '36',
                'profile-group': 'test_value_37',
                'profile-protocol-options': 'test_value_38',
                'profile-type': 'single',
                'replacemsg-override-group': 'test_value_40',
                'rsso': 'enable',
                'schedule': 'test_value_42',
                'send-deny-packet': 'enable',
                'service-negate': 'enable',
                'session-ttl': '45',
                'srcaddr-negate': 'enable',
                'ssh-filter-profile': 'test_value_47',
                'ssh-policy-redirect': 'enable',
                'ssl-mirror': 'enable',
                'ssl-ssh-profile': 'test_value_50',
                'status': 'enable',
                'tcp-mss-receiver': '52',
                'tcp-mss-sender': '53',
                'tcp-session-without-syn': 'all',
                'timeout-send-rst': 'enable',
                'tos': 'test_value_56',
                'tos-mask': 'test_value_57',
                'tos-negate': 'enable',
                'traffic-shaper': 'test_value_59',
                'traffic-shaper-reverse': 'test_value_60',
                'utm-status': 'enable',
                'uuid': 'test_value_62',
                'vlan-cos-fwd': '63',
                'vlan-cos-rev': '64',
                'vlan-filter': 'test_value_65',
                'voip-profile': 'test_value_66',
                'vpntunnel': 'test_value_67',
                'webfilter-profile': 'test_value_68'
    }

    set_method_mock.assert_called_with('firewall', 'policy6', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_firewall_policy6_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_policy6': {
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'anti-replay': 'enable',
        'application-list': 'test_value_5',
        'av-profile': 'test_value_6',
        'cifs-profile': 'test_value_7',
        'comments': 'test_value_8',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_11',
        'diffservcode-rev': 'test_value_12',
        'dlp-sensor': 'test_value_13',
        'dnsfilter-profile': 'test_value_14',
        'dsri': 'enable',
                'dstaddr-negate': 'enable',
                'emailfilter-profile': 'test_value_17',
                'firewall-session-dirty': 'check-all',
                'fixedport': 'enable',
                'global-label': 'test_value_20',
                'http-policy-redirect': 'enable',
                'icap-profile': 'test_value_22',
                'inbound': 'enable',
                'inspection-mode': 'proxy',
                'ippool': 'enable',
                'ips-sensor': 'test_value_26',
                'label': 'test_value_27',
                'logtraffic': 'all',
                'logtraffic-start': 'enable',
                'name': 'default_name_30',
                'nat': 'enable',
                'natinbound': 'enable',
                'natoutbound': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_35',
                'policyid': '36',
                'profile-group': 'test_value_37',
                'profile-protocol-options': 'test_value_38',
                'profile-type': 'single',
                'replacemsg-override-group': 'test_value_40',
                'rsso': 'enable',
                'schedule': 'test_value_42',
                'send-deny-packet': 'enable',
                'service-negate': 'enable',
                'session-ttl': '45',
                'srcaddr-negate': 'enable',
                'ssh-filter-profile': 'test_value_47',
                'ssh-policy-redirect': 'enable',
                'ssl-mirror': 'enable',
                'ssl-ssh-profile': 'test_value_50',
                'status': 'enable',
                'tcp-mss-receiver': '52',
                'tcp-mss-sender': '53',
                'tcp-session-without-syn': 'all',
                'timeout-send-rst': 'enable',
                'tos': 'test_value_56',
                'tos-mask': 'test_value_57',
                'tos-negate': 'enable',
                'traffic-shaper': 'test_value_59',
                'traffic-shaper-reverse': 'test_value_60',
                'utm-status': 'enable',
                'uuid': 'test_value_62',
                'vlan-cos-fwd': '63',
                'vlan-cos-rev': '64',
                'vlan-filter': 'test_value_65',
                'voip-profile': 'test_value_66',
                'vpntunnel': 'test_value_67',
                'webfilter-profile': 'test_value_68'
    }

    set_method_mock.assert_called_with('firewall', 'policy6', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_firewall_policy6_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'firewall_policy6': {
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    delete_method_mock.assert_called_with('firewall', 'policy6', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_firewall_policy6_deletion_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'firewall_policy6': {
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    delete_method_mock.assert_called_with('firewall', 'policy6', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_firewall_policy6_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_policy6': {
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'anti-replay': 'enable',
        'application-list': 'test_value_5',
        'av-profile': 'test_value_6',
        'cifs-profile': 'test_value_7',
        'comments': 'test_value_8',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_11',
        'diffservcode-rev': 'test_value_12',
        'dlp-sensor': 'test_value_13',
        'dnsfilter-profile': 'test_value_14',
        'dsri': 'enable',
                'dstaddr-negate': 'enable',
                'emailfilter-profile': 'test_value_17',
                'firewall-session-dirty': 'check-all',
                'fixedport': 'enable',
                'global-label': 'test_value_20',
                'http-policy-redirect': 'enable',
                'icap-profile': 'test_value_22',
                'inbound': 'enable',
                'inspection-mode': 'proxy',
                'ippool': 'enable',
                'ips-sensor': 'test_value_26',
                'label': 'test_value_27',
                'logtraffic': 'all',
                'logtraffic-start': 'enable',
                'name': 'default_name_30',
                'nat': 'enable',
                'natinbound': 'enable',
                'natoutbound': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_35',
                'policyid': '36',
                'profile-group': 'test_value_37',
                'profile-protocol-options': 'test_value_38',
                'profile-type': 'single',
                'replacemsg-override-group': 'test_value_40',
                'rsso': 'enable',
                'schedule': 'test_value_42',
                'send-deny-packet': 'enable',
                'service-negate': 'enable',
                'session-ttl': '45',
                'srcaddr-negate': 'enable',
                'ssh-filter-profile': 'test_value_47',
                'ssh-policy-redirect': 'enable',
                'ssl-mirror': 'enable',
                'ssl-ssh-profile': 'test_value_50',
                'status': 'enable',
                'tcp-mss-receiver': '52',
                'tcp-mss-sender': '53',
                'tcp-session-without-syn': 'all',
                'timeout-send-rst': 'enable',
                'tos': 'test_value_56',
                'tos-mask': 'test_value_57',
                'tos-negate': 'enable',
                'traffic-shaper': 'test_value_59',
                'traffic-shaper-reverse': 'test_value_60',
                'utm-status': 'enable',
                'uuid': 'test_value_62',
                'vlan-cos-fwd': '63',
                'vlan-cos-rev': '64',
                'vlan-filter': 'test_value_65',
                'voip-profile': 'test_value_66',
                'vpntunnel': 'test_value_67',
                'webfilter-profile': 'test_value_68'
    }

    set_method_mock.assert_called_with('firewall', 'policy6', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_firewall_policy6_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'firewall_policy6': {
            'random_attribute_not_valid': 'tag',
            'action': 'accept',
            'anti_replay': 'enable',
            'application_list': 'test_value_5',
            'av_profile': 'test_value_6',
            'cifs_profile': 'test_value_7',
            'comments': 'test_value_8',
            'diffserv_forward': 'enable',
            'diffserv_reverse': 'enable',
            'diffservcode_forward': 'test_value_11',
            'diffservcode_rev': 'test_value_12',
            'dlp_sensor': 'test_value_13',
            'dnsfilter_profile': 'test_value_14',
            'dsri': 'enable',
            'dstaddr_negate': 'enable',
            'emailfilter_profile': 'test_value_17',
            'firewall_session_dirty': 'check-all',
            'fixedport': 'enable',
            'global_label': 'test_value_20',
            'http_policy_redirect': 'enable',
            'icap_profile': 'test_value_22',
            'inbound': 'enable',
            'inspection_mode': 'proxy',
            'ippool': 'enable',
            'ips_sensor': 'test_value_26',
            'label': 'test_value_27',
            'logtraffic': 'all',
            'logtraffic_start': 'enable',
            'name': 'default_name_30',
            'nat': 'enable',
            'natinbound': 'enable',
            'natoutbound': 'enable',
            'outbound': 'enable',
            'per_ip_shaper': 'test_value_35',
            'policyid': '36',
            'profile_group': 'test_value_37',
            'profile_protocol_options': 'test_value_38',
            'profile_type': 'single',
            'replacemsg_override_group': 'test_value_40',
            'rsso': 'enable',
            'schedule': 'test_value_42',
            'send_deny_packet': 'enable',
            'service_negate': 'enable',
            'session_ttl': '45',
            'srcaddr_negate': 'enable',
            'ssh_filter_profile': 'test_value_47',
            'ssh_policy_redirect': 'enable',
            'ssl_mirror': 'enable',
            'ssl_ssh_profile': 'test_value_50',
            'status': 'enable',
            'tcp_mss_receiver': '52',
            'tcp_mss_sender': '53',
            'tcp_session_without_syn': 'all',
            'timeout_send_rst': 'enable',
            'tos': 'test_value_56',
            'tos_mask': 'test_value_57',
            'tos_negate': 'enable',
            'traffic_shaper': 'test_value_59',
            'traffic_shaper_reverse': 'test_value_60',
            'utm_status': 'enable',
            'uuid': 'test_value_62',
            'vlan_cos_fwd': '63',
            'vlan_cos_rev': '64',
            'vlan_filter': 'test_value_65',
            'voip_profile': 'test_value_66',
            'vpntunnel': 'test_value_67',
            'webfilter_profile': 'test_value_68'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_firewall_policy6.fortios_firewall(input_data, fos_instance)

    expected_data = {
        'action': 'accept',
        'anti-replay': 'enable',
        'application-list': 'test_value_5',
        'av-profile': 'test_value_6',
        'cifs-profile': 'test_value_7',
        'comments': 'test_value_8',
        'diffserv-forward': 'enable',
        'diffserv-reverse': 'enable',
        'diffservcode-forward': 'test_value_11',
        'diffservcode-rev': 'test_value_12',
        'dlp-sensor': 'test_value_13',
        'dnsfilter-profile': 'test_value_14',
        'dsri': 'enable',
                'dstaddr-negate': 'enable',
                'emailfilter-profile': 'test_value_17',
                'firewall-session-dirty': 'check-all',
                'fixedport': 'enable',
                'global-label': 'test_value_20',
                'http-policy-redirect': 'enable',
                'icap-profile': 'test_value_22',
                'inbound': 'enable',
                'inspection-mode': 'proxy',
                'ippool': 'enable',
                'ips-sensor': 'test_value_26',
                'label': 'test_value_27',
                'logtraffic': 'all',
                'logtraffic-start': 'enable',
                'name': 'default_name_30',
                'nat': 'enable',
                'natinbound': 'enable',
                'natoutbound': 'enable',
                'outbound': 'enable',
                'per-ip-shaper': 'test_value_35',
                'policyid': '36',
                'profile-group': 'test_value_37',
                'profile-protocol-options': 'test_value_38',
                'profile-type': 'single',
                'replacemsg-override-group': 'test_value_40',
                'rsso': 'enable',
                'schedule': 'test_value_42',
                'send-deny-packet': 'enable',
                'service-negate': 'enable',
                'session-ttl': '45',
                'srcaddr-negate': 'enable',
                'ssh-filter-profile': 'test_value_47',
                'ssh-policy-redirect': 'enable',
                'ssl-mirror': 'enable',
                'ssl-ssh-profile': 'test_value_50',
                'status': 'enable',
                'tcp-mss-receiver': '52',
                'tcp-mss-sender': '53',
                'tcp-session-without-syn': 'all',
                'timeout-send-rst': 'enable',
                'tos': 'test_value_56',
                'tos-mask': 'test_value_57',
                'tos-negate': 'enable',
                'traffic-shaper': 'test_value_59',
                'traffic-shaper-reverse': 'test_value_60',
                'utm-status': 'enable',
                'uuid': 'test_value_62',
                'vlan-cos-fwd': '63',
                'vlan-cos-rev': '64',
                'vlan-filter': 'test_value_65',
                'voip-profile': 'test_value_66',
                'vpntunnel': 'test_value_67',
                'webfilter-profile': 'test_value_68'
    }

    set_method_mock.assert_called_with('firewall', 'policy6', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
