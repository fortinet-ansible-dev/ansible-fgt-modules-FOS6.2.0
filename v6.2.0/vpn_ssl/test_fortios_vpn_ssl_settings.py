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
    from ansible.modules.network.fortios import fortios_vpn_ssl_settings
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_vpn_ssl_settings.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_vpn_ssl_settings_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'vpn_ssl_settings': {
            'algorithm': 'high',
            'auth_session_check_source_ip': 'enable',
            'auth_timeout': '5',
            'auto_tunnel_static_route': 'enable',
            'banned_cipher': 'RSA',
            'check_referer': 'enable',
            'default_portal': 'test_value_9',
            'deflate_compression_level': '10',
            'deflate_min_data_size': '11',
            'dns_server1': 'test_value_12',
            'dns_server2': 'test_value_13',
            'dns_suffix': 'test_value_14',
            'dtls_hello_timeout': '15',
            'dtls_tunnel': 'enable',
            'force_two_factor_auth': 'enable',
            'header_x_forwarded_for': 'pass',
            'http_compression': 'enable',
            'http_only_cookie': 'enable',
            'http_request_body_timeout': '21',
            'http_request_header_timeout': '22',
            'https_redirect': 'enable',
            'idle_timeout': '24',
            'ipv6_dns_server1': 'test_value_25',
            'ipv6_dns_server2': 'test_value_26',
            'ipv6_wins_server1': 'test_value_27',
            'ipv6_wins_server2': 'test_value_28',
            'login_attempt_limit': '29',
            'login_block_time': '30',
            'login_timeout': '31',
            'port': '32',
            'port_precedence': 'enable',
            'reqclientcert': 'enable',
            'route_source_interface': 'enable',
            'servercert': 'test_value_36',
            'source_address_negate': 'enable',
            'source_address6_negate': 'enable',
            'ssl_client_renegotiation': 'disable',
            'ssl_insert_empty_fragment': 'enable',
            'tlsv1_0': 'enable',
            'tlsv1_1': 'enable',
            'tlsv1_2': 'enable',
            'tlsv1_3': 'enable',
            'tunnel_connect_without_reauth': 'enable',
            'tunnel_user_session_timeout': '46',
            'unsafe_legacy_renegotiation': 'enable',
            'url_obscuration': 'enable',
            'wins_server1': 'test_value_49',
            'wins_server2': 'test_value_50',
            'x_content_type_options': 'enable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_vpn_ssl_settings.fortios_vpn_ssl(input_data, fos_instance)

    expected_data = {
        'algorithm': 'high',
        'auth-session-check-source-ip': 'enable',
        'auth-timeout': '5',
        'auto-tunnel-static-route': 'enable',
        'banned-cipher': 'RSA',
        'check-referer': 'enable',
        'default-portal': 'test_value_9',
        'deflate-compression-level': '10',
        'deflate-min-data-size': '11',
        'dns-server1': 'test_value_12',
        'dns-server2': 'test_value_13',
        'dns-suffix': 'test_value_14',
        'dtls-hello-timeout': '15',
        'dtls-tunnel': 'enable',
        'force-two-factor-auth': 'enable',
        'header-x-forwarded-for': 'pass',
        'http-compression': 'enable',
        'http-only-cookie': 'enable',
        'http-request-body-timeout': '21',
        'http-request-header-timeout': '22',
        'https-redirect': 'enable',
        'idle-timeout': '24',
        'ipv6-dns-server1': 'test_value_25',
        'ipv6-dns-server2': 'test_value_26',
        'ipv6-wins-server1': 'test_value_27',
        'ipv6-wins-server2': 'test_value_28',
        'login-attempt-limit': '29',
        'login-block-time': '30',
        'login-timeout': '31',
        'port': '32',
                'port-precedence': 'enable',
                'reqclientcert': 'enable',
                'route-source-interface': 'enable',
                'servercert': 'test_value_36',
                'source-address-negate': 'enable',
                'source-address6-negate': 'enable',
                'ssl-client-renegotiation': 'disable',
                'ssl-insert-empty-fragment': 'enable',
                'tlsv1-0': 'enable',
                'tlsv1-1': 'enable',
                'tlsv1-2': 'enable',
                'tlsv1-3': 'enable',
                'tunnel-connect-without-reauth': 'enable',
                'tunnel-user-session-timeout': '46',
                'unsafe-legacy-renegotiation': 'enable',
                'url-obscuration': 'enable',
                'wins-server1': 'test_value_49',
                'wins-server2': 'test_value_50',
                'x-content-type-options': 'enable'
    }

    set_method_mock.assert_called_with('vpn.ssl', 'settings', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_vpn_ssl_settings_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'vpn_ssl_settings': {
            'algorithm': 'high',
            'auth_session_check_source_ip': 'enable',
            'auth_timeout': '5',
            'auto_tunnel_static_route': 'enable',
            'banned_cipher': 'RSA',
            'check_referer': 'enable',
            'default_portal': 'test_value_9',
            'deflate_compression_level': '10',
            'deflate_min_data_size': '11',
            'dns_server1': 'test_value_12',
            'dns_server2': 'test_value_13',
            'dns_suffix': 'test_value_14',
            'dtls_hello_timeout': '15',
            'dtls_tunnel': 'enable',
            'force_two_factor_auth': 'enable',
            'header_x_forwarded_for': 'pass',
            'http_compression': 'enable',
            'http_only_cookie': 'enable',
            'http_request_body_timeout': '21',
            'http_request_header_timeout': '22',
            'https_redirect': 'enable',
            'idle_timeout': '24',
            'ipv6_dns_server1': 'test_value_25',
            'ipv6_dns_server2': 'test_value_26',
            'ipv6_wins_server1': 'test_value_27',
            'ipv6_wins_server2': 'test_value_28',
            'login_attempt_limit': '29',
            'login_block_time': '30',
            'login_timeout': '31',
            'port': '32',
            'port_precedence': 'enable',
            'reqclientcert': 'enable',
            'route_source_interface': 'enable',
            'servercert': 'test_value_36',
            'source_address_negate': 'enable',
            'source_address6_negate': 'enable',
            'ssl_client_renegotiation': 'disable',
            'ssl_insert_empty_fragment': 'enable',
            'tlsv1_0': 'enable',
            'tlsv1_1': 'enable',
            'tlsv1_2': 'enable',
            'tlsv1_3': 'enable',
            'tunnel_connect_without_reauth': 'enable',
            'tunnel_user_session_timeout': '46',
            'unsafe_legacy_renegotiation': 'enable',
            'url_obscuration': 'enable',
            'wins_server1': 'test_value_49',
            'wins_server2': 'test_value_50',
            'x_content_type_options': 'enable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_vpn_ssl_settings.fortios_vpn_ssl(input_data, fos_instance)

    expected_data = {
        'algorithm': 'high',
        'auth-session-check-source-ip': 'enable',
        'auth-timeout': '5',
        'auto-tunnel-static-route': 'enable',
        'banned-cipher': 'RSA',
        'check-referer': 'enable',
        'default-portal': 'test_value_9',
        'deflate-compression-level': '10',
        'deflate-min-data-size': '11',
        'dns-server1': 'test_value_12',
        'dns-server2': 'test_value_13',
        'dns-suffix': 'test_value_14',
        'dtls-hello-timeout': '15',
        'dtls-tunnel': 'enable',
        'force-two-factor-auth': 'enable',
        'header-x-forwarded-for': 'pass',
        'http-compression': 'enable',
        'http-only-cookie': 'enable',
        'http-request-body-timeout': '21',
        'http-request-header-timeout': '22',
        'https-redirect': 'enable',
        'idle-timeout': '24',
        'ipv6-dns-server1': 'test_value_25',
        'ipv6-dns-server2': 'test_value_26',
        'ipv6-wins-server1': 'test_value_27',
        'ipv6-wins-server2': 'test_value_28',
        'login-attempt-limit': '29',
        'login-block-time': '30',
        'login-timeout': '31',
        'port': '32',
                'port-precedence': 'enable',
                'reqclientcert': 'enable',
                'route-source-interface': 'enable',
                'servercert': 'test_value_36',
                'source-address-negate': 'enable',
                'source-address6-negate': 'enable',
                'ssl-client-renegotiation': 'disable',
                'ssl-insert-empty-fragment': 'enable',
                'tlsv1-0': 'enable',
                'tlsv1-1': 'enable',
                'tlsv1-2': 'enable',
                'tlsv1-3': 'enable',
                'tunnel-connect-without-reauth': 'enable',
                'tunnel-user-session-timeout': '46',
                'unsafe-legacy-renegotiation': 'enable',
                'url-obscuration': 'enable',
                'wins-server1': 'test_value_49',
                'wins-server2': 'test_value_50',
                'x-content-type-options': 'enable'
    }

    set_method_mock.assert_called_with('vpn.ssl', 'settings', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_vpn_ssl_settings_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'vpn_ssl_settings': {
            'algorithm': 'high',
            'auth_session_check_source_ip': 'enable',
            'auth_timeout': '5',
            'auto_tunnel_static_route': 'enable',
            'banned_cipher': 'RSA',
            'check_referer': 'enable',
            'default_portal': 'test_value_9',
            'deflate_compression_level': '10',
            'deflate_min_data_size': '11',
            'dns_server1': 'test_value_12',
            'dns_server2': 'test_value_13',
            'dns_suffix': 'test_value_14',
            'dtls_hello_timeout': '15',
            'dtls_tunnel': 'enable',
            'force_two_factor_auth': 'enable',
            'header_x_forwarded_for': 'pass',
            'http_compression': 'enable',
            'http_only_cookie': 'enable',
            'http_request_body_timeout': '21',
            'http_request_header_timeout': '22',
            'https_redirect': 'enable',
            'idle_timeout': '24',
            'ipv6_dns_server1': 'test_value_25',
            'ipv6_dns_server2': 'test_value_26',
            'ipv6_wins_server1': 'test_value_27',
            'ipv6_wins_server2': 'test_value_28',
            'login_attempt_limit': '29',
            'login_block_time': '30',
            'login_timeout': '31',
            'port': '32',
            'port_precedence': 'enable',
            'reqclientcert': 'enable',
            'route_source_interface': 'enable',
            'servercert': 'test_value_36',
            'source_address_negate': 'enable',
            'source_address6_negate': 'enable',
            'ssl_client_renegotiation': 'disable',
            'ssl_insert_empty_fragment': 'enable',
            'tlsv1_0': 'enable',
            'tlsv1_1': 'enable',
            'tlsv1_2': 'enable',
            'tlsv1_3': 'enable',
            'tunnel_connect_without_reauth': 'enable',
            'tunnel_user_session_timeout': '46',
            'unsafe_legacy_renegotiation': 'enable',
            'url_obscuration': 'enable',
            'wins_server1': 'test_value_49',
            'wins_server2': 'test_value_50',
            'x_content_type_options': 'enable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_vpn_ssl_settings.fortios_vpn_ssl(input_data, fos_instance)

    expected_data = {
        'algorithm': 'high',
        'auth-session-check-source-ip': 'enable',
        'auth-timeout': '5',
        'auto-tunnel-static-route': 'enable',
        'banned-cipher': 'RSA',
        'check-referer': 'enable',
        'default-portal': 'test_value_9',
        'deflate-compression-level': '10',
        'deflate-min-data-size': '11',
        'dns-server1': 'test_value_12',
        'dns-server2': 'test_value_13',
        'dns-suffix': 'test_value_14',
        'dtls-hello-timeout': '15',
        'dtls-tunnel': 'enable',
        'force-two-factor-auth': 'enable',
        'header-x-forwarded-for': 'pass',
        'http-compression': 'enable',
        'http-only-cookie': 'enable',
        'http-request-body-timeout': '21',
        'http-request-header-timeout': '22',
        'https-redirect': 'enable',
        'idle-timeout': '24',
        'ipv6-dns-server1': 'test_value_25',
        'ipv6-dns-server2': 'test_value_26',
        'ipv6-wins-server1': 'test_value_27',
        'ipv6-wins-server2': 'test_value_28',
        'login-attempt-limit': '29',
        'login-block-time': '30',
        'login-timeout': '31',
        'port': '32',
                'port-precedence': 'enable',
                'reqclientcert': 'enable',
                'route-source-interface': 'enable',
                'servercert': 'test_value_36',
                'source-address-negate': 'enable',
                'source-address6-negate': 'enable',
                'ssl-client-renegotiation': 'disable',
                'ssl-insert-empty-fragment': 'enable',
                'tlsv1-0': 'enable',
                'tlsv1-1': 'enable',
                'tlsv1-2': 'enable',
                'tlsv1-3': 'enable',
                'tunnel-connect-without-reauth': 'enable',
                'tunnel-user-session-timeout': '46',
                'unsafe-legacy-renegotiation': 'enable',
                'url-obscuration': 'enable',
                'wins-server1': 'test_value_49',
                'wins-server2': 'test_value_50',
                'x-content-type-options': 'enable'
    }

    set_method_mock.assert_called_with('vpn.ssl', 'settings', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_vpn_ssl_settings_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'vpn_ssl_settings': {
            'random_attribute_not_valid': 'tag',
            'algorithm': 'high',
            'auth_session_check_source_ip': 'enable',
            'auth_timeout': '5',
            'auto_tunnel_static_route': 'enable',
            'banned_cipher': 'RSA',
            'check_referer': 'enable',
            'default_portal': 'test_value_9',
            'deflate_compression_level': '10',
            'deflate_min_data_size': '11',
            'dns_server1': 'test_value_12',
            'dns_server2': 'test_value_13',
            'dns_suffix': 'test_value_14',
            'dtls_hello_timeout': '15',
            'dtls_tunnel': 'enable',
            'force_two_factor_auth': 'enable',
            'header_x_forwarded_for': 'pass',
            'http_compression': 'enable',
            'http_only_cookie': 'enable',
            'http_request_body_timeout': '21',
            'http_request_header_timeout': '22',
            'https_redirect': 'enable',
            'idle_timeout': '24',
            'ipv6_dns_server1': 'test_value_25',
            'ipv6_dns_server2': 'test_value_26',
            'ipv6_wins_server1': 'test_value_27',
            'ipv6_wins_server2': 'test_value_28',
            'login_attempt_limit': '29',
            'login_block_time': '30',
            'login_timeout': '31',
            'port': '32',
            'port_precedence': 'enable',
            'reqclientcert': 'enable',
            'route_source_interface': 'enable',
            'servercert': 'test_value_36',
            'source_address_negate': 'enable',
            'source_address6_negate': 'enable',
            'ssl_client_renegotiation': 'disable',
            'ssl_insert_empty_fragment': 'enable',
            'tlsv1_0': 'enable',
            'tlsv1_1': 'enable',
            'tlsv1_2': 'enable',
            'tlsv1_3': 'enable',
            'tunnel_connect_without_reauth': 'enable',
            'tunnel_user_session_timeout': '46',
            'unsafe_legacy_renegotiation': 'enable',
            'url_obscuration': 'enable',
            'wins_server1': 'test_value_49',
            'wins_server2': 'test_value_50',
            'x_content_type_options': 'enable'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_vpn_ssl_settings.fortios_vpn_ssl(input_data, fos_instance)

    expected_data = {
        'algorithm': 'high',
        'auth-session-check-source-ip': 'enable',
        'auth-timeout': '5',
        'auto-tunnel-static-route': 'enable',
        'banned-cipher': 'RSA',
        'check-referer': 'enable',
        'default-portal': 'test_value_9',
        'deflate-compression-level': '10',
        'deflate-min-data-size': '11',
        'dns-server1': 'test_value_12',
        'dns-server2': 'test_value_13',
        'dns-suffix': 'test_value_14',
        'dtls-hello-timeout': '15',
        'dtls-tunnel': 'enable',
        'force-two-factor-auth': 'enable',
        'header-x-forwarded-for': 'pass',
        'http-compression': 'enable',
        'http-only-cookie': 'enable',
        'http-request-body-timeout': '21',
        'http-request-header-timeout': '22',
        'https-redirect': 'enable',
        'idle-timeout': '24',
        'ipv6-dns-server1': 'test_value_25',
        'ipv6-dns-server2': 'test_value_26',
        'ipv6-wins-server1': 'test_value_27',
        'ipv6-wins-server2': 'test_value_28',
        'login-attempt-limit': '29',
        'login-block-time': '30',
        'login-timeout': '31',
        'port': '32',
                'port-precedence': 'enable',
                'reqclientcert': 'enable',
                'route-source-interface': 'enable',
                'servercert': 'test_value_36',
                'source-address-negate': 'enable',
                'source-address6-negate': 'enable',
                'ssl-client-renegotiation': 'disable',
                'ssl-insert-empty-fragment': 'enable',
                'tlsv1-0': 'enable',
                'tlsv1-1': 'enable',
                'tlsv1-2': 'enable',
                'tlsv1-3': 'enable',
                'tunnel-connect-without-reauth': 'enable',
                'tunnel-user-session-timeout': '46',
                'unsafe-legacy-renegotiation': 'enable',
                'url-obscuration': 'enable',
                'wins-server1': 'test_value_49',
                'wins-server2': 'test_value_50',
                'x-content-type-options': 'enable'
    }

    set_method_mock.assert_called_with('vpn.ssl', 'settings', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
