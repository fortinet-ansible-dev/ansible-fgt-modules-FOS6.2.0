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
    from ansible.modules.network.fortios import fortios_system_automation_action
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_system_automation_action.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_system_automation_action_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_automation_action': {
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    expected_data = {
        'action-type': 'email',
        'alicloud-access-key-id': 'test_value_4',
        'alicloud-access-key-secret': 'test_value_5',
        'alicloud-account-id': 'test_value_6',
        'alicloud-function': 'test_value_7',
        'alicloud-function-authorization': 'anonymous',
        'alicloud-function-domain': 'test_value_9',
        'alicloud-region': 'test_value_10',
        'alicloud-service': 'test_value_11',
        'alicloud-version': 'test_value_12',
        'aws-api-id': 'test_value_13',
        'aws-api-key': 'test_value_14',
        'aws-api-path': 'test_value_15',
        'aws-api-stage': 'test_value_16',
        'aws-domain': 'test_value_17',
        'aws-region': 'test_value_18',
        'azure-api-key': 'test_value_19',
        'azure-app': 'test_value_20',
        'azure-domain': 'test_value_21',
        'azure-function': 'test_value_22',
        'azure-function-authorization': 'anonymous',
        'delay': '24',
        'email-body': 'test_value_25',
        'email-from': 'test_value_26',
        'email-subject': 'test_value_27',
        'gcp-function': 'test_value_28',
        'gcp-function-domain': 'test_value_29',
        'gcp-function-region': 'test_value_30',
        'gcp-project': 'test_value_31',
        'http-body': 'test_value_32',
        'method': 'post',
        'minimum-interval': '34',
        'name': 'default_name_35',
                'port': '36',
                'protocol': 'http',
                'required': 'enable',
                'script': 'test_value_39',
                'security-tag': 'test_value_40',
                'uri': 'test_value_41'
    }

    set_method_mock.assert_called_with('system', 'automation-action', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_system_automation_action_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_automation_action': {
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    expected_data = {
        'action-type': 'email',
        'alicloud-access-key-id': 'test_value_4',
        'alicloud-access-key-secret': 'test_value_5',
        'alicloud-account-id': 'test_value_6',
        'alicloud-function': 'test_value_7',
        'alicloud-function-authorization': 'anonymous',
        'alicloud-function-domain': 'test_value_9',
        'alicloud-region': 'test_value_10',
        'alicloud-service': 'test_value_11',
        'alicloud-version': 'test_value_12',
        'aws-api-id': 'test_value_13',
        'aws-api-key': 'test_value_14',
        'aws-api-path': 'test_value_15',
        'aws-api-stage': 'test_value_16',
        'aws-domain': 'test_value_17',
        'aws-region': 'test_value_18',
        'azure-api-key': 'test_value_19',
        'azure-app': 'test_value_20',
        'azure-domain': 'test_value_21',
        'azure-function': 'test_value_22',
        'azure-function-authorization': 'anonymous',
        'delay': '24',
        'email-body': 'test_value_25',
        'email-from': 'test_value_26',
        'email-subject': 'test_value_27',
        'gcp-function': 'test_value_28',
        'gcp-function-domain': 'test_value_29',
        'gcp-function-region': 'test_value_30',
        'gcp-project': 'test_value_31',
        'http-body': 'test_value_32',
        'method': 'post',
        'minimum-interval': '34',
        'name': 'default_name_35',
                'port': '36',
                'protocol': 'http',
                'required': 'enable',
                'script': 'test_value_39',
                'security-tag': 'test_value_40',
                'uri': 'test_value_41'
    }

    set_method_mock.assert_called_with('system', 'automation-action', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_system_automation_action_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'system_automation_action': {
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    delete_method_mock.assert_called_with('system', 'automation-action', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_system_automation_action_deletion_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'system_automation_action': {
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    delete_method_mock.assert_called_with('system', 'automation-action', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_system_automation_action_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_automation_action': {
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    expected_data = {
        'action-type': 'email',
        'alicloud-access-key-id': 'test_value_4',
        'alicloud-access-key-secret': 'test_value_5',
        'alicloud-account-id': 'test_value_6',
        'alicloud-function': 'test_value_7',
        'alicloud-function-authorization': 'anonymous',
        'alicloud-function-domain': 'test_value_9',
        'alicloud-region': 'test_value_10',
        'alicloud-service': 'test_value_11',
        'alicloud-version': 'test_value_12',
        'aws-api-id': 'test_value_13',
        'aws-api-key': 'test_value_14',
        'aws-api-path': 'test_value_15',
        'aws-api-stage': 'test_value_16',
        'aws-domain': 'test_value_17',
        'aws-region': 'test_value_18',
        'azure-api-key': 'test_value_19',
        'azure-app': 'test_value_20',
        'azure-domain': 'test_value_21',
        'azure-function': 'test_value_22',
        'azure-function-authorization': 'anonymous',
        'delay': '24',
        'email-body': 'test_value_25',
        'email-from': 'test_value_26',
        'email-subject': 'test_value_27',
        'gcp-function': 'test_value_28',
        'gcp-function-domain': 'test_value_29',
        'gcp-function-region': 'test_value_30',
        'gcp-project': 'test_value_31',
        'http-body': 'test_value_32',
        'method': 'post',
        'minimum-interval': '34',
        'name': 'default_name_35',
                'port': '36',
                'protocol': 'http',
                'required': 'enable',
                'script': 'test_value_39',
                'security-tag': 'test_value_40',
                'uri': 'test_value_41'
    }

    set_method_mock.assert_called_with('system', 'automation-action', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_system_automation_action_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_automation_action': {
            'random_attribute_not_valid': 'tag',
            'action_type': 'email',
            'alicloud_access_key_id': 'test_value_4',
            'alicloud_access_key_secret': 'test_value_5',
            'alicloud_account_id': 'test_value_6',
            'alicloud_function': 'test_value_7',
            'alicloud_function_authorization': 'anonymous',
            'alicloud_function_domain': 'test_value_9',
            'alicloud_region': 'test_value_10',
            'alicloud_service': 'test_value_11',
            'alicloud_version': 'test_value_12',
            'aws_api_id': 'test_value_13',
            'aws_api_key': 'test_value_14',
            'aws_api_path': 'test_value_15',
            'aws_api_stage': 'test_value_16',
            'aws_domain': 'test_value_17',
            'aws_region': 'test_value_18',
            'azure_api_key': 'test_value_19',
            'azure_app': 'test_value_20',
            'azure_domain': 'test_value_21',
            'azure_function': 'test_value_22',
            'azure_function_authorization': 'anonymous',
            'delay': '24',
            'email_body': 'test_value_25',
            'email_from': 'test_value_26',
            'email_subject': 'test_value_27',
            'gcp_function': 'test_value_28',
            'gcp_function_domain': 'test_value_29',
            'gcp_function_region': 'test_value_30',
            'gcp_project': 'test_value_31',
            'http_body': 'test_value_32',
            'method': 'post',
            'minimum_interval': '34',
            'name': 'default_name_35',
            'port': '36',
            'protocol': 'http',
            'required': 'enable',
            'script': 'test_value_39',
            'security_tag': 'test_value_40',
            'uri': 'test_value_41'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_automation_action.fortios_system(input_data, fos_instance)

    expected_data = {
        'action-type': 'email',
        'alicloud-access-key-id': 'test_value_4',
        'alicloud-access-key-secret': 'test_value_5',
        'alicloud-account-id': 'test_value_6',
        'alicloud-function': 'test_value_7',
        'alicloud-function-authorization': 'anonymous',
        'alicloud-function-domain': 'test_value_9',
        'alicloud-region': 'test_value_10',
        'alicloud-service': 'test_value_11',
        'alicloud-version': 'test_value_12',
        'aws-api-id': 'test_value_13',
        'aws-api-key': 'test_value_14',
        'aws-api-path': 'test_value_15',
        'aws-api-stage': 'test_value_16',
        'aws-domain': 'test_value_17',
        'aws-region': 'test_value_18',
        'azure-api-key': 'test_value_19',
        'azure-app': 'test_value_20',
        'azure-domain': 'test_value_21',
        'azure-function': 'test_value_22',
        'azure-function-authorization': 'anonymous',
        'delay': '24',
        'email-body': 'test_value_25',
        'email-from': 'test_value_26',
        'email-subject': 'test_value_27',
        'gcp-function': 'test_value_28',
        'gcp-function-domain': 'test_value_29',
        'gcp-function-region': 'test_value_30',
        'gcp-project': 'test_value_31',
        'http-body': 'test_value_32',
        'method': 'post',
        'minimum-interval': '34',
        'name': 'default_name_35',
                'port': '36',
                'protocol': 'http',
                'required': 'enable',
                'script': 'test_value_39',
                'security-tag': 'test_value_40',
                'uri': 'test_value_41'
    }

    set_method_mock.assert_called_with('system', 'automation-action', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
