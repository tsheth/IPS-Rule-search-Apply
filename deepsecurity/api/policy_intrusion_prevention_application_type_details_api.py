# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2019 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.85
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from deepsecurity.api_client import ApiClient


class PolicyIntrusionPreventionApplicationTypeDetailsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def describe_intrusion_prevention_application_type_on_policy(self, policy_id, application_type_id, api_version, **kwargs):  # noqa: E501
        """Describe an intrusion prevention application type  # noqa: E501

        Describe an intrusion prevention application type including policy-level overrides.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_intrusion_prevention_application_type_on_policy(policy_id, application_type_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.describe_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_intrusion_prevention_application_type_on_policy_with_http_info(self, policy_id, application_type_id, api_version, **kwargs):  # noqa: E501
        """Describe an intrusion prevention application type  # noqa: E501

        Describe an intrusion prevention application type including policy-level overrides.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['policy_id', 'application_type_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_intrusion_prevention_application_type_on_policy" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'policy_id' is set
        if ('policy_id' not in params or
                params['policy_id'] is None):
            raise ValueError("Missing the required parameter `policy_id` when calling `describe_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'application_type_id' is set
        if ('application_type_id' not in params or
                params['application_type_id'] is None):
            raise ValueError("Missing the required parameter `application_type_id` when calling `describe_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_intrusion_prevention_application_type_on_policy`")  # noqa: E501

        if 'policy_id' in params and not re.search('\\d+', str(params['policy_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `policy_id` when calling `describe_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'application_type_id' in params and not re.search('\\d+', str(params['application_type_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `application_type_id` when calling `describe_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'policy_id' in params:
            path_params['policyID'] = params['policy_id']  # noqa: E501
        if 'application_type_id' in params:
            path_params['applicationTypeID'] = params['application_type_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/policies/{policyID}/intrusionprevention/applicationtypes/{applicationTypeID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationType',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_intrusion_prevention_application_types_on_policy(self, policy_id, api_version, **kwargs):  # noqa: E501
        """List intrusion prevention application types  # noqa: E501

        Lists all intrusion prevention application types assigned to a policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_intrusion_prevention_application_types_on_policy(policy_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only application types assigned to the current policy.
        :return: ApplicationTypes
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_intrusion_prevention_application_types_on_policy_with_http_info(policy_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_intrusion_prevention_application_types_on_policy_with_http_info(policy_id, api_version, **kwargs)  # noqa: E501
            return data

    def list_intrusion_prevention_application_types_on_policy_with_http_info(self, policy_id, api_version, **kwargs):  # noqa: E501
        """List intrusion prevention application types  # noqa: E501

        Lists all intrusion prevention application types assigned to a policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_intrusion_prevention_application_types_on_policy_with_http_info(policy_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only application types assigned to the current policy.
        :return: ApplicationTypes
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['policy_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_intrusion_prevention_application_types_on_policy" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'policy_id' is set
        if ('policy_id' not in params or
                params['policy_id'] is None):
            raise ValueError("Missing the required parameter `policy_id` when calling `list_intrusion_prevention_application_types_on_policy`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_intrusion_prevention_application_types_on_policy`")  # noqa: E501

        if 'policy_id' in params and not re.search('\\d+', str(params['policy_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `policy_id` when calling `list_intrusion_prevention_application_types_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'policy_id' in params:
            path_params['policyID'] = params['policy_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/policies/{policyID}/intrusionprevention/applicationtypes', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationTypes',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def modify_intrusion_prevention_application_type_on_policy(self, policy_id, application_type_id, application_type, api_version, **kwargs):  # noqa: E501
        """Modify an intrusion prevention application type  # noqa: E501

        Modify an intrusion prevention application type assigned to a policy. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_intrusion_prevention_application_type_on_policy(policy_id, application_type_id, application_type, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type to modify. (required)
        :param ApplicationType application_type: The settings of the application type to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.modify_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, application_type, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.modify_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, application_type, api_version, **kwargs)  # noqa: E501
            return data

    def modify_intrusion_prevention_application_type_on_policy_with_http_info(self, policy_id, application_type_id, application_type, api_version, **kwargs):  # noqa: E501
        """Modify an intrusion prevention application type  # noqa: E501

        Modify an intrusion prevention application type assigned to a policy. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, application_type, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type to modify. (required)
        :param ApplicationType application_type: The settings of the application type to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['policy_id', 'application_type_id', 'application_type', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method modify_intrusion_prevention_application_type_on_policy" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'policy_id' is set
        if ('policy_id' not in params or
                params['policy_id'] is None):
            raise ValueError("Missing the required parameter `policy_id` when calling `modify_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'application_type_id' is set
        if ('application_type_id' not in params or
                params['application_type_id'] is None):
            raise ValueError("Missing the required parameter `application_type_id` when calling `modify_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'application_type' is set
        if ('application_type' not in params or
                params['application_type'] is None):
            raise ValueError("Missing the required parameter `application_type` when calling `modify_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `modify_intrusion_prevention_application_type_on_policy`")  # noqa: E501

        if 'policy_id' in params and not re.search('\\d+', str(params['policy_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `policy_id` when calling `modify_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'application_type_id' in params and not re.search('\\d+', str(params['application_type_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `application_type_id` when calling `modify_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'policy_id' in params:
            path_params['policyID'] = params['policy_id']  # noqa: E501
        if 'application_type_id' in params:
            path_params['applicationTypeID'] = params['application_type_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'application_type' in params:
            body_params = params['application_type']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/policies/{policyID}/intrusionprevention/applicationtypes/{applicationTypeID}', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationType',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def reset_intrusion_prevention_application_type_on_policy(self, policy_id, application_type_id, api_version, **kwargs):  # noqa: E501
        """Reset intrusion prevention application type overrides  # noqa: E501

        Remove all overrides for an intrusion prevention application type from a policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.reset_intrusion_prevention_application_type_on_policy(policy_id, application_type_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type to reset. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.reset_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.reset_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, **kwargs)  # noqa: E501
            return data

    def reset_intrusion_prevention_application_type_on_policy_with_http_info(self, policy_id, application_type_id, api_version, **kwargs):  # noqa: E501
        """Reset intrusion prevention application type overrides  # noqa: E501

        Remove all overrides for an intrusion prevention application type from a policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.reset_intrusion_prevention_application_type_on_policy_with_http_info(policy_id, application_type_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int policy_id: The ID number of the policy. (required)
        :param int application_type_id: The ID number of the application type to reset. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current policy.
        :return: ApplicationType
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['policy_id', 'application_type_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method reset_intrusion_prevention_application_type_on_policy" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'policy_id' is set
        if ('policy_id' not in params or
                params['policy_id'] is None):
            raise ValueError("Missing the required parameter `policy_id` when calling `reset_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'application_type_id' is set
        if ('application_type_id' not in params or
                params['application_type_id'] is None):
            raise ValueError("Missing the required parameter `application_type_id` when calling `reset_intrusion_prevention_application_type_on_policy`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `reset_intrusion_prevention_application_type_on_policy`")  # noqa: E501

        if 'policy_id' in params and not re.search('\\d+', str(params['policy_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `policy_id` when calling `reset_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'application_type_id' in params and not re.search('\\d+', str(params['application_type_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `application_type_id` when calling `reset_intrusion_prevention_application_type_on_policy`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'policy_id' in params:
            path_params['policyID'] = params['policy_id']  # noqa: E501
        if 'application_type_id' in params:
            path_params['applicationTypeID'] = params['application_type_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/policies/{policyID}/intrusionprevention/applicationtypes/{applicationTypeID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationType',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
