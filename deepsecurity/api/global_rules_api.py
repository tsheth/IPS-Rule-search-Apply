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


class GlobalRulesApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def add_global_rules(self, globalrules, api_version, **kwargs):  # noqa: E501
        """Create and add new global rules  # noqa: E501

        Create and add global rules.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_global_rules(globalrules, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param ApplicationControlGlobalRules globalrules: The settings of the new rules. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.add_global_rules_with_http_info(globalrules, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.add_global_rules_with_http_info(globalrules, api_version, **kwargs)  # noqa: E501
            return data

    def add_global_rules_with_http_info(self, globalrules, api_version, **kwargs):  # noqa: E501
        """Create and add new global rules  # noqa: E501

        Create and add global rules.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_global_rules_with_http_info(globalrules, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param ApplicationControlGlobalRules globalrules: The settings of the new rules. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['globalrules', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method add_global_rules" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'globalrules' is set
        if ('globalrules' not in params or
                params['globalrules'] is None):
            raise ValueError("Missing the required parameter `globalrules` when calling `add_global_rules`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `add_global_rules`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'globalrules' in params:
            body_params = params['globalrules']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/applicationcontrolglobalrules', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationControlGlobalRules',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_global_rule(self, rule_id, api_version, **kwargs):  # noqa: E501
        """ Delete a global rule  # noqa: E501

        Delete a global rule by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_global_rule(rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_global_rule_with_http_info(rule_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_global_rule_with_http_info(rule_id, api_version, **kwargs)  # noqa: E501
            return data

    def delete_global_rule_with_http_info(self, rule_id, api_version, **kwargs):  # noqa: E501
        """ Delete a global rule  # noqa: E501

        Delete a global rule by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_global_rule_with_http_info(rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['rule_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_global_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'rule_id' is set
        if ('rule_id' not in params or
                params['rule_id'] is None):
            raise ValueError("Missing the required parameter `rule_id` when calling `delete_global_rule`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `delete_global_rule`")  # noqa: E501

        if 'rule_id' in params and not re.search('\\d+', str(params['rule_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `rule_id` when calling `delete_global_rule`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'rule_id' in params:
            path_params['ruleID'] = params['rule_id']  # noqa: E501

        query_params = []

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
            '/applicationcontrolglobalrules/{ruleID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type=None,  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def describe_global_rule(self, rule_id, api_version, **kwargs):  # noqa: E501
        """Describe a global rule  # noqa: E501

        Describe a global rule by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_global_rule(rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRule
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.describe_global_rule_with_http_info(rule_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_global_rule_with_http_info(rule_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_global_rule_with_http_info(self, rule_id, api_version, **kwargs):  # noqa: E501
        """Describe a global rule  # noqa: E501

        Describe a global rule by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_global_rule_with_http_info(rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRule
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['rule_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_global_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'rule_id' is set
        if ('rule_id' not in params or
                params['rule_id'] is None):
            raise ValueError("Missing the required parameter `rule_id` when calling `describe_global_rule`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_global_rule`")  # noqa: E501

        if 'rule_id' in params and not re.search('\\d+', str(params['rule_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `rule_id` when calling `describe_global_rule`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'rule_id' in params:
            path_params['ruleID'] = params['rule_id']  # noqa: E501

        query_params = []

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
            '/applicationcontrolglobalrules/{ruleID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationControlGlobalRule',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_global_rules(self, api_version, **kwargs):  # noqa: E501
        """List all global rules  # noqa: E501

        List all global rules.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_global_rules(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_global_rules_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_global_rules_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def list_global_rules_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """List all global rules  # noqa: E501

        List all global rules.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_global_rules_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_global_rules" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_global_rules`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

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
            '/applicationcontrolglobalrules', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationControlGlobalRules',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def modify_global_rule(self, rule_id, globalrule, api_version, **kwargs):  # noqa: E501
        """Modify a global rule  # noqa: E501

        Modify a global rule by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_global_rule(rule_id, globalrule, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to modify. (required)
        :param ApplicationControlGlobalRule globalrule: The settings of the rule to be modified. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRule
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.modify_global_rule_with_http_info(rule_id, globalrule, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.modify_global_rule_with_http_info(rule_id, globalrule, api_version, **kwargs)  # noqa: E501
            return data

    def modify_global_rule_with_http_info(self, rule_id, globalrule, api_version, **kwargs):  # noqa: E501
        """Modify a global rule  # noqa: E501

        Modify a global rule by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_global_rule_with_http_info(rule_id, globalrule, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int rule_id: The ID number of the rule to modify. (required)
        :param ApplicationControlGlobalRule globalrule: The settings of the rule to be modified. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApplicationControlGlobalRule
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['rule_id', 'globalrule', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method modify_global_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'rule_id' is set
        if ('rule_id' not in params or
                params['rule_id'] is None):
            raise ValueError("Missing the required parameter `rule_id` when calling `modify_global_rule`")  # noqa: E501
        # verify the required parameter 'globalrule' is set
        if ('globalrule' not in params or
                params['globalrule'] is None):
            raise ValueError("Missing the required parameter `globalrule` when calling `modify_global_rule`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `modify_global_rule`")  # noqa: E501

        if 'rule_id' in params and not re.search('\\d+', str(params['rule_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `rule_id` when calling `modify_global_rule`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'rule_id' in params:
            path_params['ruleID'] = params['rule_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'globalrule' in params:
            body_params = params['globalrule']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/applicationcontrolglobalrules/{ruleID}', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationControlGlobalRule',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def search_global_rules(self, api_version, **kwargs):  # noqa: E501
        """Search global rules  # noqa: E501

        Search for global rules using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_global_rules(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.search_global_rules_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.search_global_rules_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def search_global_rules_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """Search global rules  # noqa: E501

        Search for global rules using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_global_rules_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: ApplicationControlGlobalRules
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version', 'search_filter']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method search_global_rules" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `search_global_rules`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'search_filter' in params:
            body_params = params['search_filter']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/applicationcontrolglobalrules/search', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApplicationControlGlobalRules',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
