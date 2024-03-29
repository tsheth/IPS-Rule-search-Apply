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


class CertificatesApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def add_certificate(self, certificate, api_version, **kwargs):  # noqa: E501
        """Add a Certificate  # noqa: E501

        Add a certificate to Deep Security Manager.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_certificate(certificate, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Certificate certificate: (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.add_certificate_with_http_info(certificate, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.add_certificate_with_http_info(certificate, api_version, **kwargs)  # noqa: E501
            return data

    def add_certificate_with_http_info(self, certificate, api_version, **kwargs):  # noqa: E501
        """Add a Certificate  # noqa: E501

        Add a certificate to Deep Security Manager.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_certificate_with_http_info(certificate, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Certificate certificate: (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['certificate', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method add_certificate" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'certificate' is set
        if ('certificate' not in params or
                params['certificate'] is None):
            raise ValueError("Missing the required parameter `certificate` when calling `add_certificate`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `add_certificate`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'certificate' in params:
            body_params = params['certificate']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/certificates', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Certificate',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_certificate(self, certificate_id, api_version, **kwargs):  # noqa: E501
        """Delete a Certificate  # noqa: E501

        Delete a certificate by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_certificate(certificate_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int certificate_id: The ID number of the certificate to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_certificate_with_http_info(certificate_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_certificate_with_http_info(certificate_id, api_version, **kwargs)  # noqa: E501
            return data

    def delete_certificate_with_http_info(self, certificate_id, api_version, **kwargs):  # noqa: E501
        """Delete a Certificate  # noqa: E501

        Delete a certificate by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_certificate_with_http_info(certificate_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int certificate_id: The ID number of the certificate to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['certificate_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_certificate" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'certificate_id' is set
        if ('certificate_id' not in params or
                params['certificate_id'] is None):
            raise ValueError("Missing the required parameter `certificate_id` when calling `delete_certificate`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `delete_certificate`")  # noqa: E501

        if 'certificate_id' in params and not re.search('\\d+', str(params['certificate_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `certificate_id` when calling `delete_certificate`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'certificate_id' in params:
            path_params['certificateID'] = params['certificate_id']  # noqa: E501

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
            '/certificates/{certificateID}', 'DELETE',
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

    def describe_certificate(self, certificate_id, api_version, **kwargs):  # noqa: E501
        """Describe a Certificate  # noqa: E501

        Describe a certificate by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_certificate(certificate_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int certificate_id: The ID number of the certificate to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.describe_certificate_with_http_info(certificate_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_certificate_with_http_info(certificate_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_certificate_with_http_info(self, certificate_id, api_version, **kwargs):  # noqa: E501
        """Describe a Certificate  # noqa: E501

        Describe a certificate by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_certificate_with_http_info(certificate_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int certificate_id: The ID number of the certificate to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['certificate_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_certificate" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'certificate_id' is set
        if ('certificate_id' not in params or
                params['certificate_id'] is None):
            raise ValueError("Missing the required parameter `certificate_id` when calling `describe_certificate`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_certificate`")  # noqa: E501

        if 'certificate_id' in params and not re.search('\\d+', str(params['certificate_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `certificate_id` when calling `describe_certificate`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'certificate_id' in params:
            path_params['certificateID'] = params['certificate_id']  # noqa: E501

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
            '/certificates/{certificateID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Certificate',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_certificates(self, api_version, **kwargs):  # noqa: E501
        """List Certificates  # noqa: E501

        List all SSL certificates.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_certificates(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Certificates
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_certificates_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_certificates_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def list_certificates_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """List Certificates  # noqa: E501

        List all SSL certificates.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_certificates_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Certificates
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
                    " to method list_certificates" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_certificates`")  # noqa: E501

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
            '/certificates', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Certificates',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def target_certificate(self, url, api_version, **kwargs):  # noqa: E501
        """Retrieve a Certificate by URL  # noqa: E501

        Retrieve a certificate by URL  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.target_certificate(url, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str url: The URL of the certificate to describe (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.target_certificate_with_http_info(url, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.target_certificate_with_http_info(url, api_version, **kwargs)  # noqa: E501
            return data

    def target_certificate_with_http_info(self, url, api_version, **kwargs):  # noqa: E501
        """Retrieve a Certificate by URL  # noqa: E501

        Retrieve a certificate by URL  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.target_certificate_with_http_info(url, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str url: The URL of the certificate to describe (required)
        :param str api_version: The version of the api being called. (required)
        :return: Certificate
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['url', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method target_certificate" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'url' is set
        if ('url' not in params or
                params['url'] is None):
            raise ValueError("Missing the required parameter `url` when calling `target_certificate`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `target_certificate`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []
        if 'url' in params:
            query_params.append(('URL', params['url']))  # noqa: E501

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
            '/certificates/target', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Certificate',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
