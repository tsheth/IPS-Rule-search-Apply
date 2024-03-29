# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2019 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.85
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class AzureARMVirtualMachineSummary(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'cloud_provider': 'str',
        'deployment_model': 'str',
        'resource_group': 'str',
        'state': 'str',
        'location': 'str',
        'type': 'str',
        'operating_system': 'str',
        'public_ip_address': 'str',
        'private_ip_address': 'str',
        'cloud_service': 'str',
        'deployment_id': 'str',
        'image_id': 'str',
        'security_group': 'str',
        'dns_name': 'str'
    }

    attribute_map = {
        'cloud_provider': 'cloudProvider',
        'deployment_model': 'deploymentModel',
        'resource_group': 'resourceGroup',
        'state': 'state',
        'location': 'location',
        'type': 'type',
        'operating_system': 'operatingSystem',
        'public_ip_address': 'publicIPAddress',
        'private_ip_address': 'privateIPAddress',
        'cloud_service': 'cloudService',
        'deployment_id': 'deploymentID',
        'image_id': 'imageID',
        'security_group': 'securityGroup',
        'dns_name': 'DNSName'
    }

    def __init__(self, cloud_provider=None, deployment_model=None, resource_group=None, state=None, location=None, type=None, operating_system=None, public_ip_address=None, private_ip_address=None, cloud_service=None, deployment_id=None, image_id=None, security_group=None, dns_name=None):  # noqa: E501
        """AzureARMVirtualMachineSummary - a model defined in Swagger"""  # noqa: E501

        self._cloud_provider = None
        self._deployment_model = None
        self._resource_group = None
        self._state = None
        self._location = None
        self._type = None
        self._operating_system = None
        self._public_ip_address = None
        self._private_ip_address = None
        self._cloud_service = None
        self._deployment_id = None
        self._image_id = None
        self._security_group = None
        self._dns_name = None
        self.discriminator = None

        if cloud_provider is not None:
            self.cloud_provider = cloud_provider
        if deployment_model is not None:
            self.deployment_model = deployment_model
        if resource_group is not None:
            self.resource_group = resource_group
        if state is not None:
            self.state = state
        if location is not None:
            self.location = location
        if type is not None:
            self.type = type
        if operating_system is not None:
            self.operating_system = operating_system
        if public_ip_address is not None:
            self.public_ip_address = public_ip_address
        if private_ip_address is not None:
            self.private_ip_address = private_ip_address
        if cloud_service is not None:
            self.cloud_service = cloud_service
        if deployment_id is not None:
            self.deployment_id = deployment_id
        if image_id is not None:
            self.image_id = image_id
        if security_group is not None:
            self.security_group = security_group
        if dns_name is not None:
            self.dns_name = dns_name

    @property
    def cloud_provider(self):
        """Gets the cloud_provider of this AzureARMVirtualMachineSummary.  # noqa: E501

        Cloud provider: \"Azure\".  # noqa: E501

        :return: The cloud_provider of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._cloud_provider

    @cloud_provider.setter
    def cloud_provider(self, cloud_provider):
        """Sets the cloud_provider of this AzureARMVirtualMachineSummary.

        Cloud provider: \"Azure\".  # noqa: E501

        :param cloud_provider: The cloud_provider of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._cloud_provider = cloud_provider

    @property
    def deployment_model(self):
        """Gets the deployment_model of this AzureARMVirtualMachineSummary.  # noqa: E501

        Deployment model: \"Classic\" or \"Resource Manager\".  # noqa: E501

        :return: The deployment_model of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._deployment_model

    @deployment_model.setter
    def deployment_model(self, deployment_model):
        """Sets the deployment_model of this AzureARMVirtualMachineSummary.

        Deployment model: \"Classic\" or \"Resource Manager\".  # noqa: E501

        :param deployment_model: The deployment_model of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._deployment_model = deployment_model

    @property
    def resource_group(self):
        """Gets the resource_group of this AzureARMVirtualMachineSummary.  # noqa: E501

        Name of resource group. Searchable as String.  # noqa: E501

        :return: The resource_group of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._resource_group

    @resource_group.setter
    def resource_group(self, resource_group):
        """Sets the resource_group of this AzureARMVirtualMachineSummary.

        Name of resource group. Searchable as String.  # noqa: E501

        :param resource_group: The resource_group of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._resource_group = resource_group

    @property
    def state(self):
        """Gets the state of this AzureARMVirtualMachineSummary.  # noqa: E501

        Power state, for example, \"POWER ON\".  # noqa: E501

        :return: The state of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this AzureARMVirtualMachineSummary.

        Power state, for example, \"POWER ON\".  # noqa: E501

        :param state: The state of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._state = state

    @property
    def location(self):
        """Gets the location of this AzureARMVirtualMachineSummary.  # noqa: E501

        Physical location of the resource, for example: \"East US\". Searchable as String.  # noqa: E501

        :return: The location of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._location

    @location.setter
    def location(self, location):
        """Sets the location of this AzureARMVirtualMachineSummary.

        Physical location of the resource, for example: \"East US\". Searchable as String.  # noqa: E501

        :param location: The location of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._location = location

    @property
    def type(self):
        """Gets the type of this AzureARMVirtualMachineSummary.  # noqa: E501

        Hardware type, for example: \"Standard_DS1_v2\". Searchable as String.  # noqa: E501

        :return: The type of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this AzureARMVirtualMachineSummary.

        Hardware type, for example: \"Standard_DS1_v2\". Searchable as String.  # noqa: E501

        :param type: The type of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def operating_system(self):
        """Gets the operating_system of this AzureARMVirtualMachineSummary.  # noqa: E501

        Operating system, for example: \"Microsoft Windows\". Searchable as String.  # noqa: E501

        :return: The operating_system of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._operating_system

    @operating_system.setter
    def operating_system(self, operating_system):
        """Sets the operating_system of this AzureARMVirtualMachineSummary.

        Operating system, for example: \"Microsoft Windows\". Searchable as String.  # noqa: E501

        :param operating_system: The operating_system of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._operating_system = operating_system

    @property
    def public_ip_address(self):
        """Gets the public_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501

        Public IP address. Searchable as String.  # noqa: E501

        :return: The public_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._public_ip_address

    @public_ip_address.setter
    def public_ip_address(self, public_ip_address):
        """Sets the public_ip_address of this AzureARMVirtualMachineSummary.

        Public IP address. Searchable as String.  # noqa: E501

        :param public_ip_address: The public_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._public_ip_address = public_ip_address

    @property
    def private_ip_address(self):
        """Gets the private_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501

        Private IP address. Searchable as String.  # noqa: E501

        :return: The private_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._private_ip_address

    @private_ip_address.setter
    def private_ip_address(self, private_ip_address):
        """Sets the private_ip_address of this AzureARMVirtualMachineSummary.

        Private IP address. Searchable as String.  # noqa: E501

        :param private_ip_address: The private_ip_address of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._private_ip_address = private_ip_address

    @property
    def cloud_service(self):
        """Gets the cloud_service of this AzureARMVirtualMachineSummary.  # noqa: E501

        Cloud service, for example: \"DH-DC\". Searchable as String.  # noqa: E501

        :return: The cloud_service of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._cloud_service

    @cloud_service.setter
    def cloud_service(self, cloud_service):
        """Sets the cloud_service of this AzureARMVirtualMachineSummary.

        Cloud service, for example: \"DH-DC\". Searchable as String.  # noqa: E501

        :param cloud_service: The cloud_service of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._cloud_service = cloud_service

    @property
    def deployment_id(self):
        """Gets the deployment_id of this AzureARMVirtualMachineSummary.  # noqa: E501

        Deployment ID, for example: \"76ab36a0fb8d4c4ab6b802acdf58b3a4\". Searchable as String.  # noqa: E501

        :return: The deployment_id of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._deployment_id

    @deployment_id.setter
    def deployment_id(self, deployment_id):
        """Sets the deployment_id of this AzureARMVirtualMachineSummary.

        Deployment ID, for example: \"76ab36a0fb8d4c4ab6b802acdf58b3a4\". Searchable as String.  # noqa: E501

        :param deployment_id: The deployment_id of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._deployment_id = deployment_id

    @property
    def image_id(self):
        """Gets the image_id of this AzureARMVirtualMachineSummary.  # noqa: E501

        Image ID, for example: \"a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-R2-201503.01-en.us-127GB.vhd\". Searchable as String.  # noqa: E501

        :return: The image_id of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._image_id

    @image_id.setter
    def image_id(self, image_id):
        """Sets the image_id of this AzureARMVirtualMachineSummary.

        Image ID, for example: \"a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-R2-201503.01-en.us-127GB.vhd\". Searchable as String.  # noqa: E501

        :param image_id: The image_id of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._image_id = image_id

    @property
    def security_group(self):
        """Gets the security_group of this AzureARMVirtualMachineSummary.  # noqa: E501

        Network security group, for example: \"bh-Win10Pro-1-nsg\". Searchable as String.  # noqa: E501

        :return: The security_group of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._security_group

    @security_group.setter
    def security_group(self, security_group):
        """Sets the security_group of this AzureARMVirtualMachineSummary.

        Network security group, for example: \"bh-Win10Pro-1-nsg\". Searchable as String.  # noqa: E501

        :param security_group: The security_group of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._security_group = security_group

    @property
    def dns_name(self):
        """Gets the dns_name of this AzureARMVirtualMachineSummary.  # noqa: E501


        :return: The dns_name of this AzureARMVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._dns_name

    @dns_name.setter
    def dns_name(self, dns_name):
        """Sets the dns_name of this AzureARMVirtualMachineSummary.


        :param dns_name: The dns_name of this AzureARMVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._dns_name = dns_name

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(AzureARMVirtualMachineSummary, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, AzureARMVirtualMachineSummary):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

