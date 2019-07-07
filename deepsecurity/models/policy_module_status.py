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


class PolicyModuleStatus(object):
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
        'status': 'str',
        'status_message': 'str'
    }

    attribute_map = {
        'status': 'status',
        'status_message': 'statusMessage'
    }

    def __init__(self, status=None, status_message=None):  # noqa: E501
        """PolicyModuleStatus - a model defined in Swagger"""  # noqa: E501

        self._status = None
        self._status_message = None
        self.discriminator = None

        if status is not None:
            self.status = status
        if status_message is not None:
            self.status_message = status_message

    @property
    def status(self):
        """Gets the status of this PolicyModuleStatus.  # noqa: E501

        Status.  # noqa: E501

        :return: The status of this PolicyModuleStatus.  # noqa: E501
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this PolicyModuleStatus.

        Status.  # noqa: E501

        :param status: The status of this PolicyModuleStatus.  # noqa: E501
        :type: str
        """
        allowed_values = ["inactive", "active", "warning", "error", "not-supported"]  # noqa: E501
        if status not in allowed_values:
            raise ValueError(
                "Invalid value for `status` ({0}), must be one of {1}"  # noqa: E501
                .format(status, allowed_values)
            )

        self._status = status

    @property
    def status_message(self):
        """Gets the status_message of this PolicyModuleStatus.  # noqa: E501

        Status message.  # noqa: E501

        :return: The status_message of this PolicyModuleStatus.  # noqa: E501
        :rtype: str
        """
        return self._status_message

    @status_message.setter
    def status_message(self, status_message):
        """Sets the status_message of this PolicyModuleStatus.

        Status message.  # noqa: E501

        :param status_message: The status_message of this PolicyModuleStatus.  # noqa: E501
        :type: str
        """

        self._status_message = status_message

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
        if issubclass(PolicyModuleStatus, dict):
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
        if not isinstance(other, PolicyModuleStatus):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

