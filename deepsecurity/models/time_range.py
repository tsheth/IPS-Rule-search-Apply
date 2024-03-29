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


class TimeRange(object):
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
        'units': 'str',
        'value': 'int'
    }

    attribute_map = {
        'units': 'units',
        'value': 'value'
    }

    def __init__(self, units=None, value=None):  # noqa: E501
        """TimeRange - a model defined in Swagger"""  # noqa: E501

        self._units = None
        self._value = None
        self.discriminator = None

        if units is not None:
            self.units = units
        if value is not None:
            self.value = value

    @property
    def units(self):
        """Gets the units of this TimeRange.  # noqa: E501

        Units for the time range  # noqa: E501

        :return: The units of this TimeRange.  # noqa: E501
        :rtype: str
        """
        return self._units

    @units.setter
    def units(self, units):
        """Sets the units of this TimeRange.

        Units for the time range  # noqa: E501

        :param units: The units of this TimeRange.  # noqa: E501
        :type: str
        """
        allowed_values = ["hour", "day", "week", "month"]  # noqa: E501
        if units not in allowed_values:
            raise ValueError(
                "Invalid value for `units` ({0}), must be one of {1}"  # noqa: E501
                .format(units, allowed_values)
            )

        self._units = units

    @property
    def value(self):
        """Gets the value of this TimeRange.  # noqa: E501

        Value of the time range. With the units, defines the report's time range as the length of time previous to the current time.  # noqa: E501

        :return: The value of this TimeRange.  # noqa: E501
        :rtype: int
        """
        return self._value

    @value.setter
    def value(self, value):
        """Sets the value of this TimeRange.

        Value of the time range. With the units, defines the report's time range as the length of time previous to the current time.  # noqa: E501

        :param value: The value of this TimeRange.  # noqa: E501
        :type: int
        """

        self._value = value

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
        if issubclass(TimeRange, dict):
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
        if not isinstance(other, TimeRange):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

