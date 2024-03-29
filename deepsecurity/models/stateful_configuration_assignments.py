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

from deepsecurity.models.stateful_configuration_assignment import StatefulConfigurationAssignment  # noqa: F401,E501


class StatefulConfigurationAssignments(object):
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
        'stateful_configuration_assignments': 'list[StatefulConfigurationAssignment]'
    }

    attribute_map = {
        'stateful_configuration_assignments': 'statefulConfigurationAssignments'
    }

    def __init__(self, stateful_configuration_assignments=None):  # noqa: E501
        """StatefulConfigurationAssignments - a model defined in Swagger"""  # noqa: E501

        self._stateful_configuration_assignments = None
        self.discriminator = None

        if stateful_configuration_assignments is not None:
            self.stateful_configuration_assignments = stateful_configuration_assignments

    @property
    def stateful_configuration_assignments(self):
        """Gets the stateful_configuration_assignments of this StatefulConfigurationAssignments.  # noqa: E501


        :return: The stateful_configuration_assignments of this StatefulConfigurationAssignments.  # noqa: E501
        :rtype: list[StatefulConfigurationAssignment]
        """
        return self._stateful_configuration_assignments

    @stateful_configuration_assignments.setter
    def stateful_configuration_assignments(self, stateful_configuration_assignments):
        """Sets the stateful_configuration_assignments of this StatefulConfigurationAssignments.


        :param stateful_configuration_assignments: The stateful_configuration_assignments of this StatefulConfigurationAssignments.  # noqa: E501
        :type: list[StatefulConfigurationAssignment]
        """

        self._stateful_configuration_assignments = stateful_configuration_assignments

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
        if issubclass(StatefulConfigurationAssignments, dict):
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
        if not isinstance(other, StatefulConfigurationAssignments):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

