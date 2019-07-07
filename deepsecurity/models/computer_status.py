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


class ComputerStatus(object):
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
        'agent_status': 'str',
        'agent_status_messages': 'list[str]',
        'appliance_status': 'str',
        'appliance_status_messages': 'list[str]'
    }

    attribute_map = {
        'agent_status': 'agentStatus',
        'agent_status_messages': 'agentStatusMessages',
        'appliance_status': 'applianceStatus',
        'appliance_status_messages': 'applianceStatusMessages'
    }

    def __init__(self, agent_status=None, agent_status_messages=None, appliance_status=None, appliance_status_messages=None):  # noqa: E501
        """ComputerStatus - a model defined in Swagger"""  # noqa: E501

        self._agent_status = None
        self._agent_status_messages = None
        self._appliance_status = None
        self._appliance_status_messages = None
        self.discriminator = None

        if agent_status is not None:
            self.agent_status = agent_status
        if agent_status_messages is not None:
            self.agent_status_messages = agent_status_messages
        if appliance_status is not None:
            self.appliance_status = appliance_status
        if appliance_status_messages is not None:
            self.appliance_status_messages = appliance_status_messages

    @property
    def agent_status(self):
        """Gets the agent_status of this ComputerStatus.  # noqa: E501

        Agent status.  # noqa: E501

        :return: The agent_status of this ComputerStatus.  # noqa: E501
        :rtype: str
        """
        return self._agent_status

    @agent_status.setter
    def agent_status(self, agent_status):
        """Sets the agent_status of this ComputerStatus.

        Agent status.  # noqa: E501

        :param agent_status: The agent_status of this ComputerStatus.  # noqa: E501
        :type: str
        """
        allowed_values = ["inactive", "active", "warning", "error", "not-supported"]  # noqa: E501
        if agent_status not in allowed_values:
            raise ValueError(
                "Invalid value for `agent_status` ({0}), must be one of {1}"  # noqa: E501
                .format(agent_status, allowed_values)
            )

        self._agent_status = agent_status

    @property
    def agent_status_messages(self):
        """Gets the agent_status_messages of this ComputerStatus.  # noqa: E501

        Agent status messages.  # noqa: E501

        :return: The agent_status_messages of this ComputerStatus.  # noqa: E501
        :rtype: list[str]
        """
        return self._agent_status_messages

    @agent_status_messages.setter
    def agent_status_messages(self, agent_status_messages):
        """Sets the agent_status_messages of this ComputerStatus.

        Agent status messages.  # noqa: E501

        :param agent_status_messages: The agent_status_messages of this ComputerStatus.  # noqa: E501
        :type: list[str]
        """

        self._agent_status_messages = agent_status_messages

    @property
    def appliance_status(self):
        """Gets the appliance_status of this ComputerStatus.  # noqa: E501

        Appliance status.  # noqa: E501

        :return: The appliance_status of this ComputerStatus.  # noqa: E501
        :rtype: str
        """
        return self._appliance_status

    @appliance_status.setter
    def appliance_status(self, appliance_status):
        """Sets the appliance_status of this ComputerStatus.

        Appliance status.  # noqa: E501

        :param appliance_status: The appliance_status of this ComputerStatus.  # noqa: E501
        :type: str
        """
        allowed_values = ["inactive", "active", "warning", "error", "not-supported"]  # noqa: E501
        if appliance_status not in allowed_values:
            raise ValueError(
                "Invalid value for `appliance_status` ({0}), must be one of {1}"  # noqa: E501
                .format(appliance_status, allowed_values)
            )

        self._appliance_status = appliance_status

    @property
    def appliance_status_messages(self):
        """Gets the appliance_status_messages of this ComputerStatus.  # noqa: E501

        Appliance status messages.  # noqa: E501

        :return: The appliance_status_messages of this ComputerStatus.  # noqa: E501
        :rtype: list[str]
        """
        return self._appliance_status_messages

    @appliance_status_messages.setter
    def appliance_status_messages(self, appliance_status_messages):
        """Sets the appliance_status_messages of this ComputerStatus.

        Appliance status messages.  # noqa: E501

        :param appliance_status_messages: The appliance_status_messages of this ComputerStatus.  # noqa: E501
        :type: list[str]
        """

        self._appliance_status_messages = appliance_status_messages

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
        if issubclass(ComputerStatus, dict):
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
        if not isinstance(other, ComputerStatus):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

