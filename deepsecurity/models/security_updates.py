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

from deepsecurity.models.component import Component  # noqa: F401,E501
from deepsecurity.models.update_status import UpdateStatus  # noqa: F401,E501


class SecurityUpdates(object):
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
        'update_status': 'UpdateStatus',
        'last_changed': 'int',
        'rules': 'list[Component]',
        'anti_malware': 'list[Component]',
        'web_reputation_service': 'list[Component]',
        'manifests': 'list[Component]',
        'other': 'list[Component]'
    }

    attribute_map = {
        'update_status': 'updateStatus',
        'last_changed': 'lastChanged',
        'rules': 'rules',
        'anti_malware': 'antiMalware',
        'web_reputation_service': 'webReputationService',
        'manifests': 'manifests',
        'other': 'other'
    }

    def __init__(self, update_status=None, last_changed=None, rules=None, anti_malware=None, web_reputation_service=None, manifests=None, other=None):  # noqa: E501
        """SecurityUpdates - a model defined in Swagger"""  # noqa: E501

        self._update_status = None
        self._last_changed = None
        self._rules = None
        self._anti_malware = None
        self._web_reputation_service = None
        self._manifests = None
        self._other = None
        self.discriminator = None

        if update_status is not None:
            self.update_status = update_status
        if last_changed is not None:
            self.last_changed = last_changed
        if rules is not None:
            self.rules = rules
        if anti_malware is not None:
            self.anti_malware = anti_malware
        if web_reputation_service is not None:
            self.web_reputation_service = web_reputation_service
        if manifests is not None:
            self.manifests = manifests
        if other is not None:
            self.other = other

    @property
    def update_status(self):
        """Gets the update_status of this SecurityUpdates.  # noqa: E501


        :return: The update_status of this SecurityUpdates.  # noqa: E501
        :rtype: UpdateStatus
        """
        return self._update_status

    @update_status.setter
    def update_status(self, update_status):
        """Sets the update_status of this SecurityUpdates.


        :param update_status: The update_status of this SecurityUpdates.  # noqa: E501
        :type: UpdateStatus
        """

        self._update_status = update_status

    @property
    def last_changed(self):
        """Gets the last_changed of this SecurityUpdates.  # noqa: E501

        Date when components were last updated, in milliseconds since epoch.  # noqa: E501

        :return: The last_changed of this SecurityUpdates.  # noqa: E501
        :rtype: int
        """
        return self._last_changed

    @last_changed.setter
    def last_changed(self, last_changed):
        """Sets the last_changed of this SecurityUpdates.

        Date when components were last updated, in milliseconds since epoch.  # noqa: E501

        :param last_changed: The last_changed of this SecurityUpdates.  # noqa: E501
        :type: int
        """

        self._last_changed = last_changed

    @property
    def rules(self):
        """Gets the rules of this SecurityUpdates.  # noqa: E501

        Security update components: rules.  # noqa: E501

        :return: The rules of this SecurityUpdates.  # noqa: E501
        :rtype: list[Component]
        """
        return self._rules

    @rules.setter
    def rules(self, rules):
        """Sets the rules of this SecurityUpdates.

        Security update components: rules.  # noqa: E501

        :param rules: The rules of this SecurityUpdates.  # noqa: E501
        :type: list[Component]
        """

        self._rules = rules

    @property
    def anti_malware(self):
        """Gets the anti_malware of this SecurityUpdates.  # noqa: E501

        Security update components: anti-malware.  # noqa: E501

        :return: The anti_malware of this SecurityUpdates.  # noqa: E501
        :rtype: list[Component]
        """
        return self._anti_malware

    @anti_malware.setter
    def anti_malware(self, anti_malware):
        """Sets the anti_malware of this SecurityUpdates.

        Security update components: anti-malware.  # noqa: E501

        :param anti_malware: The anti_malware of this SecurityUpdates.  # noqa: E501
        :type: list[Component]
        """

        self._anti_malware = anti_malware

    @property
    def web_reputation_service(self):
        """Gets the web_reputation_service of this SecurityUpdates.  # noqa: E501

        Security update components: web reputation service.  # noqa: E501

        :return: The web_reputation_service of this SecurityUpdates.  # noqa: E501
        :rtype: list[Component]
        """
        return self._web_reputation_service

    @web_reputation_service.setter
    def web_reputation_service(self, web_reputation_service):
        """Sets the web_reputation_service of this SecurityUpdates.

        Security update components: web reputation service.  # noqa: E501

        :param web_reputation_service: The web_reputation_service of this SecurityUpdates.  # noqa: E501
        :type: list[Component]
        """

        self._web_reputation_service = web_reputation_service

    @property
    def manifests(self):
        """Gets the manifests of this SecurityUpdates.  # noqa: E501

        Security update components: manifests.  # noqa: E501

        :return: The manifests of this SecurityUpdates.  # noqa: E501
        :rtype: list[Component]
        """
        return self._manifests

    @manifests.setter
    def manifests(self, manifests):
        """Sets the manifests of this SecurityUpdates.

        Security update components: manifests.  # noqa: E501

        :param manifests: The manifests of this SecurityUpdates.  # noqa: E501
        :type: list[Component]
        """

        self._manifests = manifests

    @property
    def other(self):
        """Gets the other of this SecurityUpdates.  # noqa: E501

        Security update components: other.  # noqa: E501

        :return: The other of this SecurityUpdates.  # noqa: E501
        :rtype: list[Component]
        """
        return self._other

    @other.setter
    def other(self, other):
        """Sets the other of this SecurityUpdates.

        Security update components: other.  # noqa: E501

        :param other: The other of this SecurityUpdates.  # noqa: E501
        :type: list[Component]
        """

        self._other = other

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
        if issubclass(SecurityUpdates, dict):
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
        if not isinstance(other, SecurityUpdates):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

