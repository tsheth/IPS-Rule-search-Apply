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


class SoftwareInventory(object):
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
        'computer_id': 'int',
        'name': 'str',
        'description': 'str',
        'state': 'str',
        'start_date': 'int',
        'completed_date': 'int',
        'initiator_id': 'int',
        'id': 'int'
    }

    attribute_map = {
        'computer_id': 'computerID',
        'name': 'name',
        'description': 'description',
        'state': 'state',
        'start_date': 'startDate',
        'completed_date': 'completedDate',
        'initiator_id': 'initiatorID',
        'id': 'ID'
    }

    def __init__(self, computer_id=None, name=None, description=None, state=None, start_date=None, completed_date=None, initiator_id=None, id=None):  # noqa: E501
        """SoftwareInventory - a model defined in Swagger"""  # noqa: E501

        self._computer_id = None
        self._name = None
        self._description = None
        self._state = None
        self._start_date = None
        self._completed_date = None
        self._initiator_id = None
        self._id = None
        self.discriminator = None

        if computer_id is not None:
            self.computer_id = computer_id
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if state is not None:
            self.state = state
        if start_date is not None:
            self.start_date = start_date
        if completed_date is not None:
            self.completed_date = completed_date
        if initiator_id is not None:
            self.initiator_id = initiator_id
        if id is not None:
            self.id = id

    @property
    def computer_id(self):
        """Gets the computer_id of this SoftwareInventory.  # noqa: E501

        ID of the computer that the inventory scan was performed on (or is being performed on). Searchable as Numeric.  # noqa: E501

        :return: The computer_id of this SoftwareInventory.  # noqa: E501
        :rtype: int
        """
        return self._computer_id

    @computer_id.setter
    def computer_id(self, computer_id):
        """Sets the computer_id of this SoftwareInventory.

        ID of the computer that the inventory scan was performed on (or is being performed on). Searchable as Numeric.  # noqa: E501

        :param computer_id: The computer_id of this SoftwareInventory.  # noqa: E501
        :type: int
        """

        self._computer_id = computer_id

    @property
    def name(self):
        """Gets the name of this SoftwareInventory.  # noqa: E501

        Name of the inventory. Searchable as String.  # noqa: E501

        :return: The name of this SoftwareInventory.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this SoftwareInventory.

        Name of the inventory. Searchable as String.  # noqa: E501

        :param name: The name of this SoftwareInventory.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this SoftwareInventory.  # noqa: E501

        Description of the inventory. Searchable as String.  # noqa: E501

        :return: The description of this SoftwareInventory.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this SoftwareInventory.

        Description of the inventory. Searchable as String.  # noqa: E501

        :param description: The description of this SoftwareInventory.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def state(self):
        """Gets the state of this SoftwareInventory.  # noqa: E501

        State of the inventory scan. Searchable as Choice.  # noqa: E501

        :return: The state of this SoftwareInventory.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this SoftwareInventory.

        State of the inventory scan. Searchable as Choice.  # noqa: E501

        :param state: The state of this SoftwareInventory.  # noqa: E501
        :type: str
        """
        allowed_values = ["unknown", "building", "complete", "failed", "requested"]  # noqa: E501
        if state not in allowed_values:
            raise ValueError(
                "Invalid value for `state` ({0}), must be one of {1}"  # noqa: E501
                .format(state, allowed_values)
            )

        self._state = state

    @property
    def start_date(self):
        """Gets the start_date of this SoftwareInventory.  # noqa: E501

        Time the inventory scan was started, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The start_date of this SoftwareInventory.  # noqa: E501
        :rtype: int
        """
        return self._start_date

    @start_date.setter
    def start_date(self, start_date):
        """Sets the start_date of this SoftwareInventory.

        Time the inventory scan was started, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param start_date: The start_date of this SoftwareInventory.  # noqa: E501
        :type: int
        """

        self._start_date = start_date

    @property
    def completed_date(self):
        """Gets the completed_date of this SoftwareInventory.  # noqa: E501

        Time the inventory scan was completed, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The completed_date of this SoftwareInventory.  # noqa: E501
        :rtype: int
        """
        return self._completed_date

    @completed_date.setter
    def completed_date(self, completed_date):
        """Sets the completed_date of this SoftwareInventory.

        Time the inventory scan was completed, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param completed_date: The completed_date of this SoftwareInventory.  # noqa: E501
        :type: int
        """

        self._completed_date = completed_date

    @property
    def initiator_id(self):
        """Gets the initiator_id of this SoftwareInventory.  # noqa: E501

        Either the ID of the administrator that initiated the inventory scan or the ID of the API key if the inventory scan was initiated using an API Key. Searchable as Numeric.  # noqa: E501

        :return: The initiator_id of this SoftwareInventory.  # noqa: E501
        :rtype: int
        """
        return self._initiator_id

    @initiator_id.setter
    def initiator_id(self, initiator_id):
        """Sets the initiator_id of this SoftwareInventory.

        Either the ID of the administrator that initiated the inventory scan or the ID of the API key if the inventory scan was initiated using an API Key. Searchable as Numeric.  # noqa: E501

        :param initiator_id: The initiator_id of this SoftwareInventory.  # noqa: E501
        :type: int
        """

        self._initiator_id = initiator_id

    @property
    def id(self):
        """Gets the id of this SoftwareInventory.  # noqa: E501

        ID of the software inventory. Searchable as ID.  # noqa: E501

        :return: The id of this SoftwareInventory.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this SoftwareInventory.

        ID of the software inventory. Searchable as ID.  # noqa: E501

        :param id: The id of this SoftwareInventory.  # noqa: E501
        :type: int
        """

        self._id = id

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
        if issubclass(SoftwareInventory, dict):
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
        if not isinstance(other, SoftwareInventory):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

