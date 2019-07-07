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


class LogInspectionDecoderRights(object):
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
        'can_create_new_log_inspection_decoders': 'bool',
        'can_delete_log_inspection_decoders': 'bool',
        'can_edit_log_inspection_decoder_properties': 'bool'
    }

    attribute_map = {
        'can_create_new_log_inspection_decoders': 'canCreateNewLogInspectionDecoders',
        'can_delete_log_inspection_decoders': 'canDeleteLogInspectionDecoders',
        'can_edit_log_inspection_decoder_properties': 'canEditLogInspectionDecoderProperties'
    }

    def __init__(self, can_create_new_log_inspection_decoders=None, can_delete_log_inspection_decoders=None, can_edit_log_inspection_decoder_properties=None):  # noqa: E501
        """LogInspectionDecoderRights - a model defined in Swagger"""  # noqa: E501

        self._can_create_new_log_inspection_decoders = None
        self._can_delete_log_inspection_decoders = None
        self._can_edit_log_inspection_decoder_properties = None
        self.discriminator = None

        if can_create_new_log_inspection_decoders is not None:
            self.can_create_new_log_inspection_decoders = can_create_new_log_inspection_decoders
        if can_delete_log_inspection_decoders is not None:
            self.can_delete_log_inspection_decoders = can_delete_log_inspection_decoders
        if can_edit_log_inspection_decoder_properties is not None:
            self.can_edit_log_inspection_decoder_properties = can_edit_log_inspection_decoder_properties

    @property
    def can_create_new_log_inspection_decoders(self):
        """Gets the can_create_new_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501

        Right to create new log inspection decoders.  # noqa: E501

        :return: The can_create_new_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_create_new_log_inspection_decoders

    @can_create_new_log_inspection_decoders.setter
    def can_create_new_log_inspection_decoders(self, can_create_new_log_inspection_decoders):
        """Sets the can_create_new_log_inspection_decoders of this LogInspectionDecoderRights.

        Right to create new log inspection decoders.  # noqa: E501

        :param can_create_new_log_inspection_decoders: The can_create_new_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501
        :type: bool
        """

        self._can_create_new_log_inspection_decoders = can_create_new_log_inspection_decoders

    @property
    def can_delete_log_inspection_decoders(self):
        """Gets the can_delete_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501

        Right to delete log inspection decoders.  # noqa: E501

        :return: The can_delete_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete_log_inspection_decoders

    @can_delete_log_inspection_decoders.setter
    def can_delete_log_inspection_decoders(self, can_delete_log_inspection_decoders):
        """Sets the can_delete_log_inspection_decoders of this LogInspectionDecoderRights.

        Right to delete log inspection decoders.  # noqa: E501

        :param can_delete_log_inspection_decoders: The can_delete_log_inspection_decoders of this LogInspectionDecoderRights.  # noqa: E501
        :type: bool
        """

        self._can_delete_log_inspection_decoders = can_delete_log_inspection_decoders

    @property
    def can_edit_log_inspection_decoder_properties(self):
        """Gets the can_edit_log_inspection_decoder_properties of this LogInspectionDecoderRights.  # noqa: E501

        Right to edit log inspection decoder properties.  # noqa: E501

        :return: The can_edit_log_inspection_decoder_properties of this LogInspectionDecoderRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_edit_log_inspection_decoder_properties

    @can_edit_log_inspection_decoder_properties.setter
    def can_edit_log_inspection_decoder_properties(self, can_edit_log_inspection_decoder_properties):
        """Sets the can_edit_log_inspection_decoder_properties of this LogInspectionDecoderRights.

        Right to edit log inspection decoder properties.  # noqa: E501

        :param can_edit_log_inspection_decoder_properties: The can_edit_log_inspection_decoder_properties of this LogInspectionDecoderRights.  # noqa: E501
        :type: bool
        """

        self._can_edit_log_inspection_decoder_properties = can_edit_log_inspection_decoder_properties

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
        if issubclass(LogInspectionDecoderRights, dict):
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
        if not isinstance(other, LogInspectionDecoderRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
