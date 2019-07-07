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

from deepsecurity.models.computer_filter import ComputerFilter  # noqa: F401,E501
from deepsecurity.models.recipients import Recipients  # noqa: F401,E501
from deepsecurity.models.tag_filter import TagFilter  # noqa: F401,E501
from deepsecurity.models.time_range import TimeRange  # noqa: F401,E501


class GenerateReportTaskParameters(object):
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
        'report_template_id': 'int',
        'format': 'str',
        'classification': 'str',
        'recipients': 'Recipients',
        'time_range': 'TimeRange',
        'tag_filter': 'TagFilter',
        'computer_filter': 'ComputerFilter'
    }

    attribute_map = {
        'report_template_id': 'reportTemplateID',
        'format': 'format',
        'classification': 'classification',
        'recipients': 'recipients',
        'time_range': 'timeRange',
        'tag_filter': 'tagFilter',
        'computer_filter': 'computerFilter'
    }

    def __init__(self, report_template_id=None, format=None, classification=None, recipients=None, time_range=None, tag_filter=None, computer_filter=None):  # noqa: E501
        """GenerateReportTaskParameters - a model defined in Swagger"""  # noqa: E501

        self._report_template_id = None
        self._format = None
        self._classification = None
        self._recipients = None
        self._time_range = None
        self._tag_filter = None
        self._computer_filter = None
        self.discriminator = None

        if report_template_id is not None:
            self.report_template_id = report_template_id
        if format is not None:
            self.format = format
        if classification is not None:
            self.classification = classification
        if recipients is not None:
            self.recipients = recipients
        if time_range is not None:
            self.time_range = time_range
        if tag_filter is not None:
            self.tag_filter = tag_filter
        if computer_filter is not None:
            self.computer_filter = computer_filter

    @property
    def report_template_id(self):
        """Gets the report_template_id of this GenerateReportTaskParameters.  # noqa: E501

        Report template identifier.  # noqa: E501

        :return: The report_template_id of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: int
        """
        return self._report_template_id

    @report_template_id.setter
    def report_template_id(self, report_template_id):
        """Sets the report_template_id of this GenerateReportTaskParameters.

        Report template identifier.  # noqa: E501

        :param report_template_id: The report_template_id of this GenerateReportTaskParameters.  # noqa: E501
        :type: int
        """

        self._report_template_id = report_template_id

    @property
    def format(self):
        """Gets the format of this GenerateReportTaskParameters.  # noqa: E501

        Report format.  # noqa: E501

        :return: The format of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: str
        """
        return self._format

    @format.setter
    def format(self, format):
        """Sets the format of this GenerateReportTaskParameters.

        Report format.  # noqa: E501

        :param format: The format of this GenerateReportTaskParameters.  # noqa: E501
        :type: str
        """
        allowed_values = ["pdf", "csv", "html", "plaintext", "rtf", "xls", "xml"]  # noqa: E501
        if format not in allowed_values:
            raise ValueError(
                "Invalid value for `format` ({0}), must be one of {1}"  # noqa: E501
                .format(format, allowed_values)
            )

        self._format = format

    @property
    def classification(self):
        """Gets the classification of this GenerateReportTaskParameters.  # noqa: E501

        Report classification.  # noqa: E501

        :return: The classification of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: str
        """
        return self._classification

    @classification.setter
    def classification(self, classification):
        """Sets the classification of this GenerateReportTaskParameters.

        Report classification.  # noqa: E501

        :param classification: The classification of this GenerateReportTaskParameters.  # noqa: E501
        :type: str
        """
        allowed_values = ["blank", "topsecret", "secret", "confidential", "official", "les", "limited", "unclassified", "internal"]  # noqa: E501
        if classification not in allowed_values:
            raise ValueError(
                "Invalid value for `classification` ({0}), must be one of {1}"  # noqa: E501
                .format(classification, allowed_values)
            )

        self._classification = classification

    @property
    def recipients(self):
        """Gets the recipients of this GenerateReportTaskParameters.  # noqa: E501


        :return: The recipients of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: Recipients
        """
        return self._recipients

    @recipients.setter
    def recipients(self, recipients):
        """Sets the recipients of this GenerateReportTaskParameters.


        :param recipients: The recipients of this GenerateReportTaskParameters.  # noqa: E501
        :type: Recipients
        """

        self._recipients = recipients

    @property
    def time_range(self):
        """Gets the time_range of this GenerateReportTaskParameters.  # noqa: E501


        :return: The time_range of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: TimeRange
        """
        return self._time_range

    @time_range.setter
    def time_range(self, time_range):
        """Sets the time_range of this GenerateReportTaskParameters.


        :param time_range: The time_range of this GenerateReportTaskParameters.  # noqa: E501
        :type: TimeRange
        """

        self._time_range = time_range

    @property
    def tag_filter(self):
        """Gets the tag_filter of this GenerateReportTaskParameters.  # noqa: E501


        :return: The tag_filter of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: TagFilter
        """
        return self._tag_filter

    @tag_filter.setter
    def tag_filter(self, tag_filter):
        """Sets the tag_filter of this GenerateReportTaskParameters.


        :param tag_filter: The tag_filter of this GenerateReportTaskParameters.  # noqa: E501
        :type: TagFilter
        """

        self._tag_filter = tag_filter

    @property
    def computer_filter(self):
        """Gets the computer_filter of this GenerateReportTaskParameters.  # noqa: E501


        :return: The computer_filter of this GenerateReportTaskParameters.  # noqa: E501
        :rtype: ComputerFilter
        """
        return self._computer_filter

    @computer_filter.setter
    def computer_filter(self, computer_filter):
        """Sets the computer_filter of this GenerateReportTaskParameters.


        :param computer_filter: The computer_filter of this GenerateReportTaskParameters.  # noqa: E501
        :type: ComputerFilter
        """

        self._computer_filter = computer_filter

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
        if issubclass(GenerateReportTaskParameters, dict):
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
        if not isinstance(other, GenerateReportTaskParameters):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

