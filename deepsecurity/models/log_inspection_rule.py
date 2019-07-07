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

from deepsecurity.models.log_files import LogFiles  # noqa: F401,E501


class LogInspectionRule(object):
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
        'name': 'str',
        'description': 'str',
        'minimum_agent_version': 'str',
        'minimum_manager_version': 'str',
        'type': 'str',
        'original_issue': 'int',
        'last_updated': 'int',
        'identifier': 'str',
        'template': 'str',
        'rule_id': 'int',
        'level': 'int',
        'groups': 'list[str]',
        'rule_description': 'str',
        'pattern': 'str',
        'pattern_type': 'str',
        'dependency': 'str',
        'dependency_rule_id': 'int',
        'dependency_group': 'str',
        'frequency': 'int',
        'time_frame': 'int',
        'rule_xml': 'str',
        'log_files': 'LogFiles',
        'alert_enabled': 'bool',
        'alert_minimum_severity': 'int',
        'recommendations_mode': 'str',
        'sort_order': 'int',
        'can_be_assigned_alone': 'bool',
        'depends_on_rule_ids': 'list[int]',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'minimum_agent_version': 'minimumAgentVersion',
        'minimum_manager_version': 'minimumManagerVersion',
        'type': 'type',
        'original_issue': 'originalIssue',
        'last_updated': 'lastUpdated',
        'identifier': 'identifier',
        'template': 'template',
        'rule_id': 'ruleID',
        'level': 'level',
        'groups': 'groups',
        'rule_description': 'ruleDescription',
        'pattern': 'pattern',
        'pattern_type': 'patternType',
        'dependency': 'dependency',
        'dependency_rule_id': 'dependencyRuleID',
        'dependency_group': 'dependencyGroup',
        'frequency': 'frequency',
        'time_frame': 'timeFrame',
        'rule_xml': 'ruleXML',
        'log_files': 'logFiles',
        'alert_enabled': 'alertEnabled',
        'alert_minimum_severity': 'alertMinimumSeverity',
        'recommendations_mode': 'recommendationsMode',
        'sort_order': 'sortOrder',
        'can_be_assigned_alone': 'canBeAssignedAlone',
        'depends_on_rule_ids': 'dependsOnRuleIDs',
        'id': 'ID'
    }

    def __init__(self, name=None, description=None, minimum_agent_version=None, minimum_manager_version=None, type=None, original_issue=None, last_updated=None, identifier=None, template=None, rule_id=None, level=None, groups=None, rule_description=None, pattern=None, pattern_type=None, dependency=None, dependency_rule_id=None, dependency_group=None, frequency=None, time_frame=None, rule_xml=None, log_files=None, alert_enabled=None, alert_minimum_severity=None, recommendations_mode=None, sort_order=None, can_be_assigned_alone=None, depends_on_rule_ids=None, id=None):  # noqa: E501
        """LogInspectionRule - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._minimum_agent_version = None
        self._minimum_manager_version = None
        self._type = None
        self._original_issue = None
        self._last_updated = None
        self._identifier = None
        self._template = None
        self._rule_id = None
        self._level = None
        self._groups = None
        self._rule_description = None
        self._pattern = None
        self._pattern_type = None
        self._dependency = None
        self._dependency_rule_id = None
        self._dependency_group = None
        self._frequency = None
        self._time_frame = None
        self._rule_xml = None
        self._log_files = None
        self._alert_enabled = None
        self._alert_minimum_severity = None
        self._recommendations_mode = None
        self._sort_order = None
        self._can_be_assigned_alone = None
        self._depends_on_rule_ids = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if minimum_agent_version is not None:
            self.minimum_agent_version = minimum_agent_version
        if minimum_manager_version is not None:
            self.minimum_manager_version = minimum_manager_version
        if type is not None:
            self.type = type
        if original_issue is not None:
            self.original_issue = original_issue
        if last_updated is not None:
            self.last_updated = last_updated
        if identifier is not None:
            self.identifier = identifier
        if template is not None:
            self.template = template
        if rule_id is not None:
            self.rule_id = rule_id
        if level is not None:
            self.level = level
        if groups is not None:
            self.groups = groups
        if rule_description is not None:
            self.rule_description = rule_description
        if pattern is not None:
            self.pattern = pattern
        if pattern_type is not None:
            self.pattern_type = pattern_type
        if dependency is not None:
            self.dependency = dependency
        if dependency_rule_id is not None:
            self.dependency_rule_id = dependency_rule_id
        if dependency_group is not None:
            self.dependency_group = dependency_group
        if frequency is not None:
            self.frequency = frequency
        if time_frame is not None:
            self.time_frame = time_frame
        if rule_xml is not None:
            self.rule_xml = rule_xml
        if log_files is not None:
            self.log_files = log_files
        if alert_enabled is not None:
            self.alert_enabled = alert_enabled
        if alert_minimum_severity is not None:
            self.alert_minimum_severity = alert_minimum_severity
        if recommendations_mode is not None:
            self.recommendations_mode = recommendations_mode
        if sort_order is not None:
            self.sort_order = sort_order
        if can_be_assigned_alone is not None:
            self.can_be_assigned_alone = can_be_assigned_alone
        if depends_on_rule_ids is not None:
            self.depends_on_rule_ids = depends_on_rule_ids
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this LogInspectionRule.  # noqa: E501

        Name of the log inspection rule. Searchable as String.  # noqa: E501

        :return: The name of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this LogInspectionRule.

        Name of the log inspection rule. Searchable as String.  # noqa: E501

        :param name: The name of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this LogInspectionRule.  # noqa: E501

        Description of the log inspection rule that appears in search results, and on the General tab in the Deep Security Manager user interface. Searchable as String.  # noqa: E501

        :return: The description of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this LogInspectionRule.

        Description of the log inspection rule that appears in search results, and on the General tab in the Deep Security Manager user interface. Searchable as String.  # noqa: E501

        :param description: The description of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def minimum_agent_version(self):
        """Gets the minimum_agent_version of this LogInspectionRule.  # noqa: E501

        Minimum Deep Security Agent version required by the log inspection rule. Searchable as String.  # noqa: E501

        :return: The minimum_agent_version of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._minimum_agent_version

    @minimum_agent_version.setter
    def minimum_agent_version(self, minimum_agent_version):
        """Sets the minimum_agent_version of this LogInspectionRule.

        Minimum Deep Security Agent version required by the log inspection rule. Searchable as String.  # noqa: E501

        :param minimum_agent_version: The minimum_agent_version of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._minimum_agent_version = minimum_agent_version

    @property
    def minimum_manager_version(self):
        """Gets the minimum_manager_version of this LogInspectionRule.  # noqa: E501

        Minimumn Deep Security Manager version required by the log inspection rule. Searchable as String.  # noqa: E501

        :return: The minimum_manager_version of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._minimum_manager_version

    @minimum_manager_version.setter
    def minimum_manager_version(self, minimum_manager_version):
        """Sets the minimum_manager_version of this LogInspectionRule.

        Minimumn Deep Security Manager version required by the log inspection rule. Searchable as String.  # noqa: E501

        :param minimum_manager_version: The minimum_manager_version of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._minimum_manager_version = minimum_manager_version

    @property
    def type(self):
        """Gets the type of this LogInspectionRule.  # noqa: E501

        Type of the log inspection rule. The value 'Defined' is used for log inspection rules provided by Trend Micro. Searchable as String.  # noqa: E501

        :return: The type of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this LogInspectionRule.

        Type of the log inspection rule. The value 'Defined' is used for log inspection rules provided by Trend Micro. Searchable as String.  # noqa: E501

        :param type: The type of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def original_issue(self):
        """Gets the original_issue of this LogInspectionRule.  # noqa: E501

        Creation timestamp of the log inspection rule, measured in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The original_issue of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._original_issue

    @original_issue.setter
    def original_issue(self, original_issue):
        """Sets the original_issue of this LogInspectionRule.

        Creation timestamp of the log inspection rule, measured in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param original_issue: The original_issue of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._original_issue = original_issue

    @property
    def last_updated(self):
        """Gets the last_updated of this LogInspectionRule.  # noqa: E501

        Update timestamp of the log inspection rule, measured in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The last_updated of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._last_updated

    @last_updated.setter
    def last_updated(self, last_updated):
        """Sets the last_updated of this LogInspectionRule.

        Update timestamp of the log inspection rule, measured in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param last_updated: The last_updated of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._last_updated = last_updated

    @property
    def identifier(self):
        """Gets the identifier of this LogInspectionRule.  # noqa: E501

        Indentifier of the log inspection rule used in the Deep Security Manager user interface. Searchable as String.  # noqa: E501

        :return: The identifier of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._identifier

    @identifier.setter
    def identifier(self, identifier):
        """Sets the identifier of this LogInspectionRule.

        Indentifier of the log inspection rule used in the Deep Security Manager user interface. Searchable as String.  # noqa: E501

        :param identifier: The identifier of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._identifier = identifier

    @property
    def template(self):
        """Gets the template of this LogInspectionRule.  # noqa: E501

        Template used to create this rule.  # noqa: E501

        :return: The template of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._template

    @template.setter
    def template(self, template):
        """Sets the template of this LogInspectionRule.

        Template used to create this rule.  # noqa: E501

        :param template: The template of this LogInspectionRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["basic-rule", "custom"]  # noqa: E501
        if template not in allowed_values:
            raise ValueError(
                "Invalid value for `template` ({0}), must be one of {1}"  # noqa: E501
                .format(template, allowed_values)
            )

        self._template = template

    @property
    def rule_id(self):
        """Gets the rule_id of this LogInspectionRule.  # noqa: E501

        ID of the log inspection rule sent to the Deep Security Agent. The values 100000 - 109999 are reserved for user-definded rules.  # noqa: E501

        :return: The rule_id of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._rule_id

    @rule_id.setter
    def rule_id(self, rule_id):
        """Sets the rule_id of this LogInspectionRule.

        ID of the log inspection rule sent to the Deep Security Agent. The values 100000 - 109999 are reserved for user-definded rules.  # noqa: E501

        :param rule_id: The rule_id of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._rule_id = rule_id

    @property
    def level(self):
        """Gets the level of this LogInspectionRule.  # noqa: E501

        Log level of the log inspection rule indicates severity of attack. Level 0 is the least severe and will not log an event. Level 15 is the most severe.  # noqa: E501

        :return: The level of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._level

    @level.setter
    def level(self, level):
        """Sets the level of this LogInspectionRule.

        Log level of the log inspection rule indicates severity of attack. Level 0 is the least severe and will not log an event. Level 15 is the most severe.  # noqa: E501

        :param level: The level of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._level = level

    @property
    def groups(self):
        """Gets the groups of this LogInspectionRule.  # noqa: E501

        Groups that the log inspection rule is assigned to, separated by commas. Useful when dependency is used as it's possible to create a log inspection rule that fires when another log inspection rule belonging to a specific group fires.  # noqa: E501

        :return: The groups of this LogInspectionRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._groups

    @groups.setter
    def groups(self, groups):
        """Sets the groups of this LogInspectionRule.

        Groups that the log inspection rule is assigned to, separated by commas. Useful when dependency is used as it's possible to create a log inspection rule that fires when another log inspection rule belonging to a specific group fires.  # noqa: E501

        :param groups: The groups of this LogInspectionRule.  # noqa: E501
        :type: list[str]
        """

        self._groups = groups

    @property
    def rule_description(self):
        """Gets the rule_description of this LogInspectionRule.  # noqa: E501

        Description of the log inspection rule that appears on events and the Content tab in the Deep Security Manager user interface. Alternatively, you can configure this by inserting a description in 'ruleXML'.  # noqa: E501

        :return: The rule_description of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._rule_description

    @rule_description.setter
    def rule_description(self, rule_description):
        """Sets the rule_description of this LogInspectionRule.

        Description of the log inspection rule that appears on events and the Content tab in the Deep Security Manager user interface. Alternatively, you can configure this by inserting a description in 'ruleXML'.  # noqa: E501

        :param rule_description: The rule_description of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._rule_description = rule_description

    @property
    def pattern(self):
        """Gets the pattern of this LogInspectionRule.  # noqa: E501

        Regular expression pattern the log inspection rule will look for in the logs. The rule will be triggered on a match. Open Source HIDS SEcurity (OSSEC) regular expression syntax is supported, see http://www.ossec.net/docs/syntax/regex.html.  # noqa: E501

        :return: The pattern of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._pattern

    @pattern.setter
    def pattern(self, pattern):
        """Sets the pattern of this LogInspectionRule.

        Regular expression pattern the log inspection rule will look for in the logs. The rule will be triggered on a match. Open Source HIDS SEcurity (OSSEC) regular expression syntax is supported, see http://www.ossec.net/docs/syntax/regex.html.  # noqa: E501

        :param pattern: The pattern of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._pattern = pattern

    @property
    def pattern_type(self):
        """Gets the pattern_type of this LogInspectionRule.  # noqa: E501

        Pattern the log inspection rule will look for in the logs. The string matching pattern is faster than the regex pattern.  # noqa: E501

        :return: The pattern_type of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._pattern_type

    @pattern_type.setter
    def pattern_type(self, pattern_type):
        """Sets the pattern_type of this LogInspectionRule.

        Pattern the log inspection rule will look for in the logs. The string matching pattern is faster than the regex pattern.  # noqa: E501

        :param pattern_type: The pattern_type of this LogInspectionRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["string", "regex"]  # noqa: E501
        if pattern_type not in allowed_values:
            raise ValueError(
                "Invalid value for `pattern_type` ({0}), must be one of {1}"  # noqa: E501
                .format(pattern_type, allowed_values)
            )

        self._pattern_type = pattern_type

    @property
    def dependency(self):
        """Gets the dependency of this LogInspectionRule.  # noqa: E501

        Indicates if a dependant rule or dependency group is set or not. If set, the log inspection rule will only log an event if the dependency is triggered. Available for user-defined rules.  # noqa: E501

        :return: The dependency of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._dependency

    @dependency.setter
    def dependency(self, dependency):
        """Sets the dependency of this LogInspectionRule.

        Indicates if a dependant rule or dependency group is set or not. If set, the log inspection rule will only log an event if the dependency is triggered. Available for user-defined rules.  # noqa: E501

        :param dependency: The dependency of this LogInspectionRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["none", "rule", "group"]  # noqa: E501
        if dependency not in allowed_values:
            raise ValueError(
                "Invalid value for `dependency` ({0}), must be one of {1}"  # noqa: E501
                .format(dependency, allowed_values)
            )

        self._dependency = dependency

    @property
    def dependency_rule_id(self):
        """Gets the dependency_rule_id of this LogInspectionRule.  # noqa: E501

        If dependency is configured, the ID of the rule that this rule is dependant on. Ignored if the rule is from Trend Micro, which uses `dependsOnRuleIDs` instead.  # noqa: E501

        :return: The dependency_rule_id of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._dependency_rule_id

    @dependency_rule_id.setter
    def dependency_rule_id(self, dependency_rule_id):
        """Sets the dependency_rule_id of this LogInspectionRule.

        If dependency is configured, the ID of the rule that this rule is dependant on. Ignored if the rule is from Trend Micro, which uses `dependsOnRuleIDs` instead.  # noqa: E501

        :param dependency_rule_id: The dependency_rule_id of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._dependency_rule_id = dependency_rule_id

    @property
    def dependency_group(self):
        """Gets the dependency_group of this LogInspectionRule.  # noqa: E501

        If dependency is configured, the dependancy groups that this rule is dependant on.  # noqa: E501

        :return: The dependency_group of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._dependency_group

    @dependency_group.setter
    def dependency_group(self, dependency_group):
        """Sets the dependency_group of this LogInspectionRule.

        If dependency is configured, the dependancy groups that this rule is dependant on.  # noqa: E501

        :param dependency_group: The dependency_group of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._dependency_group = dependency_group

    @property
    def frequency(self):
        """Gets the frequency of this LogInspectionRule.  # noqa: E501

        Number of times the dependant rule has to match within a specific time frame before the rule is triggered.  # noqa: E501

        :return: The frequency of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._frequency

    @frequency.setter
    def frequency(self, frequency):
        """Sets the frequency of this LogInspectionRule.

        Number of times the dependant rule has to match within a specific time frame before the rule is triggered.  # noqa: E501

        :param frequency: The frequency of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._frequency = frequency

    @property
    def time_frame(self):
        """Gets the time_frame of this LogInspectionRule.  # noqa: E501

        Time period for the frequency of log inspection rule triggers that will generate an event, in seconds.  # noqa: E501

        :return: The time_frame of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._time_frame

    @time_frame.setter
    def time_frame(self, time_frame):
        """Sets the time_frame of this LogInspectionRule.

        Time period for the frequency of log inspection rule triggers that will generate an event, in seconds.  # noqa: E501

        :param time_frame: The time_frame of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._time_frame = time_frame

    @property
    def rule_xml(self):
        """Gets the rule_xml of this LogInspectionRule.  # noqa: E501

        Log inspection rule in an XML format. For information on the XML format, see http://ossec-docs.readthedocs.io/en/latest/syntax/head_rules.html  # noqa: E501

        :return: The rule_xml of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._rule_xml

    @rule_xml.setter
    def rule_xml(self, rule_xml):
        """Sets the rule_xml of this LogInspectionRule.

        Log inspection rule in an XML format. For information on the XML format, see http://ossec-docs.readthedocs.io/en/latest/syntax/head_rules.html  # noqa: E501

        :param rule_xml: The rule_xml of this LogInspectionRule.  # noqa: E501
        :type: str
        """

        self._rule_xml = rule_xml

    @property
    def log_files(self):
        """Gets the log_files of this LogInspectionRule.  # noqa: E501

        Collection of log files monitored by the log inspection rule.  # noqa: E501

        :return: The log_files of this LogInspectionRule.  # noqa: E501
        :rtype: LogFiles
        """
        return self._log_files

    @log_files.setter
    def log_files(self, log_files):
        """Sets the log_files of this LogInspectionRule.

        Collection of log files monitored by the log inspection rule.  # noqa: E501

        :param log_files: The log_files of this LogInspectionRule.  # noqa: E501
        :type: LogFiles
        """

        self._log_files = log_files

    @property
    def alert_enabled(self):
        """Gets the alert_enabled of this LogInspectionRule.  # noqa: E501

        Controls whether to raise an alert when a log inspection rule logs an event. Use true to raise an alert. Searchable as Boolean.  # noqa: E501

        :return: The alert_enabled of this LogInspectionRule.  # noqa: E501
        :rtype: bool
        """
        return self._alert_enabled

    @alert_enabled.setter
    def alert_enabled(self, alert_enabled):
        """Sets the alert_enabled of this LogInspectionRule.

        Controls whether to raise an alert when a log inspection rule logs an event. Use true to raise an alert. Searchable as Boolean.  # noqa: E501

        :param alert_enabled: The alert_enabled of this LogInspectionRule.  # noqa: E501
        :type: bool
        """

        self._alert_enabled = alert_enabled

    @property
    def alert_minimum_severity(self):
        """Gets the alert_minimum_severity of this LogInspectionRule.  # noqa: E501

        Severity level that will trigger an alert. Ignored unless `ruleXML` contains multiple rules with different severities, and so you must indicate which severity level to use. Searchable as Numeric.  # noqa: E501

        :return: The alert_minimum_severity of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._alert_minimum_severity

    @alert_minimum_severity.setter
    def alert_minimum_severity(self, alert_minimum_severity):
        """Sets the alert_minimum_severity of this LogInspectionRule.

        Severity level that will trigger an alert. Ignored unless `ruleXML` contains multiple rules with different severities, and so you must indicate which severity level to use. Searchable as Numeric.  # noqa: E501

        :param alert_minimum_severity: The alert_minimum_severity of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._alert_minimum_severity = alert_minimum_severity

    @property
    def recommendations_mode(self):
        """Gets the recommendations_mode of this LogInspectionRule.  # noqa: E501

        Indicates if the log inspection rule will be recommended or not. Use the enabled option to recommend this rule. Searchable as Choice.  # noqa: E501

        :return: The recommendations_mode of this LogInspectionRule.  # noqa: E501
        :rtype: str
        """
        return self._recommendations_mode

    @recommendations_mode.setter
    def recommendations_mode(self, recommendations_mode):
        """Sets the recommendations_mode of this LogInspectionRule.

        Indicates if the log inspection rule will be recommended or not. Use the enabled option to recommend this rule. Searchable as Choice.  # noqa: E501

        :param recommendations_mode: The recommendations_mode of this LogInspectionRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["unknown", "enabled", "ignored", "disabled"]  # noqa: E501
        if recommendations_mode not in allowed_values:
            raise ValueError(
                "Invalid value for `recommendations_mode` ({0}), must be one of {1}"  # noqa: E501
                .format(recommendations_mode, allowed_values)
            )

        self._recommendations_mode = recommendations_mode

    @property
    def sort_order(self):
        """Gets the sort_order of this LogInspectionRule.  # noqa: E501

        Order in which log inspection rules are sent to the Deep Security Agent. Log inspeciton rules are sent in ascending order. Valid values are between 10000 and 20000.  # noqa: E501

        :return: The sort_order of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._sort_order

    @sort_order.setter
    def sort_order(self, sort_order):
        """Sets the sort_order of this LogInspectionRule.

        Order in which log inspection rules are sent to the Deep Security Agent. Log inspeciton rules are sent in ascending order. Valid values are between 10000 and 20000.  # noqa: E501

        :param sort_order: The sort_order of this LogInspectionRule.  # noqa: E501
        :type: int
        """

        self._sort_order = sort_order

    @property
    def can_be_assigned_alone(self):
        """Gets the can_be_assigned_alone of this LogInspectionRule.  # noqa: E501

        Indicates whether this log inspection rule can be allocated without allocating any additional log inspection rules. Ignored if the rule is user-defined, which uses `dependency` instead.  # noqa: E501

        :return: The can_be_assigned_alone of this LogInspectionRule.  # noqa: E501
        :rtype: bool
        """
        return self._can_be_assigned_alone

    @can_be_assigned_alone.setter
    def can_be_assigned_alone(self, can_be_assigned_alone):
        """Sets the can_be_assigned_alone of this LogInspectionRule.

        Indicates whether this log inspection rule can be allocated without allocating any additional log inspection rules. Ignored if the rule is user-defined, which uses `dependency` instead.  # noqa: E501

        :param can_be_assigned_alone: The can_be_assigned_alone of this LogInspectionRule.  # noqa: E501
        :type: bool
        """

        self._can_be_assigned_alone = can_be_assigned_alone

    @property
    def depends_on_rule_ids(self):
        """Gets the depends_on_rule_ids of this LogInspectionRule.  # noqa: E501

        IDs of log inspection rules, separated by commas, that are required by this rule. Ignored if the rule is user-defined, which uses `dependencyRuleID` or `dependencyGroup` instead.  # noqa: E501

        :return: The depends_on_rule_ids of this LogInspectionRule.  # noqa: E501
        :rtype: list[int]
        """
        return self._depends_on_rule_ids

    @depends_on_rule_ids.setter
    def depends_on_rule_ids(self, depends_on_rule_ids):
        """Sets the depends_on_rule_ids of this LogInspectionRule.

        IDs of log inspection rules, separated by commas, that are required by this rule. Ignored if the rule is user-defined, which uses `dependencyRuleID` or `dependencyGroup` instead.  # noqa: E501

        :param depends_on_rule_ids: The depends_on_rule_ids of this LogInspectionRule.  # noqa: E501
        :type: list[int]
        """

        self._depends_on_rule_ids = depends_on_rule_ids

    @property
    def id(self):
        """Gets the id of this LogInspectionRule.  # noqa: E501

        ID of the log inspection rule. This number is set automatically. Searchable as ID.  # noqa: E501

        :return: The id of this LogInspectionRule.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this LogInspectionRule.

        ID of the log inspection rule. This number is set automatically. Searchable as ID.  # noqa: E501

        :param id: The id of this LogInspectionRule.  # noqa: E501
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
        if issubclass(LogInspectionRule, dict):
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
        if not isinstance(other, LogInspectionRule):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

