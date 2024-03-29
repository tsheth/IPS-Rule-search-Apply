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

from deepsecurity.models.check_for_security_updates_task_parameters import CheckForSecurityUpdatesTaskParameters  # noqa: F401,E501
from deepsecurity.models.discover_computers_task_parameters import DiscoverComputersTaskParameters  # noqa: F401,E501
from deepsecurity.models.generate_report_task_parameters import GenerateReportTaskParameters  # noqa: F401,E501
from deepsecurity.models.run_script_task_parameters import RunScriptTaskParameters  # noqa: F401,E501
from deepsecurity.models.scan_for_integrity_changes_task_parameters import ScanForIntegrityChangesTaskParameters  # noqa: F401,E501
from deepsecurity.models.scan_for_malware_task_parameters import ScanForMalwareTaskParameters  # noqa: F401,E501
from deepsecurity.models.scan_for_open_ports_task_parameters import ScanForOpenPortsTaskParameters  # noqa: F401,E501
from deepsecurity.models.scan_for_recommendations_task_parameters import ScanForRecommendationsTaskParameters  # noqa: F401,E501
from deepsecurity.models.schedule_details import ScheduleDetails  # noqa: F401,E501
from deepsecurity.models.send_alert_summary_task_parameters import SendAlertSummaryTaskParameters  # noqa: F401,E501
from deepsecurity.models.send_policy_task_parameters import SendPolicyTaskParameters  # noqa: F401,E501
from deepsecurity.models.synchronize_cloud_account_task_parameters import SynchronizeCloudAccountTaskParameters  # noqa: F401,E501
from deepsecurity.models.synchronize_directory_task_parameters import SynchronizeDirectoryTaskParameters  # noqa: F401,E501
from deepsecurity.models.synchronize_v_center_task_parameters import SynchronizeVCenterTaskParameters  # noqa: F401,E501
from deepsecurity.models.update_suspicious_objects_list_task_parameters import UpdateSuspiciousObjectsListTaskParameters  # noqa: F401,E501


class ScheduledTask(object):
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
        'type': 'str',
        'schedule_details': 'ScheduleDetails',
        'enabled': 'bool',
        'last_run_time': 'int',
        'next_run_time': 'int',
        'run_now': 'bool',
        'scan_for_open_ports_task_parameters': 'ScanForOpenPortsTaskParameters',
        'send_alert_summary_task_parameters': 'SendAlertSummaryTaskParameters',
        'discover_computers_task_parameters': 'DiscoverComputersTaskParameters',
        'run_script_task_parameters': 'RunScriptTaskParameters',
        'send_policy_task_parameters': 'SendPolicyTaskParameters',
        'generate_report_task_parameters': 'GenerateReportTaskParameters',
        'synchronize_directory_task_parameters': 'SynchronizeDirectoryTaskParameters',
        'scan_for_recommendations_task_parameters': 'ScanForRecommendationsTaskParameters',
        'synchronize_v_center_task_parameters': 'SynchronizeVCenterTaskParameters',
        'scan_for_integrity_changes_task_parameters': 'ScanForIntegrityChangesTaskParameters',
        'scan_for_malware_task_parameters': 'ScanForMalwareTaskParameters',
        'check_for_security_updates_task_parameters': 'CheckForSecurityUpdatesTaskParameters',
        'synchronize_cloud_account_task_parameters': 'SynchronizeCloudAccountTaskParameters',
        'update_suspicious_objects_list_task_parameters': 'UpdateSuspiciousObjectsListTaskParameters',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'type': 'type',
        'schedule_details': 'scheduleDetails',
        'enabled': 'enabled',
        'last_run_time': 'lastRunTime',
        'next_run_time': 'nextRunTime',
        'run_now': 'runNow',
        'scan_for_open_ports_task_parameters': 'scanForOpenPortsTaskParameters',
        'send_alert_summary_task_parameters': 'sendAlertSummaryTaskParameters',
        'discover_computers_task_parameters': 'discoverComputersTaskParameters',
        'run_script_task_parameters': 'runScriptTaskParameters',
        'send_policy_task_parameters': 'sendPolicyTaskParameters',
        'generate_report_task_parameters': 'generateReportTaskParameters',
        'synchronize_directory_task_parameters': 'synchronizeDirectoryTaskParameters',
        'scan_for_recommendations_task_parameters': 'scanForRecommendationsTaskParameters',
        'synchronize_v_center_task_parameters': 'synchronizeVCenterTaskParameters',
        'scan_for_integrity_changes_task_parameters': 'scanForIntegrityChangesTaskParameters',
        'scan_for_malware_task_parameters': 'scanForMalwareTaskParameters',
        'check_for_security_updates_task_parameters': 'checkForSecurityUpdatesTaskParameters',
        'synchronize_cloud_account_task_parameters': 'synchronizeCloudAccountTaskParameters',
        'update_suspicious_objects_list_task_parameters': 'updateSuspiciousObjectsListTaskParameters',
        'id': 'ID'
    }

    def __init__(self, name=None, type=None, schedule_details=None, enabled=None, last_run_time=None, next_run_time=None, run_now=None, scan_for_open_ports_task_parameters=None, send_alert_summary_task_parameters=None, discover_computers_task_parameters=None, run_script_task_parameters=None, send_policy_task_parameters=None, generate_report_task_parameters=None, synchronize_directory_task_parameters=None, scan_for_recommendations_task_parameters=None, synchronize_v_center_task_parameters=None, scan_for_integrity_changes_task_parameters=None, scan_for_malware_task_parameters=None, check_for_security_updates_task_parameters=None, synchronize_cloud_account_task_parameters=None, update_suspicious_objects_list_task_parameters=None, id=None):  # noqa: E501
        """ScheduledTask - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._type = None
        self._schedule_details = None
        self._enabled = None
        self._last_run_time = None
        self._next_run_time = None
        self._run_now = None
        self._scan_for_open_ports_task_parameters = None
        self._send_alert_summary_task_parameters = None
        self._discover_computers_task_parameters = None
        self._run_script_task_parameters = None
        self._send_policy_task_parameters = None
        self._generate_report_task_parameters = None
        self._synchronize_directory_task_parameters = None
        self._scan_for_recommendations_task_parameters = None
        self._synchronize_v_center_task_parameters = None
        self._scan_for_integrity_changes_task_parameters = None
        self._scan_for_malware_task_parameters = None
        self._check_for_security_updates_task_parameters = None
        self._synchronize_cloud_account_task_parameters = None
        self._update_suspicious_objects_list_task_parameters = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if type is not None:
            self.type = type
        if schedule_details is not None:
            self.schedule_details = schedule_details
        if enabled is not None:
            self.enabled = enabled
        if last_run_time is not None:
            self.last_run_time = last_run_time
        if next_run_time is not None:
            self.next_run_time = next_run_time
        if run_now is not None:
            self.run_now = run_now
        if scan_for_open_ports_task_parameters is not None:
            self.scan_for_open_ports_task_parameters = scan_for_open_ports_task_parameters
        if send_alert_summary_task_parameters is not None:
            self.send_alert_summary_task_parameters = send_alert_summary_task_parameters
        if discover_computers_task_parameters is not None:
            self.discover_computers_task_parameters = discover_computers_task_parameters
        if run_script_task_parameters is not None:
            self.run_script_task_parameters = run_script_task_parameters
        if send_policy_task_parameters is not None:
            self.send_policy_task_parameters = send_policy_task_parameters
        if generate_report_task_parameters is not None:
            self.generate_report_task_parameters = generate_report_task_parameters
        if synchronize_directory_task_parameters is not None:
            self.synchronize_directory_task_parameters = synchronize_directory_task_parameters
        if scan_for_recommendations_task_parameters is not None:
            self.scan_for_recommendations_task_parameters = scan_for_recommendations_task_parameters
        if synchronize_v_center_task_parameters is not None:
            self.synchronize_v_center_task_parameters = synchronize_v_center_task_parameters
        if scan_for_integrity_changes_task_parameters is not None:
            self.scan_for_integrity_changes_task_parameters = scan_for_integrity_changes_task_parameters
        if scan_for_malware_task_parameters is not None:
            self.scan_for_malware_task_parameters = scan_for_malware_task_parameters
        if check_for_security_updates_task_parameters is not None:
            self.check_for_security_updates_task_parameters = check_for_security_updates_task_parameters
        if synchronize_cloud_account_task_parameters is not None:
            self.synchronize_cloud_account_task_parameters = synchronize_cloud_account_task_parameters
        if update_suspicious_objects_list_task_parameters is not None:
            self.update_suspicious_objects_list_task_parameters = update_suspicious_objects_list_task_parameters
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this ScheduledTask.  # noqa: E501

        Name of scheduled task. Searchable as String.  # noqa: E501

        :return: The name of this ScheduledTask.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this ScheduledTask.

        Name of scheduled task. Searchable as String.  # noqa: E501

        :param name: The name of this ScheduledTask.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def type(self):
        """Gets the type of this ScheduledTask.  # noqa: E501

        Type of scheduled task. Searchable as Choice.  # noqa: E501

        :return: The type of this ScheduledTask.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this ScheduledTask.

        Type of scheduled task. Searchable as Choice.  # noqa: E501

        :param type: The type of this ScheduledTask.  # noqa: E501
        :type: str
        """
        allowed_values = ["scan-for-open-ports", "send-alert-summary", "discover-computers", "run-script", "send-policy", "generate-report", "synchronize-directory", "synchronize-users", "scan-for-recommendations", "synchronize-vcenter", "scan-for-integrity-changes", "scan-for-malware", "check-for-security-updates", "synchronize-cloud-account", "check-for-software-updates", "update-suspicious-objects-list"]  # noqa: E501
        if type not in allowed_values:
            raise ValueError(
                "Invalid value for `type` ({0}), must be one of {1}"  # noqa: E501
                .format(type, allowed_values)
            )

        self._type = type

    @property
    def schedule_details(self):
        """Gets the schedule_details of this ScheduledTask.  # noqa: E501


        :return: The schedule_details of this ScheduledTask.  # noqa: E501
        :rtype: ScheduleDetails
        """
        return self._schedule_details

    @schedule_details.setter
    def schedule_details(self, schedule_details):
        """Sets the schedule_details of this ScheduledTask.


        :param schedule_details: The schedule_details of this ScheduledTask.  # noqa: E501
        :type: ScheduleDetails
        """

        self._schedule_details = schedule_details

    @property
    def enabled(self):
        """Gets the enabled of this ScheduledTask.  # noqa: E501

        Indicates whether or not the scheduled task is enabled. Searchable as Boolean.  # noqa: E501

        :return: The enabled of this ScheduledTask.  # noqa: E501
        :rtype: bool
        """
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Sets the enabled of this ScheduledTask.

        Indicates whether or not the scheduled task is enabled. Searchable as Boolean.  # noqa: E501

        :param enabled: The enabled of this ScheduledTask.  # noqa: E501
        :type: bool
        """

        self._enabled = enabled

    @property
    def last_run_time(self):
        """Gets the last_run_time of this ScheduledTask.  # noqa: E501

        The last time this scheduled task was run, or null if never run. Searchable as Date.  # noqa: E501

        :return: The last_run_time of this ScheduledTask.  # noqa: E501
        :rtype: int
        """
        return self._last_run_time

    @last_run_time.setter
    def last_run_time(self, last_run_time):
        """Sets the last_run_time of this ScheduledTask.

        The last time this scheduled task was run, or null if never run. Searchable as Date.  # noqa: E501

        :param last_run_time: The last_run_time of this ScheduledTask.  # noqa: E501
        :type: int
        """

        self._last_run_time = last_run_time

    @property
    def next_run_time(self):
        """Gets the next_run_time of this ScheduledTask.  # noqa: E501

        The next time this scheduled task is scheduled to run, or null if it not scheduled to run in the future. Searchable as Date.  # noqa: E501

        :return: The next_run_time of this ScheduledTask.  # noqa: E501
        :rtype: int
        """
        return self._next_run_time

    @next_run_time.setter
    def next_run_time(self, next_run_time):
        """Sets the next_run_time of this ScheduledTask.

        The next time this scheduled task is scheduled to run, or null if it not scheduled to run in the future. Searchable as Date.  # noqa: E501

        :param next_run_time: The next_run_time of this ScheduledTask.  # noqa: E501
        :type: int
        """

        self._next_run_time = next_run_time

    @property
    def run_now(self):
        """Gets the run_now of this ScheduledTask.  # noqa: E501

        Indicates that the scheduled task should execute immediately.  # noqa: E501

        :return: The run_now of this ScheduledTask.  # noqa: E501
        :rtype: bool
        """
        return self._run_now

    @run_now.setter
    def run_now(self, run_now):
        """Sets the run_now of this ScheduledTask.

        Indicates that the scheduled task should execute immediately.  # noqa: E501

        :param run_now: The run_now of this ScheduledTask.  # noqa: E501
        :type: bool
        """

        self._run_now = run_now

    @property
    def scan_for_open_ports_task_parameters(self):
        """Gets the scan_for_open_ports_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The scan_for_open_ports_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: ScanForOpenPortsTaskParameters
        """
        return self._scan_for_open_ports_task_parameters

    @scan_for_open_ports_task_parameters.setter
    def scan_for_open_ports_task_parameters(self, scan_for_open_ports_task_parameters):
        """Sets the scan_for_open_ports_task_parameters of this ScheduledTask.


        :param scan_for_open_ports_task_parameters: The scan_for_open_ports_task_parameters of this ScheduledTask.  # noqa: E501
        :type: ScanForOpenPortsTaskParameters
        """

        self._scan_for_open_ports_task_parameters = scan_for_open_ports_task_parameters

    @property
    def send_alert_summary_task_parameters(self):
        """Gets the send_alert_summary_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The send_alert_summary_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: SendAlertSummaryTaskParameters
        """
        return self._send_alert_summary_task_parameters

    @send_alert_summary_task_parameters.setter
    def send_alert_summary_task_parameters(self, send_alert_summary_task_parameters):
        """Sets the send_alert_summary_task_parameters of this ScheduledTask.


        :param send_alert_summary_task_parameters: The send_alert_summary_task_parameters of this ScheduledTask.  # noqa: E501
        :type: SendAlertSummaryTaskParameters
        """

        self._send_alert_summary_task_parameters = send_alert_summary_task_parameters

    @property
    def discover_computers_task_parameters(self):
        """Gets the discover_computers_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The discover_computers_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: DiscoverComputersTaskParameters
        """
        return self._discover_computers_task_parameters

    @discover_computers_task_parameters.setter
    def discover_computers_task_parameters(self, discover_computers_task_parameters):
        """Sets the discover_computers_task_parameters of this ScheduledTask.


        :param discover_computers_task_parameters: The discover_computers_task_parameters of this ScheduledTask.  # noqa: E501
        :type: DiscoverComputersTaskParameters
        """

        self._discover_computers_task_parameters = discover_computers_task_parameters

    @property
    def run_script_task_parameters(self):
        """Gets the run_script_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The run_script_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: RunScriptTaskParameters
        """
        return self._run_script_task_parameters

    @run_script_task_parameters.setter
    def run_script_task_parameters(self, run_script_task_parameters):
        """Sets the run_script_task_parameters of this ScheduledTask.


        :param run_script_task_parameters: The run_script_task_parameters of this ScheduledTask.  # noqa: E501
        :type: RunScriptTaskParameters
        """

        self._run_script_task_parameters = run_script_task_parameters

    @property
    def send_policy_task_parameters(self):
        """Gets the send_policy_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The send_policy_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: SendPolicyTaskParameters
        """
        return self._send_policy_task_parameters

    @send_policy_task_parameters.setter
    def send_policy_task_parameters(self, send_policy_task_parameters):
        """Sets the send_policy_task_parameters of this ScheduledTask.


        :param send_policy_task_parameters: The send_policy_task_parameters of this ScheduledTask.  # noqa: E501
        :type: SendPolicyTaskParameters
        """

        self._send_policy_task_parameters = send_policy_task_parameters

    @property
    def generate_report_task_parameters(self):
        """Gets the generate_report_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The generate_report_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: GenerateReportTaskParameters
        """
        return self._generate_report_task_parameters

    @generate_report_task_parameters.setter
    def generate_report_task_parameters(self, generate_report_task_parameters):
        """Sets the generate_report_task_parameters of this ScheduledTask.


        :param generate_report_task_parameters: The generate_report_task_parameters of this ScheduledTask.  # noqa: E501
        :type: GenerateReportTaskParameters
        """

        self._generate_report_task_parameters = generate_report_task_parameters

    @property
    def synchronize_directory_task_parameters(self):
        """Gets the synchronize_directory_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The synchronize_directory_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: SynchronizeDirectoryTaskParameters
        """
        return self._synchronize_directory_task_parameters

    @synchronize_directory_task_parameters.setter
    def synchronize_directory_task_parameters(self, synchronize_directory_task_parameters):
        """Sets the synchronize_directory_task_parameters of this ScheduledTask.


        :param synchronize_directory_task_parameters: The synchronize_directory_task_parameters of this ScheduledTask.  # noqa: E501
        :type: SynchronizeDirectoryTaskParameters
        """

        self._synchronize_directory_task_parameters = synchronize_directory_task_parameters

    @property
    def scan_for_recommendations_task_parameters(self):
        """Gets the scan_for_recommendations_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The scan_for_recommendations_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: ScanForRecommendationsTaskParameters
        """
        return self._scan_for_recommendations_task_parameters

    @scan_for_recommendations_task_parameters.setter
    def scan_for_recommendations_task_parameters(self, scan_for_recommendations_task_parameters):
        """Sets the scan_for_recommendations_task_parameters of this ScheduledTask.


        :param scan_for_recommendations_task_parameters: The scan_for_recommendations_task_parameters of this ScheduledTask.  # noqa: E501
        :type: ScanForRecommendationsTaskParameters
        """

        self._scan_for_recommendations_task_parameters = scan_for_recommendations_task_parameters

    @property
    def synchronize_v_center_task_parameters(self):
        """Gets the synchronize_v_center_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The synchronize_v_center_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: SynchronizeVCenterTaskParameters
        """
        return self._synchronize_v_center_task_parameters

    @synchronize_v_center_task_parameters.setter
    def synchronize_v_center_task_parameters(self, synchronize_v_center_task_parameters):
        """Sets the synchronize_v_center_task_parameters of this ScheduledTask.


        :param synchronize_v_center_task_parameters: The synchronize_v_center_task_parameters of this ScheduledTask.  # noqa: E501
        :type: SynchronizeVCenterTaskParameters
        """

        self._synchronize_v_center_task_parameters = synchronize_v_center_task_parameters

    @property
    def scan_for_integrity_changes_task_parameters(self):
        """Gets the scan_for_integrity_changes_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The scan_for_integrity_changes_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: ScanForIntegrityChangesTaskParameters
        """
        return self._scan_for_integrity_changes_task_parameters

    @scan_for_integrity_changes_task_parameters.setter
    def scan_for_integrity_changes_task_parameters(self, scan_for_integrity_changes_task_parameters):
        """Sets the scan_for_integrity_changes_task_parameters of this ScheduledTask.


        :param scan_for_integrity_changes_task_parameters: The scan_for_integrity_changes_task_parameters of this ScheduledTask.  # noqa: E501
        :type: ScanForIntegrityChangesTaskParameters
        """

        self._scan_for_integrity_changes_task_parameters = scan_for_integrity_changes_task_parameters

    @property
    def scan_for_malware_task_parameters(self):
        """Gets the scan_for_malware_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The scan_for_malware_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: ScanForMalwareTaskParameters
        """
        return self._scan_for_malware_task_parameters

    @scan_for_malware_task_parameters.setter
    def scan_for_malware_task_parameters(self, scan_for_malware_task_parameters):
        """Sets the scan_for_malware_task_parameters of this ScheduledTask.


        :param scan_for_malware_task_parameters: The scan_for_malware_task_parameters of this ScheduledTask.  # noqa: E501
        :type: ScanForMalwareTaskParameters
        """

        self._scan_for_malware_task_parameters = scan_for_malware_task_parameters

    @property
    def check_for_security_updates_task_parameters(self):
        """Gets the check_for_security_updates_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The check_for_security_updates_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: CheckForSecurityUpdatesTaskParameters
        """
        return self._check_for_security_updates_task_parameters

    @check_for_security_updates_task_parameters.setter
    def check_for_security_updates_task_parameters(self, check_for_security_updates_task_parameters):
        """Sets the check_for_security_updates_task_parameters of this ScheduledTask.


        :param check_for_security_updates_task_parameters: The check_for_security_updates_task_parameters of this ScheduledTask.  # noqa: E501
        :type: CheckForSecurityUpdatesTaskParameters
        """

        self._check_for_security_updates_task_parameters = check_for_security_updates_task_parameters

    @property
    def synchronize_cloud_account_task_parameters(self):
        """Gets the synchronize_cloud_account_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The synchronize_cloud_account_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: SynchronizeCloudAccountTaskParameters
        """
        return self._synchronize_cloud_account_task_parameters

    @synchronize_cloud_account_task_parameters.setter
    def synchronize_cloud_account_task_parameters(self, synchronize_cloud_account_task_parameters):
        """Sets the synchronize_cloud_account_task_parameters of this ScheduledTask.


        :param synchronize_cloud_account_task_parameters: The synchronize_cloud_account_task_parameters of this ScheduledTask.  # noqa: E501
        :type: SynchronizeCloudAccountTaskParameters
        """

        self._synchronize_cloud_account_task_parameters = synchronize_cloud_account_task_parameters

    @property
    def update_suspicious_objects_list_task_parameters(self):
        """Gets the update_suspicious_objects_list_task_parameters of this ScheduledTask.  # noqa: E501


        :return: The update_suspicious_objects_list_task_parameters of this ScheduledTask.  # noqa: E501
        :rtype: UpdateSuspiciousObjectsListTaskParameters
        """
        return self._update_suspicious_objects_list_task_parameters

    @update_suspicious_objects_list_task_parameters.setter
    def update_suspicious_objects_list_task_parameters(self, update_suspicious_objects_list_task_parameters):
        """Sets the update_suspicious_objects_list_task_parameters of this ScheduledTask.


        :param update_suspicious_objects_list_task_parameters: The update_suspicious_objects_list_task_parameters of this ScheduledTask.  # noqa: E501
        :type: UpdateSuspiciousObjectsListTaskParameters
        """

        self._update_suspicious_objects_list_task_parameters = update_suspicious_objects_list_task_parameters

    @property
    def id(self):
        """Gets the id of this ScheduledTask.  # noqa: E501

        Scheduled task identifier. Searchable as ID.  # noqa: E501

        :return: The id of this ScheduledTask.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ScheduledTask.

        Scheduled task identifier. Searchable as ID.  # noqa: E501

        :param id: The id of this ScheduledTask.  # noqa: E501
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
        if issubclass(ScheduledTask, dict):
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
        if not isinstance(other, ScheduledTask):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

