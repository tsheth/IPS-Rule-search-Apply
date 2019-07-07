

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception
import os
import json

# Import code example files for testing
import computer_status_examples

# Uncomment to allow connections that are 'secured' with self-signed certificate 
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the DSM URL and API key from a JSON file
property_file = os.path.dirname(os.path.abspath(__file__)) + '/properties.json'

with open(property_file) as raw_properties:
    properties = json.load(raw_properties)

secret_key = properties['secretkey']
url = properties['url']

# Add DSM host information to the API client configuration
configuration = api.Configuration()
configuration.host = url
configuration.api_key['api-secret-key'] = secret_key

api_version = 'v1'

# Values for use in examples

# policy_id for Rate Limit example
# policy_id for Application Control example
# policy_id for Integrity Monitoring example
# policy_id for Intrusion Prevention examples
# policy_id for Log Inspection Examples
# policy_id for Web Reputation examples
# policy_id for Anti-malware example
# policy_id for Firewall example
# policy_id for Search Examples
policy_id = 201

# computer_ids for Rate Limit example
computer_ids = [31, 32, 33, 34, 35]
cve_id = "CVE-2006-0468"

# computer_id & policy_name for Policy examples
computer_id = 1
policy_name = "API_Test_Policy"
reset_li_policy_id = 8
reset_li_rule_id = 20

# im_rule_ids for Integrity Monitoring example
im_rule_ids = [1, 2]

# li_rules for Log Inspection Examples
li_rules = [21, 25, 31]

# security_level for Web Reputation examples
security_level = "High"

# real_time_scan_config_id & real_time_scan_schedule_id for Anti-malware example
real_time_scan_config_id = 1
real_time_scan_schedule_id = 4

# ip_rule_ids for Intrusion Prevention examples
ip_rule_ids = [1, 2, 3, 4]

# key_id & role_id & key_name for API Key examples
key_id = 4
role_id = 1
key_name = "auditor_key"

# rule_ids for Firewall examples
rule_ids = [1, 2, 3, 4]

# num_days & relay_list_id & name for Search Examples
num_days = 40
relay_list_id = 1
name = "API Policy"

# computer_id_status_change, rule_id, rule_id_2 & cve_id for Computer Status examples
computer_id_status_change = 2
rule_id = 6104
rule_id_2 = 5930
data = "NO"

# for Common Objects examples
scan_config_id = 2
dir_list_id = 1
li_rule_name = "Inspect log for error"
path = "C:/logfile.log"
pattern = "^ERROR"
group = "Windows Rules"
xml = "PGdyb3VwIG5hbWU9IldpbmRvd3MgUnVsZXMiPg0KICA8cnVsZSBpZD0iMTAwMDAwIiBsZXZlbD0iMCI"
dir_list_name = "test list"
dir_path = "C:\\windows\\"

# for Tenant examples
account_name = "Test_tenant"
tenant_id = 6
new_policy = api.Policy()
new_policy.name = "Test Policy"
new_policy.description = "Inherits from Base Policy"
new_policy.auto_requires_update = "on"
new_policy.parent_id = 1

# For Settings examples
settings_policy_id = 9

# For Computer Overrides examples
override_computer_id = 2
expand = api.Expand()
expand.add(expand.intrusion_prevention)

# For Scheduled Tasks examples
custom_interval = 2
start_time = 30000
day = 14
scheduled_task_id = 5

# For Role examples
role_name = "Auditor"

# For Automate Deployment examples
host_name = "testhostname"


def main():
    # Rate Limit example
    # print(
    #        "Displaying result from role_limit_examples.set_computer_policy_check_rate_limit\n" +
    #        str(rate_limit_examples.set_computer_policy_check_rate_limit(
    #
    # )

    # print(
    #         "Displaying results from computer_status_examples.apply_rule_to_policies:\n" +
    #        str(computer_status_examples.apply_rule_to_policies(
    #           api, configuration, api_version, api_exception, computer_status_examples.check_computers_for_ip_rule(
    #               api, configuration, api_version, api_exception, rule_id), rule_id_2), ) +
    #       "Displaying results from intrusion_prevention_recommendations" +
    #       computer_status_examples.get_intrusion_prevention_recommendations(
    #           api, configuration, api_version, api_exception, computer_id)
    # )

    # print("Displaying polices" + str(computer_status_examples.get_policies_list(api, configuration, api_version, api_exception)))

    # print("Displaying polices" + str(
    #    computer_status_examples.get_intrusion_prevention_recommendations(api, configuration, api_version,api_exception, computer_id)))

    print("Displaying polices" + str(
       computer_status_examples.find_rules_for_cve(api, configuration, api_version, api_exception, cve_id)))

    #print("Displaying  Prevention rules for all computers of active tenants  " +computer_status_examples.get_ip_rules_for_tenant_computers(api, configuration, api_version, api_exception))
    # print("Displaying RECOMMENDATIONS" + str(computer_status_examples.get_intrusion_prevention_recommendations(api, configuration, api_version, api_exception, computer_id)))
    # print("Displaying Recommendation rules set to NO " + str(computer_status_examples.search_updated_intrusion_prevention_rules(api, configuration, api_version,api_exception, data)))
    # print("Displaying Smart type computers" +str(computer_status_examples.find_rules_for_Type(api, configuration, api_version, api_exception, type)))


if __name__ == '__main__':
    main()
