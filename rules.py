# Copyright 2019 Trend Micro.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

def find_rules_for_recommendable(api, configuration, api_version, api_exception):

    rule_id_s = []

    # Set search criteria for recommendable rule
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "recommendationsMode"
    search_criteria.choice_value = "disabled"
    search_criteria.choice_test = "equal"

    search_criteria2 = api.SearchCriteria()
    search_criteria2.field_name = "severity"
    search_criteria2.choice_value = "high"
    search_criteria2.choice_test = "equal"

    # Create a search filter for recommendable
    search_filter = api.SearchFilter()
    search_filter.search_criteria = [search_criteria, search_criteria2]



    try:
        # Search for all intrusion prevention rules for the CVE
        ip_rules_api = api.IntrusionPreventionRulesApi(api.ApiClient(configuration))
        ip_rules_search_results = ip_rules_api.search_intrusion_prevention_rules(api_version,
                                                                             search_filter=search_filter)
        # Get the intrusion prevention rule IDs for the RECOMMENDABLE field set to No from the results
        for rule in ip_rules_search_results.intrusion_prevention_rules:
            rule_id_s.append(rule.id)

        return rule_id_s

    except api_exception as e:
        return "Exception: " + str(e)


def get_intrusion_prevention_recommendations(api, configuration, api_version, api_exception, computer_id):
    """Obtains the list of recommended intrusion prevention rules to apply to a computer, according to the results of the last recommendation scan.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer that was scanned.
    :return: A list of recommended Intrusion Prevention rules to apply to a computer,
    according to the results of the last recommendation scan or None if no scan was performed.
    """

    ip_recommendations_api = api.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(
        api.ApiClient(configuration))

    try:
        ip_assignments = ip_recommendations_api.list_intrusion_prevention_rule_ids_on_computer(computer_id, api_version,
                                                                                               overrides=False)
        return ip_assignments.recommended_to_assign_rule_ids

    except api_exception as e:
        return "Exception: " + str(e)
