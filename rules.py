

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

    search_criteria3 = api.SearchCriteria()
    search_criteria3.field_name = "severity"
    search_criteria3.choice_value = "critical"
    search_criteria3.choice_test = "equal"

    # Create a search filter for recommendable
    search_filter = api.SearchFilter()
    search_filter.search_criteria = [search_criteria, search_criteria2, search_criteria3]



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


def apply_intrusion_prevention_recommendations(api, configuration, api_version, api_exception, rule_id, policy_id_no):
    """Obtains the list of recommended intrusion prevention rules to apply to a computer, according to the results of the last recommendation scan.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param rule_id: The ID of rules that recommendable set to no.
    :return: A list of recommended Intrusion Prevention rules to apply to a computer,
    according to the results of the last recommendation scan or None if no scan was performed.
    """

    ips_recommendations_api = api.PolicyIntrusionPreventionRuleAssignmentsRecommendationsApi(api.ApiClient(configuration))
    rule_ids_obj = api.models.RuleIDs(rule_id)
    policy_id = policy_id_no
    try:
        ip_assignments = ips_recommendations_api.add_intrusion_prevention_rule_ids_to_policy(policy_id, api_version, intrusion_prevention_rule_ids=rule_ids_obj, overrides=False)
        print(ip_assignments)
        return "success"

    except api_exception as e:
        return "Exception: " + str(e)
