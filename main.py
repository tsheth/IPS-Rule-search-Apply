

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception
import os
import json
import argparse

# Import code example files for testing
import rules

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

def parse_args():
    """Parse command-line arguments."""

    # This is split out from the main() function solely so that I can skip over
    # it more easily when going through the code.

    parser = argparse.ArgumentParser(
        description='List vulnerabilities found in scans',
    )

    parser.add_argument(
        '--policy-id',
        action='store',
        default=os.environ.get('POLICY_ID', None),
        help='The policy id where all rules need to be applied. Example: 1'
    )


    return parser.parse_args()

def main():
    args = parse_args()
    print(args)
    policy_id = args.policy_id

    recommendable_no_rule = rules.find_rules_for_recommendable(api, configuration, api_version, api_exception)
    print(recommendable_no_rule)
    print(rules.apply_intrusion_prevention_recommendations(api, configuration, api_version, api_exception, recommendable_no_rule, policy_id))

if __name__ == '__main__':
    main()
