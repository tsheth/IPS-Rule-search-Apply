from __future__ import print_function
import sys, warnings
import deepsecurity
from deepsecurity.rest import ApiException


##set paged search function
def paged_search_computers(api, configuration, api_version, api_exception, pagesize):
	""" Uses a search filter to create a paged list of computers

	:param api: The Deep Security API modules.
	:param configuration: Configuration object to pass to the api client.
	:param api_version: The version of the API to use.
	:param api_exception: The Deep Security API exception module.
	:return: A list of computer objects
	"""

	# Set search criteria
	search_criteria = api.SearchCriteria()
	search_criteria.id_value = 0
	search_criteria.id_test = "greater-than"

	# Create a search filter with maximum returned items
	page_size = pagesize
	search_filter = api.SearchFilter()
	search_filter.max_items = page_size
	search_filter.search_criteria = [search_criteria]

	# Perform the search and do work on the results
	computers_api = api.ComputersApi(api.ApiClient(configuration))
	paged_computers = []

	try:
		while True:
			computers = computers_api.search_computers(api_version, search_filter=search_filter)
			num_found = len(computers.computers)
			current_paged_computers = []

			if num_found == 0:
				print("No computers found.")
				break

			for computer in computers.computers:
				current_paged_computers.append(computer)

			for item in current_paged_computers:
				paged_computers.append(item)

			# Get the ID of the last computer in the page and return it with the number of computers on the page
			last_id = computers.computers[-1].id
			search_criteria.id_value = last_id
			print("Last ID: " + str(last_id), "Computers found: " + str(num_found))

			###change back to if num_found != page_size:
			### to perform tests use if num_found != 1:
			if num_found != page_size:
				break

		return paged_computers
		#print(len(paged_computers))
	except api_exception as e:
		return "Exception: " + str(e)

#######################FUNCTIONS END ##########################



####global variables
total_computers_list = []
anti_mal = []

# DSAAS API Setup
if not sys.warnoptions:
	warnings.simplefilter("ignore")
configuration = deepsecurity.Configuration()
configuration.host = 'https://dsm.brycehawk.com/api'

# Authentication
#configuration.api_key['api-secret-key'] = "0FA59FB6-961A-A931-C955-FA7258C3C898:120ECCD8-E79A-E4C3-D9C4-F1AAE59B376A:P/mygoaZe6XyNhnqKNGxyxKxoI4Xv+GDfjHnYaRs060="
configuration.api_key['api-secret-key'] = "78878370-2536-C1E9-3E5C-1017B35CA282:cBX8mdZ5Uh/GVtflOqb9uW3GUMlM53AzXYijuXfB8fA="

# Initialization
# Set Any Required Values
#api_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
api_version = 'v1'

total_computers_list=paged_search_computers(deepsecurity,configuration,api_version,ApiException,100)
totalcomps=len(total_computers_list)
print(str(totalcomps)+" computers imported into buffer")

advanced_threat_correlation_pattern = ""
advanced_threat_scan_engine = ""
intellitrap_exception_pattern = ""
intellitrap_pattern = ""
smartscan_agent_pattern = ""
trusted_cert_auth_pattern = ""

iep = ""
ip = ""


if len(total_computers_list) !=0:
	for computer in total_computers_list:
		if computer.agent_version != "0.0.0.0":
			#for anti_malware in computer.security_updates:
			#	if anti_malware['name'] == 'Advanced Threat Correlation Pattern':
			#		advanced_threat_correlation_pattern = anti_malware['version']
			#	if anti_malware['name'] == 'Advanced Threat Scan Engine':
			#		advanced_threat_scan_engine = anti_malware['version']
			print("Host Name: " + str(computer.host_name))
			print("DSA version:  " + str(computer.agent_version))
			print("Security Update details:  " + str(computer.security_updates))
			print("------------------------------------------------------------------------")
			#print(computer.security_updates.anti_malware.last_changed)
