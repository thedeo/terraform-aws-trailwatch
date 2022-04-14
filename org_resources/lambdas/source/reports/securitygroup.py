import boto3
import uuid
import logging

from common import create_client
from common import get_available_regions
from common import retry
from common import clean_account_name
from common import create_report_table
from common import swap_report_table
from common import get_report_table
from common import verify_member_role_access

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Variables
################################################################################################
from common import project_name
from common import org_account_id


################################################################################################
# Mode b Logic
################################################################################################
def get_security_groups(account_id, account_alias, region):
	ec2 = create_client(account_id, region, 'ec2')

	security_group_list = []
	# Get list of all security groups in paginated list
	next_token = False
	while True:
		if not next_token:
			try:
				response = ec2.describe_security_groups()
				security_group_list = security_group_list + response['SecurityGroups']
				if response.get('NextToken', ''):
					next_token = True
					token = response['NextToken']
				else:
					break # no more security groups left to list
			except Exception as e:
				print(e)
				exit(1)

		elif next_token:
			try:
				response = ec2.describe_security_groups(NextToken=token)
				security_group_list = security_group_list + response['SecurityGroups']
				if response.get('NextToken', ''):
					next_token = True
					token = response['NextToken']
				else:
					break # no more security groups left to list
			except Exception as e:
				print(e)
				exit(1)
	return security_group_list

def get_db_security_groups(account_id, account_alias, region):
	rds = create_client(account_id, region, 'rds')

	db_security_group_list = []
	# Get list of all db security groups in paginated list
	next_marker = False
	while True:
		if not next_marker:
			try:
				response = rds.describe_db_security_groups()
				db_security_group_list = db_security_group_list + response['DBSecurityGroups']
				if response.get('Marker', ''):
					next_marker = True
					marker = response['Marker']
				else:
					break # no more db security groups left to list
			except Exception as e:
				print(e)
				exit(1)

		elif next_marker:
			try:
				response = rds.describe_db_security_groups(Marker=marker)
				db_security_group_list = db_security_group_list + response['DBSecurityGroups']
				if response.get('Marker', ''):
					next_marker = True
					marker = response['Marker']
				else:
					break # no more db security groups left to list
			except Exception as e:
				print(e)
				exit(1)
	return db_security_group_list


def divide_list(l, n, account_id, account_name, account_alias, region, report_type, report_table, mode):
	# This function will divide lists into chunks while also inserting data
	# needed for the state machine to loop over the information properly.
	for i in range(0, len(l), n): # i will increment by n
		yield { 
				'account_id':    account_id,
				'account_name':  account_name,
				'account_alias': account_alias,
				'region':        region,
				'report_type':   report_type,
				'report_table':  report_table,
				'mode':          mode,
				'list_batch': 	 l[i:i + n] # reference by list index ex. 0:49,50:99, etc
			  }


################################################################################################
# Mode c_ec2 Logic
################################################################################################
def analyze_ec2_data(account_id, account_alias, region, security_group_list):
	processed_data_list = []
	rules = []
	for security_group in security_group_list:
		group_id = security_group['GroupId']
		group_name = security_group['GroupName']
		group_description = security_group['Description']
		group_vpc_id = security_group.get('VpcId', '-')

		# Put various permission type information into lists and dicts
		# so as to make it easier to loop over all the information.
		ip_permission_directions = {}
		ip_permission_directions['ingress'] = security_group['IpPermissions']
		ip_permission_directions['egress'] = security_group['IpPermissionsEgress']
		
		directions = ['ingress', 'egress']
		permission_types = ({'name': 'IpRanges', 'ref': 'CidrIp'},
							{'name': 'Ipv6Ranges', 'ref': 'CidrIpv6'},
							{'name': 'PrefixListIds', 'ref': 'PrefixListId'})

		for direction in directions:
			for ip_permissions in ip_permission_directions[direction]:
				for permission_type in permission_types:
					type_name = permission_type['name']
					type_ref = permission_type['ref']
					permissions = ip_permissions[type_name]
					for permission in permissions:
						rule_dict = {}

						# Find out what the ports are based on protocol
						ip_protocol  = ip_permissions['IpProtocol']
						if ip_protocol == '-1':
							from_port = 0
							to_port = 65535
						else:
							from_port = ip_permissions.get('FromPort', 0)
							to_port   = ip_permissions.get('ToPort', 0)

						rule_dict['group_id'] = group_id
						rule_dict['group_name'] = group_name
						rule_dict['group_vpc_id'] = group_vpc_id
						rule_dict['group_description'] = group_description
						rule_dict['direction'] = direction
						rule_dict['address'] = permission[type_ref]
						rule_dict['isrange'] = 'false' if from_port == to_port else 'true'
						rule_dict['ip_protocol'] = ip_protocol
						rule_dict['from_port'] = from_port
						rule_dict['to_port'] = to_port
						rule_dict['rule_description'] = permission.get('Description', '-')
						rules.append(rule_dict)

	########################
	# Package Processed Data
	########################
	for rule in rules:
		item = {}
		item.setdefault('rule_id', {})['S'] = str(uuid.uuid4())
		item.setdefault('account_id', {})['S'] = account_id
		item.setdefault('account_alias', {})['S'] = account_alias
		item.setdefault('region', {})['S'] = region
		item.setdefault('sg_type', {})['S'] = 'ec2'
		item.setdefault('group_id', {})['S'] = rule['group_id']
		item.setdefault('group_name', {})['S'] = rule['group_name']
		item.setdefault('direction', {})['S'] = rule['direction']
		item.setdefault('address', {})['S'] = rule['address']
		item.setdefault('isrange', {})['S'] = rule['isrange']
		item.setdefault('ip_protocol', {})['S'] = rule['ip_protocol']
		item.setdefault('from_port', {})['N'] = str(rule['from_port'])
		item.setdefault('to_port', {})['N'] = str(rule['to_port'])
		item.setdefault('rule_description', {})['S'] = rule['rule_description']
		processed_data_list.append({"PutRequest": {"Item": item}})

	return processed_data_list


################################################################################################
# Mode c_rds Logic
################################################################################################
def analyze_rds_data(account_id, account_alias, region, db_security_group_list):
	processed_data_list = []
	rules = []
	for security_group in db_security_group_list:
		for ip_range in security_group['IPRanges']:
			rule_dict = {}
			rule_dict['group_id'] = '-'
			rule_dict['group_vpc_id'] = security_group.get('VpcId', '-')
			rule_dict['group_name'] = security_group['DBSecurityGroupName']
			rule_dict['group_description'] = security_group['DBSecurityGroupDescription']
			rule_dict['direction'] = 'ingress'
			rule_dict['address'] = ip_range['CIDRIP']
			rule_dict['isrange'] = 'false'
			rule_dict['from_port'] = 0
			rule_dict['to_port'] = 0
			rule_dict['rule_description'] = '-'
			rules.append(rule_dict)


	########################
	# Package Processed Data
	########################
	for rule in rules:
		item = {}
		item.setdefault('rule_id', {})['S'] = str(uuid.uuid4())
		item.setdefault('account_id', {})['S'] = account_id
		item.setdefault('account_alias', {})['S'] = account_alias
		item.setdefault('region', {})['S'] = region
		item.setdefault('sg_type', {})['S'] = 'rds'
		item.setdefault('group_id', {})['S'] = '-'
		item.setdefault('group_vpc_id', {})['S'] = rule['group_vpc_id']
		item.setdefault('group_name', {})['S'] = rule['group_name']
		item.setdefault('direction', {})['S'] = 'ingress'
		item.setdefault('address', {})['S'] = rule['address']
		item.setdefault('isrange', {})['S'] = 'false'
		item.setdefault('ip_protocol', {})['S'] = 'tcp'
		item.setdefault('from_port', {})['N'] = str(0)
		item.setdefault('to_port', {})['N'] = str(0)
		item.setdefault('rule_description', {})['S'] = '-'
		processed_data_list.append({"PutRequest": {"Item": item}})

	return processed_data_list

################################################################################################
# Shared DynamoDB Logic
################################################################################################
def send_to_dynamodb(account_id, account_alias, processed_data_list, report_table):
	dynamodb = boto3.client('dynamodb', region_name='us-east-1')

	request_items_batch = []
	count = 0
	retry_limit = 3
	total_put_request = len(processed_data_list)

	# Create Batches of 25 request items
	for put_request in processed_data_list:

		request_items_batch.append(put_request)
		count += 1
		total_put_request -= 1

		if count > 24:
			# Put batch into dynamodb
			retry_count = 0
			while True:
				try:
					dynamodb.batch_write_item(RequestItems={f"{report_table}": request_items_batch})
					print(f'Put {count} items into dynamodb successfully!')
					break
				except Exception as e:
					retry_count = retry(e, f'Put items batch for {account_alias}({account_id}): {request_items_batch}', 
										retry_count, retry_limit)

			count = 0
			request_items_batch = []

		# After the count of records left goes below 24
		# wait until the records left is 0 and then send
		# to Firehose.
		if count < 25  and count != 0 and total_put_request == 0:
			# Put batch into dynamodb
			retry_count = 0
			while True:
				try:
					dynamodb.batch_write_item(RequestItems={f"{report_table}": request_items_batch})
					print(f'Put {count} items into dynamodb successfully!')
					break
				except Exception as e:
					retry_count = retry(e, f'Put items batch for {account_alias}({account_id}): {request_items_batch}', 
										retry_count, retry_limit)



################################################################################################
# Start the Script
################################################################################################
def start(event):
	report_type = event.get('report_type', '')
	mode		= event.get('mode', '')

	if not report_type == 'securitygroup':
		print('Event does not match report type "securitygroup".')
		print(event)
		exit(1)

	if mode == 'bootstrap':
		create_report_table(project_name, report_type, 'account_id', 'rule_id')

	if mode == 'a':
		# Mode a will collect a list of regions
		account_id 	  = event['payload']['Id']
		account_name  = event['payload']['Name']
		account_alias = clean_account_name(account_name)

		# Verify that role exists in member account before attempting to pull data.
		# if we can't access this account we will pass an empty list for 'region_list'
		# which will cause no further logic to run for this account.
		# This will ensure that the state machine doesn't fail if a newly added account
		# doesn't yet have the proper IAM roles to allow for analysis.
		access_verified = verify_member_role_access(account_id, 'us-east-1', 'ec2')
		if not access_verified:
			print(f'Cannot assume role for {account_alias}({account_id}). Skipping...')
			region_list = []
		else:
			print(f'Getting region list for {account_alias}({account_id})')
			region_list = get_available_regions(account_id)

		return {
			'statusCode':    200,
			'account_id':    account_id,
			'account_name':  account_name,
			'account_alias': account_alias,
			'report_type':   report_type,
			'mode':          'b',
			'region_list':   region_list
		}

	if mode == 'b':
		# Mode b collects detailed collects a list of security groups and db security groups (rds)
		account_id = event['account_id']
		account_name = event['account_name']
		account_alias = event['account_alias']
		region = event['region']
		report_table = get_report_table(report_type)

		print(f'Getting security group lists for {region} in {account_alias}({account_id})')
		security_group_list = get_security_groups(account_id, account_alias, region)
		db_security_group_list = get_db_security_groups(account_id, account_alias, region)
		
		# Divide lists into chunks of 50 to avoid lambda limits
		divided_sg_list = list(divide_list(security_group_list, 50, account_id, account_name, account_alias, region, report_type, report_table, 'c_ec2'))
		divided_db_sg_list = list(divide_list(db_security_group_list, 50, account_id, account_name, account_alias, region, report_type, report_table, 'c_rds'))

		group_lists = divided_sg_list + divided_db_sg_list

		return {
			'statusCode':    200,
			'group_lists':   group_lists
		}

	if mode == 'c_ec2':
		# Mode c_ec2 collects detailed ec2 security group data. The results are stored in DynamoDB.
		account_id = event['account_id']
		account_alias = event['account_alias']
		region = event['region']
		security_group_list = event['list_batch']
		num_security_groups = len(security_group_list)
		report_table = event['report_table']
		
		print(f'Analyzing data for {num_security_groups} security groups in {region} - {account_alias}({account_id})...')
		processed_data_list = analyze_ec2_data(account_id, account_alias, region, security_group_list)

		print(f'Sending data for {num_security_groups} security groups in {account_alias}({account_id}) to DynamoDB...')
		send_to_dynamodb(account_id, account_alias, processed_data_list, report_table)


	if mode == 'c_rds':
		# Mode c_rds collects detailed rds db security group data. The results are stored in DynamoDB.
		account_id = event['account_id']
		account_alias = event['account_alias']
		region = event['region']
		db_security_group_list = event['list_batch']
		num_security_groups = len(db_security_group_list)
		report_table = event['report_table']
		
		print(f'Analyzing data for {num_security_groups} db security groups in {region} - {account_alias}({account_id})...')
		processed_data_list = analyze_rds_data(account_id, account_alias, region, db_security_group_list)

		print(f'Sending data for {num_security_groups} db security groups in {account_alias}({account_id}) to DynamoDB...')
		send_to_dynamodb(account_id, account_alias, processed_data_list, report_table)

	if mode == 'cleanup':
		# We will update the active table to the one we just created in mode a.
		swap_report_table(project_name, report_type)
