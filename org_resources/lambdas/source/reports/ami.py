import boto3
import logging

from common import create_client
from common import get_available_regions
from common import retry
from common import clean_account_name
from common import create_report_table
from common import swap_report_table
from common import get_report_table

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Variables
################################################################################################
from common import project_name
from common import org_account_id

ami_aws_account_mapping = {
	'309956199498': 'redhat',
	'099720109477': 'ubuntu',
	'125523088429': 'centos',
	'136693071363': 'debian',
	'379101102735': 'debian'
}

################################################################################################
# Mode B Logic
################################################################################################
def get_instance_list(account_id, account_alias, region):
	ec2 = create_client(account_id, region, 'ec2')

	instance_list = []
	# Get list of all resources in paginated list
	next_token = False
	retry_limit = 3
	retry_count = 0
	while True:
		if not next_token:
			try:
				response = ec2.describe_instances()
				instance_list = instance_list + response['Reservations']
				if response.get('NextToken', ''):
					next_token = True
					token = response['NextToken']
				else:
					break # no more resources left to list
			except Exception as e:
				retry_count = retry(e, f'Get instance_list for {account_alias}({account_id}): {region}', 
									retry_count, retry_limit)

		elif next_token:
			try:
				response = ec2.describe_instances(NextToken=token)
				instance_list = instance_list + response['Reservations']
				if response.get('NextToken', ''):
					next_token = True
					token = response['NextToken']
				else:
					break # no more resources left to list
			except Exception as e:
				retry_count = retry(e, f'Get instance_list for {account_alias}({account_id}): {region}',
									retry_count, retry_limit)
	return instance_list


def get_ami_details(account_id, account_alias, region, instance_list):
	ec2 = create_client(account_id, region, 'ec2')

	instance_id_and_ami_id_list = []
	ami_list = []
	ami_details = {}
	for reservation in instance_list:
		for instance in reservation.get('Instances', []):
			instance_id_and_ami_id_list.append({'instance_id': instance['InstanceId'], 
												'instance_state': instance['State']['Name'],
												'ami_id': instance['ImageId']}
			)
			ami_list.append(instance['ImageId'])

	if instance_id_and_ami_id_list:
		# Get resource detail
		retry_limit = 3
		retry_count = 0
		while True:
			try:
				response = ec2.describe_images(ImageIds=ami_list,IncludeDeprecated=True)
				break
			except Exception as e:
				retry_count = retry(e, f'Get AMI details for {account_alias}({account_id}): {region}', 
									retry_count, retry_limit)

		# Put AMI details in to dict for easier use later.
		for ami in response['Images']:
			ami_id = ami['ImageId']
			ami_details[ami_id] = ami

	return ami_details, instance_id_and_ami_id_list

def try_mapping(ami_owner):
	if ami_owner == '-':
		return '-'
	else:
		return ami_aws_account_mapping.get(ami_owner, '-')


def analyze_data(account_id, account_alias, region, ami_details, instance_id_and_ami_id_list):

	########################
	# Package Processed Data
	########################
	processed_data_list = []
	for instance_id_and_ami_id in instance_id_and_ami_id_list:
		ami_id = instance_id_and_ami_id['ami_id']
		ami_owner = ami_details.get(ami_id, {}).get('OwnerId', '-')

		item = {}
		item.setdefault('account_id', {})['S'] = account_id
		item.setdefault('account_alias', {})['S'] = account_alias
		item.setdefault('region', {})['S'] = region
		item.setdefault('instance_id', {})['S'] = instance_id_and_ami_id['instance_id']
		item.setdefault('instance_state', {})['S'] = instance_id_and_ami_id['instance_state']
		item.setdefault('ami_id', {})['S'] = ami_id
		item.setdefault('ami_name', {})['S'] = ami_details.get(ami_id, {}).get('Name', '-')
		item.setdefault('ami_state', {})['S'] = ami_details.get(ami_id, {}).get('State', '-')
		item.setdefault('ami_owner', {})['S'] = ami_owner
		item.setdefault('ami_owner_alias', {})['S'] = ami_details.get(ami_id, {}).get('ImageOwnerAlias', try_mapping(ami_owner))
		item.setdefault('public', {})['S'] = str(ami_details.get(ami_id, {}).get('Public', '-')).lower()
		item.setdefault('platform', {})['S'] = ami_details.get(ami_id, {}).get('Platform', 'other')
		item.setdefault('architecture', {})['S'] = ami_details.get(ami_id, {}).get('Architecture', '-')
		item.setdefault('virt_type', {})['S'] = ami_details.get(ami_id, {}).get('VirtualizationType', '-')
		item.setdefault('root_device_type', {})['S'] = ami_details.get(ami_id, {}).get('RootDeviceType', '-')
		item.setdefault('root_device_name', {})['S'] = ami_details.get(ami_id, {}).get('RootDeviceName', '-')
		item.setdefault('description', {})['S'] = ami_details.get(ami_id, {}).get('Description', '-')
		item.setdefault('creation_date', {})['S'] = ami_details.get(ami_id, {}).get('CreationDate', '-')
		processed_data_list.append({"PutRequest": {"Item": item}})

	return processed_data_list


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

	if not report_type == 'ami':
		print('Event does not match report type "ami".')
		print(event)
		exit(1)

	if mode == 'bootstrap':
		create_report_table(project_name, report_type, 'account_id', 'instance_id')

	if mode == 'a':
		# Mode a will collect a list of users, divide them into 50 user chunks for processing.
		account_id 	  = event['payload']['Id']
		account_name  = event['payload']['Name']
		account_alias = clean_account_name(account_name)
		
		print(f'Getting region list for {account_alias}({account_id})')
		region_list = get_available_regions(account_id)

		return {
			'statusCode':    200,
			'account_id':    account_id,
			'account_name':  account_name,
			'account_alias': account_alias,
			'report_type':   report_type,
			'mode':          'b',
			'region_list': region_list
		}

	if mode == 'b':
		# Mode b collects detailed instance image data and perform analysis on it. The result is stored in DynamoDB.
		account_id    = event['account_id']
		account_alias = event['account_alias']
		region        = event['region']
		
		print(f'Getting instance list for {account_alias}({account_id}) - {region}')
		instance_list = get_instance_list(account_id, account_alias, region)

		print(f'Getting AMI details for {account_alias}({account_id}) - {region}')
		ami_details, instance_id_and_ami_id_list = get_ami_details(account_id, account_alias, region, instance_list)

		if instance_id_and_ami_id_list:
			print(f'Analyzing data for {account_alias}({account_id}) - {region}')
			processed_data_list = analyze_data(account_id, account_alias, region, ami_details, instance_id_and_ami_id_list)

			print(f'Sending data for {account_alias}({account_id}) to DynamoDB...')
			report_table = get_report_table(report_type)
			send_to_dynamodb(account_id, account_alias, processed_data_list, report_table)
		else:
			print(f'No instances found for {account_alias}({account_id}) - {region}')

	if mode == 'cleanup':
		# We will update the active table to the one we just created in mode a.
		swap_report_table(project_name, report_type)
