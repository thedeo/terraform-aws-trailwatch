import boto3
import os
import re
import json
import logging
import datetime

from time import sleep
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Variables
################################################################################################
project_name	 	= os.environ['project_name']
region			 	= os.environ['region']
org_account_id		= os.environ['org_account_id']
member_role_name 	= os.environ['member_role_name']
session_name 		= f'{project_name}-report'

################################################################################################
# Regex
################################################################################################
is_account_id = re.compile('^[0-9]{12}$')

################################################################################################
# This function will make the datetime object serializable for json.dumps
################################################################################################
def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

################################################################################################
# Create cross account credentials
################################################################################################
def create_client(account_id, region, service):
	retry_limit = 1
	retries = 0
	while True:
		try:
			sts_connection = boto3.client('sts')
			external_account = sts_connection.assume_role(
				RoleArn=f"arn:aws:iam::{account_id}:role/{member_role_name}",
				RoleSessionName=session_name
			)
			
			ACCESS_KEY = external_account['Credentials']['AccessKeyId']
			SECRET_KEY = external_account['Credentials']['SecretAccessKey']
			SESSION_TOKEN = external_account['Credentials']['SessionToken']

			# create service client using the assumed role credentials, e.g. S3
			client = boto3.client(
				service,
				aws_access_key_id=ACCESS_KEY,
				aws_secret_access_key=SECRET_KEY,
				aws_session_token=SESSION_TOKEN,
				region_name=region
			)
			break
		except Exception as e:
			print(f'Error creating {service} client  -- {account_id}')
			print(e)
			retries += 1
			if retries >= retry_limit:
				print(f'Retry limit of {retry_limit} attempts reached. Exiting...')
				exit(1)
			sleep(2)

	return client

################################################################################################
# Get available regions for account
################################################################################################
def get_available_regions(account_id):
	# Retrieve all of the available regions in an account.

	account_regions = []
	try:
		ec2 = create_client(account_id, 'us-east-1', 'ec2')

		params = {}
		params["AllRegions"] = False
		regions_dict = ec2.describe_regions(**params)
		all_regions = [region['RegionName'] for region in regions_dict['Regions']]
	except Exception as e:
		print(e)
		pass

	# Test to see if regions found are actually enabled.
	for region in all_regions:
		sts = create_client(account_id, region, 'sts')
		try:
			sts.get_caller_identity()
			account_regions.append(region)
		except ClientError as e:
			continue

	return account_regions

################################################################################################
# DynamoDB - Manage Report Tables
################################################################################################
def create_report_table(project_name, report_type, table_hash, table_range):
	dynamodb = boto3.client('dynamodb', region_name='us-east-1')
	retry_limit = 3

	#########################################################
	# Create DynamoDB table
	#########################################################
	timestamp = datetime.datetime.utcnow().strftime('%m%d%Y-%H%M%S%f')[:-4]
	next_table_name = f'{project_name}-report-{report_type}-{timestamp}'

	retry_count = 0
	while True:
		try:
			print(f'>>> Creating table [{next_table_name}]...')
			response = dynamodb.create_table(
				TableName=next_table_name,
				KeySchema=[
					{
						'AttributeName': table_hash,
						'KeyType': 'HASH'  # Partition key
					},
					{
						'AttributeName': table_range,
						'KeyType': 'RANGE'  # Sort key
					},
				],
				AttributeDefinitions=[
					{
						'AttributeName': table_hash,
						'AttributeType': 'S'
					},
					{
						'AttributeName': table_range,
						'AttributeType': 'S'
					}
				],
				BillingMode='PAY_PER_REQUEST'
			)
			waiter = dynamodb.get_waiter('table_exists')
			waiter.wait(TableName=next_table_name) # wait for table TO exist
			print(f'>>> Table created.')
			break
		except Exception as e:
			retry_count = retry(e, f'>>> Create DynamoDB table {next_table_name}', retry_count, retry_limit)

	#########################################################
	# Update active table
	#########################################################
	retry_count = 0
	while True:
		try:
			session = boto3.Session(region_name='us-east-1')
			resource = session.resource('dynamodb')
			table = resource.Table(f'{project_name}-report-active-tables')
			print('>>> Created DynamoDB table object.')
			break
		except Exception as e:
			retry_count = retry(e, f'Create DynamoDB table object.',
								retry_count, retry_limit)

	retry_count = 0
	while True:
		# Check to see if 'active' or 'next' table have been set already.
		try:
			get_response = table.get_item(Key={'report_type': report_type})
			break
		except Exception as e:
			retry_count = retry(e, f'Get {report_type} values from DynamoDB!',
								retry_count, retry_limit)

	if get_response.get('Item', {}).get('active_table', ''):

		# If there is an active_table, store next table name in 'next_table'.
		retry_count = 0
		while True:
			try:
				update_response = table.update_item(
					Key={
						'report_type': report_type,
					},
					UpdateExpression='SET #attribute1 = :value1',
					ExpressionAttributeNames={
						'#attribute1': 'next_table'
					},
					ExpressionAttributeValues={
						':value1': next_table_name
					}
				)
				break 
			except Exception as e:
				retry_count = retry(e, f'Set next table as {next_table_name} in DynamoDB!',
									retry_count, retry_limit)

	else:
		# If there is NOT an active_table, store next table name in 'active_table' and 'next_table'.
		retry_count = 0
		while True:
			try:
				entry = {}
				entry['report_type']  = report_type
				entry['active_table'] = next_table_name
				entry['next_table']  = next_table_name
				table.put_item(Item=entry)
				break 
			except Exception as e:
				retry_count = retry(e, f'Set active_table and next_table as {next_table_name} in DynamoDB!',
									retry_count, retry_limit)


def swap_report_table(project_name, report_type):
	dynamodb = boto3.client('dynamodb', region_name='us-east-1')
	retry_limit = 3

	#########################################################
	# Update active table
	#########################################################
	retry_count = 0
	while True:
		try:
			session = boto3.Session(region_name='us-east-1')
			resource = session.resource('dynamodb')
			table = resource.Table(f'{project_name}-report-active-tables')
			print('>>> Created DynamoDB table object.')
			break
		except Exception as e:
			retry_count = retry(e, f'Create DynamoDB table object.',
								retry_count, retry_limit)

	# Set 'active_table' to the value of 'next_table' which was just freshly populated.
	# Set 'next_table' to empty string.
	retry_count = 0
	while True:
		try:
			old_active_table = table.get_item(Key={'report_type': report_type}).get('Item', {}).get('active_table', '')
			new_active_table = table.get_item(Key={'report_type': report_type}).get('Item', {}).get('next_table', '')

			update_response = table.update_item(
				Key={
					'report_type': report_type,
				},
				UpdateExpression='SET #attribute1 = :value1, #attribute2 = :value2',
				ExpressionAttributeNames={
					'#attribute1': 'active_table',
					'#attribute2': 'next_table'
				},
				ExpressionAttributeValues={
					':value1': new_active_table,
					':value2': ''
				}
			)
			break
		except Exception as e:
			retry_count = retry(e, f'Set active table as {new_active_table} in DynamoDB!',
								retry_count, retry_limit)

	#########################################################
	# Delete old table if not only table existing
	#########################################################
	if not old_active_table == new_active_table:
		retry_count = 0
		while True:
			try:
				print(f'Deleting old table {old_active_table}...')
				response = dynamodb.delete_table(TableName=old_active_table)
				waiter = dynamodb.get_waiter('table_not_exists')
				waiter.wait(TableName=old_active_table) # wait for table to NOT exist
				print(f'Table deleted.')
				break
			except Exception as e:
				retry_count = retry(e, f'delete table \'{old_active_table}\'.', retry_count, retry_limit)



def get_report_table(report_type):
	# This function is used to retrieve the 'next_table' which will be used to
	# populate the latest version of the report.
	retry_limit = 3
	retry_count = 0
	while True:
		try:
			session = boto3.Session(region_name='us-east-1')
			resource = session.resource('dynamodb')
			table = resource.Table(f'{project_name}-report-active-tables')
			print('>>> Created DynamoDB table object.')
			break
		except Exception as e:
			retry_count = retry(e, f'Create DynamoDB table object.',
								retry_count, retry_limit)

	retry_count = 0
	while True:
		try:
			next_table = table.get_item(Key={'report_type': report_type}).get('Item', {}).get('next_table', 'TableNameNotFound')
			break
		except Exception as e:
			retry_count = retry(e, f'Retrieved next_table value of: {next_table}',
								retry_count, retry_limit)

	return next_table



################################################################################################
# Make account name consistent
################################################################################################
def clean_account_name(account_name):
	chars_to_replace = "'\"()!@#$%^&*_+:;<>/?\\`~=,"
	for char in chars_to_replace:
		account_name = account_name.replace(char, "")
	return account_name.replace(" ", "-").lower()

################################################################################################
# Retry with exponential backoff
################################################################################################
def retry(e, message, retry_count, retry_limit):
	print(e)
	if retry_count > retry_limit:
		print(f'Reached limit of {retry_limit} retries: {message}. Exiting...')
		exit(1)
	else:
		print(f'Retrying in {2*retry_count} seconds: {message}')
		sleep(2*retry_count) # exponential backoff for rate limiting
	retry_count = retry_count + 1
	return retry_count