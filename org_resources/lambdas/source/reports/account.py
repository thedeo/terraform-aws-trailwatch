import boto3
import os
import re
import json
import logging
import datetime

from time import sleep
from botocore.exceptions import ClientError

from common import create_client
from common import get_available_regions
from common import retry
from common import clean_account_name

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Variables
################################################################################################
from common import project_name
from common import org_account_id

# Clients
dynamodb = boto3.client('dynamodb', region_name='us-east-1')

################################################################################################
# Get Service Usage from Cost Explorer
################################################################################################
def get_service_usage(account_id, account_alias):

	ce = create_client(account_id, 'us-east-1', 'ce')

	# Determine dates for this month and one month ago.
	first_of_month = datetime.date.today().replace(day=1)
	month = int(first_of_month.strftime("%m"))
	year = int(first_of_month.strftime("%Y"))
	if month == 1:
		previous_month = 12
		year -= 1
	else:
		previous_month = month - 1
	one_month_ago = first_of_month.replace(year=year,month=previous_month,day=1)

	start = one_month_ago.strftime("%Y-%m-%d")
	end = first_of_month.strftime("%Y-%m-%d")

	cost_and_usage = []
	# Get list of all items in paginated list
	next_token = False
	while True:
		if not next_token:
			try:
				response = ce.get_cost_and_usage(
					TimePeriod={
						'Start': start,
						'End': end
					},
					Granularity='MONTHLY',
					Metrics=[
						'BlendedCost',
					],
					GroupBy=[
						{
							'Type': 'DIMENSION',
							'Key': 'SERVICE'
						},
					]
				)
				cost_and_usage = cost_and_usage + response['ResultsByTime'][0]['Groups']
				if response.get('NextPageToken', ''):
					next_token = True
					token = response['NextPageToken']
				else:
					break # no more items left to list
			except Exception as e:
				print(e)
				exit(1)

		elif next_token:
			try:
				response = ce.get_cost_and_usage(
				    TimePeriod={
				        'Start': start,
				        'End': end
				    },
				    Granularity='MONTHLY',
				    Metrics=[
				        'BlendedCost',
				    ],
				    GroupBy=[
				        {
				            'Type': 'DIMENSION',
				            'Key': 'SERVICE'
				        },
				    ],
				    NextPageToken=token
				)
				cost_and_usage = cost_and_usage + response['ResultsByTime'][0]['Groups']
				if response.get('NextPageToken', ''):
					next_token = True
					token = response['NextPageToken']
				else:
					break # no more items left to list
			except Exception as e:
				print(e)
				exit(1)

	ignored_services = ['AWS CloudTrail', 
						'AWS Config', 
						'AWS Systems Manager',
						'Amazon GuardDuty',
						'AmazonCloudWatch',
						'CloudWatch Events',
						'Tax',
						'AWS Support (Business)',
						'AWS Support (Developer)',
						'VM-Series Next-Generation Firewall Bundle 1 [VM-300]',
						'Trend Micro Cloud One',
						'The Things Stack AWS Launcher for LoRaWAN',
						'Savings Plans for AWS Compute usage',
						'OpenVPN Access Server (10 Connected Devices)',
						'JPEGmini Photo Server',
						'Fortinet Managed Rules for AWS WAF - Complete OWASP Top 10',
						'Contact Center Telecommunications (service sold by AMCS, LLC) ',
						'OpenVPN Access Server (100 Connected Devices)',
						'bucketAV - Antivirus for Amazon S3 - previously VirusScan for Amazon S3' ]

	# Add to list unless ignored or if usage is too low.
	service_list = []
	for service in cost_and_usage:
		service_name = service['Keys'][0]
		service_cost = int(float(service['Metrics']['BlendedCost']['Amount']))
		if service_cost > 1 and service_name not in ignored_services:
			service_list.append(service_name)

	service_short_name_mapping = {
	'Amazon Registrar': 'registrar',
	'AWS CloudHSM': 'cloudhsm',
	'AWS CloudTrail': 'cloudtrail',
	'AWS Config': 'config',
	'AWS Systems Manager': 'ssm',
	'Amazon GuardDuty': 'guardduty',
	'AmazonCloudWatch': 'cw',
	'CloudWatch Events': 'cw events',
	'AWS Backup': 'backup',
	'AWS Cloud Map': 'cloudmap',
	'AWS CloudShell': 'cloudshell',
	'AWS CodeArtifact': 'codeartifact',
	'AWS CodeCommit': 'codecommit',
	'AWS CodePipeline': 'codepipeline',
	'AWS Cost Explorer': 'costexplorer',
	'AWS Data Pipeline': 'datapipeline',
	'AWS DataSync': 'datasync',
	'AWS Database Migration Service': 'dms',
	'AWS Direct Connect': 'directconnect',
	'AWS Directory Service': 'directory',
	'AWS Elemental MediaStore': 'elemental',
	'AWS Global Accelerator': 'accelerator',
	'AWS Glue': 'glue',
	'AWS IoT': 'iot',
	'AWS Key Management Service': 'kms',
	'AWS Lambda': 'lambda',
	'AWS Secrets Manager': 'secrets',
	'AWS Security Hub': 'sechub',
	'AWS Step Functions': 'stepfunc',
	'AWS WAF': 'waf',
	'AWS X-Ray': 'xray',
	'Amazon API Gateway': 'apigateway',
	'Amazon Athena': 'athena',
	'Amazon CloudFront': 'cloudfront',
	'Amazon Cognito': 'cognito',
	'Amazon Connect': 'connect',
	'Amazon Detective': 'detective',
	'Amazon DynamoDB': 'dynamodb',
	'Amazon EC2 Container Registry (ECR)': 'ecr',
	'Amazon ElastiCache': 'ecache',
	'EC2 - Other': 'ec2',
	'Amazon Elastic Compute Cloud - Compute': 'ec2',
	'Amazon Elastic Container Service': 'ecs',
	'Amazon Elastic Container Service for Kubernetes': 'eks',
	'Amazon Elastic File System': 'efs',
	'Amazon Elastic Load Balancing': 'elb',
	'Amazon Elasticsearch Service': 'elasticsearch',
	'Amazon FSx': 'fsx',
	'Amazon Glacier': 'glacier',
	'Amazon Inspector': 'inspector',
	'Amazon Kinesis': 'kinesis',
	'Amazon Kinesis Firehose': 'firehose',
	'Amazon Polly': 'polly',
	'Amazon Quantum Ledger Database': 'qldb',
	'Amazon QuickSight': 'quicksight',
	'Amazon Redshift': 'redshift',
	'Amazon Relational Database Service': 'rds',
	'Amazon Route 53': 'r53',
	'Amazon SageMaker': 'sagemaker',
	'Amazon Simple Email Service': 'ses',
	'Amazon Simple Notification Service': 'sns',
	'Amazon Simple Queue Service': 'sqs',
	'Amazon Simple Storage Service': 's3',
	'Amazon SimpleDB': 'simpledb',
	'Amazon Textract': 'textract',
	'Amazon Virtual Private Cloud': 'vpc',
	'Amazon WorkDocs': 'workdocs',
	'Amazon WorkSpaces': 'workspaces',
	'CodeBuild': 'codebuild'
	}

	# Use mapping to short names
	service_short_name_list = []
	for service in service_list:
		short_name = service_short_name_mapping.get(service, service)
		service_short_name_list.append(short_name)

	# Remove repeats and sort
	service_short_name_set = set(service_short_name_list)
	service_short_name_list = list(service_short_name_set)
	service_short_name_list.sort()

	# Turn into string
	services_used = ", ".join(service_short_name_list)

	return services_used


################################################################################################
# Process Data
################################################################################################
def analyze_data(account_id, account_alias, event, services_used):

	processed_data_list = []
	########################
	# Package Processed Data
	########################
	item = {}
	item.setdefault('account_id', {})['S'] = account_id
	item.setdefault('account_alias', {})['S'] = account_alias
	item.setdefault('billing_name', {})['S'] = event['payload']['Name']
	item.setdefault('email', {})['S'] = event['payload']['Email']
	item.setdefault('joined_method', {})['S'] = event['payload']['JoinedMethod']
	item.setdefault('joined_date', {})['S'] = event['payload']['JoinedTimestamp']
	item.setdefault('services_used', {})['S'] = services_used if services_used else '-' # if services_used is empty set to '-'
	processed_data_list.append({"PutRequest": {"Item": item}})

	return processed_data_list


################################################################################################
# DynamoDB Logic
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
					dynamodb.batch_write_item(RequestItems={report_table: request_items_batch})
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
					dynamodb.batch_write_item(RequestItems={report_table: request_items_batch})
					print(f'Put {count} items into dynamodb successfully!')
					break
				except Exception as e:
					retry_count = retry(e, f'Put items batch for {account_alias}({account_id}): {request_items_batch}', 
										retry_count, retry_limit)


# ################################################################################################
# # DynamoDB
# ################################################################################################
# def send_status_to_dynamodb(account_id, status, name_prefix):
# 	invocation_name = f'{name_prefix}_{account_id}'
# 	retry_limit = 15
# 	retry_count = 0

# 	while True:
# 		try:
# 			session = boto3.Session(region_name='us-east-1')
# 			resource = session.resource('dynamodb')
# 			table = resource.Table(report_status_table)
# 			print('>>> Created DynamoDB table object.')
# 			break
# 		except Exception as e:
# 			retry_count = retry(e, f'Create DynamoDB table object.',
# 								retry_count, retry_limit)

# 	while True:
# 		# Only check for 'RUNNING' status if trying to set the status to 'DONE'
# 		try:
# 			if status == 'DONE': # target status
# 				get_response = table.get_item(Key={'invocation_name': invocation_name})
# 				if get_response.get('Item', {}).get('status', '') != 'RUNNING':
# 					print(f'>>> Waiting for {invocation_name} to be in \'RUNNING\' status.')
# 					sleep(5)
# 					retry_count += 1
# 					if retry_count > retry_limit:
# 						print(f'Retry limit of {retry_limit} reached. Exiting.')
# 						exit(1)
# 				else:
# 					print('>>> \'RUNNING\' status found.')
# 					break
# 			else:
# 				break
# 		except Exception as e:
# 			retry_count = retry(e, f'Create DynamoDB table object.',
# 								retry_count, retry_limit)

# 	while True:
# 		try:
# 			# Update status
# 			update_response = table.update_item(
# 				Key={
# 					'invocation_name': invocation_name,
# 				},
# 				UpdateExpression='SET #attribute1 = :value1',
# 				ExpressionAttributeNames={
# 					'#attribute1': 'status'
# 				},
# 				ExpressionAttributeValues={
# 					':value1': status
# 				}
# 			)
# 			break 
# 		except Exception as e:
# 			retry_count = retry(e, f'Verify status marked as {status} in DynamoDB!',
# 								retry_count, retry_limit)

# 	while True:
# 		try:
# 			# Verify status else try again
# 			get_response = table.get_item(Key={'invocation_name': invocation_name})
# 			if get_response['Item']['status'] != status:
# 				retry_count = retry('Status not updated', f'Verify {invocation_name} marked as {status} in DynamoDB!',
# 									retry_count, retry_limit)
# 			else:
# 				print(f'>>> Verified {invocation_name} marked as {status} in DynamoDB!')
# 				break 
# 		except Exception as e:
# 			retry_count = retry(e, f'Verify status marked as {status} in DynamoDB!',
# 								retry_count, retry_limit)

# def check_overall_status():
# 	session = boto3.Session(region_name='us-east-1')
# 	resource = session.resource('dynamodb')
# 	table = resource.Table(report_status_table)

# 	scan_kwargs = {}
# 	start_key = None
# 	while True:
# 		if start_key:
# 			scan_kwargs['ExclusiveStartKey'] = start_key
# 		response = table.scan(**scan_kwargs)
# 		if response.get('Items', {}):
# 			for invocation in response['Items']:
# 				if invocation['status'] == 'ERROR':
# 					return 'ERROR'
# 				elif invocation['status'] == 'RUNNING':
# 					return 'RUNNING'
# 		start_key = response.get('LastEvaluatedKey', None)
# 		if not start_key:
# 			break
# 	return 'OK' # all invoations have completed.

# def update_automation_metadata(overall_status):
# 	retry_limit = 3
# 	retry_count = 0
# 	while True:
# 		try:
# 			session = boto3.Session(region_name='us-east-1')
# 			resource = session.resource('dynamodb')
# 			table = resource.Table(metadata_dynamodb_table)
# 			response = table.update_item(
# 				Key={
# 					'report_name': report_name,
# 				},
# 				UpdateExpression='SET #attribute1 = :value1',
# 				ExpressionAttributeNames={
# 					'#attribute1': 'overall_status'
# 				},
# 				ExpressionAttributeValues={
# 					':value1': overall_status
# 				}
# 			)
# 			print(f'>>> Updated overall status in dynamodb to {overall_status}!')
# 			break 
# 		except Exception as e:
# 			retry_count = retry(e, f'Update overall status in dynamodb to {overall_status}!',
# 								retry_count, retry_limit)


################################################################################################
# Start the Script
################################################################################################
def start(event):
	report_type = event.get('report_type', '')

	if not report_type == 'account':
		print('Event  does not match report type "account".')
		print(event)
		exit(1)

	##############
	# GATHER 
	##############
	# Routine account_id/account_alias discovery
	account_id 	  = event['payload']['Id']
	account_name  = event['payload']['Name']
	account_alias = clean_account_name(account_name)
	services_used = get_service_usage(account_id, account_alias)

	###############
	# PROCESS
	###############
	report_table = f'{project_name}-report-{report_type}'

	print(f'Analizing data for {account_id}({account_alias})...')
	processed_data_list = analyze_data(account_id, account_alias, event, services_used)

	print(f'Sending data for {account_alias}({account_id}) to DynamoDB...')
	send_to_dynamodb(account_id, account_alias, processed_data_list, report_table)

	###############
	# NOTIFY
	###############
	# send_status_to_dynamodb(account_id, 'DONE', f'sub')
	# overall_status = check_overall_status()
	# if overall_status in ['OK', 'ERROR']:
	# 	update_automation_metadata(overall_status)
	# else:
	# 	print('>>> Some invocations are still running...')
	print('Done!')