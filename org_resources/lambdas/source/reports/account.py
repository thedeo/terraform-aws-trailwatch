import boto3
import json
import logging
import datetime

from calendar import monthrange

from common import create_client
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

# Clients
dynamodb = boto3.client('dynamodb', region_name='us-east-1')

################################################################################################
# Get Service Usage from Cost Explorer
################################################################################################
def get_service_usage(account_id, account_alias):

	# Verify that role exists in member account before attempting to pull data.
	# if we can't access this account we will mark the service usage field as 'AccessDenied'
	# which will cause no further logic to run for this account.
	# This will ensure that the state machine doesn't fail if a newly added account
	# doesn't yet have the proper IAM roles to allow for analysis.
	access_verified = verify_member_role_access(account_id, 'us-east-1', 'ce')
	if not access_verified:
		print(f'Could not get service usage for {account_id}({account_alias})')
		return 'AccessDenied', {}, {}, '-'

	ce = create_client(account_id, 'us-east-1', 'ce')


	# Generate date ranges for current and previous month.
	date_ranges = {}

	# Current Month Date Range
	first_of_month = datetime.date.today().replace(day=1)
	today          = datetime.date.today()

	# If you pass a start and end date of the same date the
	# API call will fail. So with this we ensure that on the
	# first of the month doesn't cause an error.
	if first_of_month == today:
		today = today.replace(day=2)

	month_name 	   = today.strftime("%b")
	start          = first_of_month.strftime("%Y-%m-%d")
	end            = today.strftime("%Y-%m-%d")

	date_ranges['current_month'] = {'month_name': month_name, 'start': start, 'end': end}

	# Previous Month Date Range
	month = int(first_of_month.strftime("%m"))
	year  = int(first_of_month.strftime("%Y"))
	if month == 1:
		previous_month = 12
		year -= 1
	else:
		previous_month = month - 1
		
	last_month   		  = first_of_month.replace(year=year,month=previous_month,day=1)
	end_of_previous_month = last_month.replace(day = monthrange(last_month.year, last_month.month)[1])

	month_name = last_month.strftime("%b")
	start 	   = last_month.strftime("%Y-%m-%d")
	end   	   = end_of_previous_month.strftime("%Y-%m-%d")

	date_ranges['previous_month'] = {'month_name': month_name, 'start': start, 'end': end}

	# Retrieve data and place into dict.
	cost_data = {}
	for date_range in date_ranges.keys():
		month_name = date_ranges[date_range]['month_name']
		start 	   = date_ranges[date_range]['start']
		end   	   = date_ranges[date_range]['end']

		cost_and_usage = []
		# Get list of all items in paginated list
		next_token = False
		while True:
			if not next_token:
				try:
					response = ce.get_cost_and_usage(
						TimePeriod={
							'Start': start,
							'End':   end
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
					print(f'Start: {start}')
					print(f'End: {end}')
					exit(1)

			elif next_token:
				try:
					response = ce.get_cost_and_usage(
						TimePeriod={
							'Start': start,
							'End':   end
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
					print(f'Start: {start}')
					print(f'End: {end}')
					exit(1)

		ignored_services = ['Tax',
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

		service_short_name_mapping = {
		'AWS Support (Business)': 'support-bus',
		'AWS Support (Developer)': 'support-dev',
		'AWS Support (Enterprise)': 'support-ent',
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
		'AWS Step Functions': 'stepfunctions',
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

		# Add to list unless ignored or over 0.01 of currency.
		service_list = []
		cost_by_service = {}
		currency_unit_by_service = {}
		total_account_cost = {}
		for service in cost_and_usage:
			service_name  = service['Keys'][0]
			short_name    = service_short_name_mapping.get(service_name, service_name)
			currency_unit = service['Metrics']['BlendedCost']['Unit']
			service_cost  = float(service['Metrics']['BlendedCost']['Amount'])
			total_account_cost.setdefault(currency_unit, 0.00)
			total_account_cost[currency_unit] += service_cost
			if service_cost > 0.01 and service_name not in ignored_services:
				service_list.append(service_name)

				# Either create new entry or add value to existing.
				if not cost_by_service.get(short_name, ''):
					cost_by_service[short_name] = service_cost
				else:
					cost_by_service[short_name] = cost_by_service[short_name] + service_cost

				# Create entry if it doesn't exist
				if not currency_unit_by_service.get(short_name, ''):
					currency_unit_by_service[short_name] = currency_unit

		# Create a string of all currency totals
		total_account_cost_list   = []
		total_account_cost_string = ''
		for k, v in total_account_cost.items():
			total_account_cost_list.append(f'{v:,.2f} {k}')
		total_account_cost_string = ", ".join(total_account_cost_list)

		# Use mapping to short names
		service_short_name_list = []
		for service_name in service_list:
			short_name = service_short_name_mapping.get(service_name, service_name)
			service_short_name_list.append(short_name)

		# Remove repeats and sort
		service_short_name_set  = set(service_short_name_list)
		service_short_name_list = list(service_short_name_set)
		service_short_name_list.sort()

		# Turn into string
		services_used = ", ".join(service_short_name_list)

		# Create string for date range
		start_day = int(start[8:])
		end_day   = int(end[8:])

		def get_suffix(day):
			if 4 <= day <= 20 or 24 <= day <= 30:
			    suffix = "th"
			else:
			    suffix = ["st", "nd", "rd"][day % 10 - 1]
			return suffix

		date_range_string = f'{month_name} {start_day}{get_suffix(start_day)} - {end_day}{get_suffix(end_day)}'


		cost_data[date_range] = {
			'date_range': date_range_string,
			'services_used': services_used, 
			'cost_by_service': cost_by_service, 
			'currency_unit_by_service': currency_unit_by_service, 
			'total_account_cost_string': total_account_cost_string
		}

	return cost_data


################################################################################################
# Process Data
################################################################################################
def analyze_data(account_id, account_alias, event, cost_data):

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

	# Current Month Cost Data
	item.setdefault('current_month_date_range', {})['S'] 		        = cost_data['current_month']['date_range']
	item.setdefault('current_month_services_used', {})['S'] 		    = cost_data['current_month']['services_used'] if cost_data['current_month']['services_used'] else '-'
	item.setdefault('current_month_cost_by_service', {})['S'] 			= json.dumps(cost_data['current_month']['cost_by_service'])
	item.setdefault('current_month_currency_unit_by_service', {})['S']  = json.dumps(cost_data['current_month']['currency_unit_by_service'])
	item.setdefault('current_month_total_account_cost', {})['S'] 		= cost_data['current_month']['total_account_cost_string']

	# Previous Month Cost Data
	item.setdefault('previous_month_date_range', {})['S'] 		        = cost_data['previous_month']['date_range']
	item.setdefault('previous_month_services_used', {})['S'] 			= cost_data['previous_month']['services_used'] if cost_data['previous_month']['services_used'] else '-'
	item.setdefault('previous_month_cost_by_service', {})['S'] 			= json.dumps(cost_data['previous_month']['cost_by_service'])
	item.setdefault('previous_month_currency_unit_by_service', {})['S'] = json.dumps(cost_data['previous_month']['currency_unit_by_service'])
	item.setdefault('previous_month_total_account_cost', {})['S'] 		= cost_data['previous_month']['total_account_cost_string']
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


################################################################################################
# Start the Script
################################################################################################
def start(event):
	report_type = event.get('report_type', '')
	mode		= event.get('mode', '')

	if not report_type == 'account':
		print('Event  does not match report type "account".')
		print(event)
		exit(1)

	if mode == 'bootstrap':
		create_report_table(project_name, report_type, 'account_id', 'account_alias')

	if mode == 'a':
		account_id 	  = event['payload']['Id']
		account_name  = event['payload']['Name']
		account_alias = clean_account_name(account_name)
		cost_data = get_service_usage(account_id, account_alias)

		print(f'Analizing data for {account_id}({account_alias})...')
		processed_data_list = analyze_data(account_id, account_alias, event, cost_data)

		print(f'Sending data for {account_alias}({account_id}) to DynamoDB...')
		report_table = get_report_table(report_type)
		send_to_dynamodb(account_id, account_alias, processed_data_list, report_table)

	if mode == 'cleanup':
		# We will update the active table to the one we just created in mode a.
		swap_report_table(project_name, report_type)