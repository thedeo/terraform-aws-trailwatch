import boto3

from time import sleep

from dashboard.vars import *

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

def get_report_table(report_type):
	# This function is used to retrieve the 'active_table' name
	retry_limit = 3
	retry_count = 0
	while True:
		try:
			session = boto3.Session(region_name=region)
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
			report_table = table.get_item(Key={'report_type': report_type}).get('Item', {}).get('active_table', 'TableNameNotFound')
			break
		except Exception as e:
			retry_count = retry(e, f'Retrieve active_table value',
								retry_count, retry_limit)

	return report_table

def get_step_function_status(report_type):
	# Get information about the last successful SFN execution.
	sfn = boto3.client('stepfunctions', region_name=region)
	state_machine_arn  = f'arn:aws:states:{region}:{account_id}:stateMachine:{project_name}-report-{report_type}'
	state_machine_name = f'{project_name}-report-{report_type}'

	retry_limit = 3
	retry_count = 0
	while True:
		try:
			response = sfn.list_executions(
			    stateMachineArn=state_machine_arn,
			    statusFilter='SUCCEEDED'
			)
			last_execution = response['executions'][0]
			print(f'>>> Retrieved execution details for {state_machine_name}.')
			break
		except Exception as e:
			print(f'Could not get last_execution for {state_machine_name}.')
			last_execution = 'None'
			break

	return last_execution