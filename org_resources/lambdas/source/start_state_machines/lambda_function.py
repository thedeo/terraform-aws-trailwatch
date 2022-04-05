import json
import logging
import boto3
import os
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Vars
################################################################################################
project_name	  = os.environ['project_name']
region			  = os.environ['region']

def lambda_handler(event, context):
	report_type		  = event['report_type']
	state_machine_arn = event['state_machine_arn']

	try:
		sfn = boto3.client('stepfunctions')
		response = sfn.start_execution(
		    stateMachineArn=state_machine_arn,
		    name=f'initial-run-{str(uuid.uuid4())}',
		    input="{}"
		)
		print(f'State machine for {report_type} report started.')
	except Exception as e:
		print(e)
		print(f'Event: {event}')
		exit(1)

	return {
		'statusCode': 200,
		'body': json.dumps(f'State machine for {report_type} report started.')
	}

