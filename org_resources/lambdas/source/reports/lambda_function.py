import os
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

	report = event.get('report', '')

	# Default exit.
	if not report:
		print('No report type specified. Exiting.')


	# Account
	elif report == 'account':
		print(f'Starting {report} logic ...')
		import account
		account.start(event)

	# User
	elif report == 'user':
		print(f'Starting {report} logic ...')
		import user
		user.start(event)

	# AMI
	elif report == 'ami':
		print(f'Starting {report} logic ...')
		import ami
		ami.start(event)

	# Security Group
	elif report == 'securitygroup':
		print(f'Starting {report} logic ...')
		import securitygroup
		securitygroup.start(event)


	return {
		'statusCode': 200,
		'body': json.dumps(f'Finished Primary Logic.')
	}