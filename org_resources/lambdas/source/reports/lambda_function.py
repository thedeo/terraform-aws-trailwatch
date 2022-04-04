import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

	report_type = event.get('report_type', '')

	# Default exit.
	if not report_type:
		print('No report_type type specified. Exiting.')


	# Account
	elif report_type == 'account':
		print(f'Starting {report_type} logic ...')
		import account
		account.start(event)

	# User
	elif report_type == 'user':
		print(f'Starting {report_type} logic ...')
		import user
		return user.start(event)

	# AMI
	elif report_type == 'ami':
		print(f'Starting {report_type} logic ...')
		import ami
		return ami.start(event)

	# Security Group
	elif report_type == 'securitygroup':
		print(f'Starting {report_type} logic ...')
		import securitygroup
		return securitygroup.start(event)