import json
import logging
import boto3
import os
import urllib3
import re
import datetime

from time import sleep
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)



################################################################################################
# Vars
################################################################################################
project_name	 	   	= os.environ['project_name']
region			 	   	= os.environ['region']
ses_region		 	   	= os.environ['ses_region']
table_name 		 	   	= os.environ['dynamodb_table']
dashboard_domain       	= os.environ['dashboard_domain']
email_summary_frequency = os.environ['email_summary_frequency']
alert_sender     	   	= os.environ['alert_sender']
alert_recipients 	   	= json.loads(os.environ['alert_recipients'])
ignored_iam_principals 	= json.loads(os.environ['ignored_iam_principals'])

################################################################################################
# Send Email
################################################################################################

def send_email(events_by_account, start_time, end_time, events_scanned_count, omit_count):
	ses = boto3.client('ses', region_name=ses_region)

	################################################################################################
	# CSS Style and HTML
	################################################################################################
	style = """<style>
	table {
		 display:table;
		 margin-right:auto;
		 margin-left:auto;
		 width:90%;
	 }

	pre {
		white-space: pre-wrap;       /* css-3 */
		white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
		white-space: -pre-wrap;      /* Opera 4-6 */
		white-space: -o-pre-wrap;    /* Opera 7 */
		word-wrap: break-word;       /* Internet Explorer 5.5+ */
		font-family: "courier new", courier, monospace;
		font-size: 12px;
	}

	#accounttable {
	  font-family: Arial, Helvetica, sans-serif;
	  border-collapse: collapse;
	}

	#accounttable th {
	  border: 1px solid #c4c4c4;
	  padding: 5px;
	  background-color: #f2f2f2;
	  color: black;
	}
	  
	#accounttable td {
	  padding: 5px;
	  font-size: 13px;
	  display:table-cell;
	  text-align:left;
	}

	#accountheader th {
	  padding-top: 12px;
	  padding-bottom: 12px;
	  padding-left: 12px;
	  text-align: center;
	  background-color: #242e9c !important;
	  color: white !important;
	  font-size: 20px;
	}

	</style>"""

	num_events = 0
	for account_key in events_by_account.keys():
		events = events_by_account[account_key]['events']
		for event in events:
			num_events += event['count']
	num_accounts = len(events_by_account.keys())

	html = '''
	<p>
	  <div style="font-family: Arial, Helvetica, sans-serif; font-weight: bold; font-size: 30px; text-align: center;">Event Summary</div>
	  <div style="font-family: Arial, Helvetica, sans-serif; font-weight: bold; font-size: 12px; text-align: center;">(''' + str(num_events) + ''' found, ''' + str(omit_count) + ''' omitted, ''' + str(num_accounts) + ''' accounts, ''' + str(events_scanned_count) + ''' queried)</div>
	  <div style="font-family: Arial, Helvetica, sans-serif; font-weight: bold; font-size: 12px; text-align: center;"><a href="https://''' + dashboard_domain + '''/events/?start='''+start_time+'''&end='''+end_time+'''">view event details</a></div>
	</p>
	<table id="accounttable">'''
	html_table_body_end = """</tbody>\n"""
	for account_key in events_by_account.keys():
		account_id = events_by_account[account_key]['account_id']
		account_alias = events_by_account[account_key]['account_alias']
		events = sorted(events_by_account[account_key]['events'], key = lambda i: (i['user'], i['event_name']))

		html_table_body_start = """
		<thead id="accountheader"><tr><th colspan="6" align="center">""" + account_alias + """ (""" + account_id + """)</th></thead>
		<thead id="columnheaders"><tr align="left"><th>User</th><th>IP</th><th>Country</th><th>Service</th><th>EventName</th><th>Count</th></tr></thead>
		<tbody>"""

		# Toggle color of each row back and forth
		rows = ""
		count = 0
		for event in events:
			count = (count + 1) % 2
			if count == 1:
				row_color = f'#d1d1d1'
			else:
				row_color = f'#fff'
			rows += f"<tr style=\"color: black; background-color: {row_color};\"><td>{event['user']}</td><td>{event['source_ip'].replace('.amazonaws.com', '')}</td><td>{event['geo_country']}</td><td>{event['source'].replace('aws.', '')}</td><td>{event['event_name']}</td><td>{event['count']}</td></tr>\n"
			
		html += html_table_body_start + rows + html_table_body_end

	html += '</table>'

	################################################################################################
	# Build/Send email with SES
	################################################################################################
	CHARSET = "UTF-8"
	#CONFIGURATION_SET = "ConfigSet"
	SENDER = f"\"{project_name}\" <{alert_sender}>"
	RECIPIENTS = alert_recipients
	SUBJECT = f'{str(num_events)} new events'
	BODY_HTML = style + html

	BODY_TEXT = (f"{project_name} alert\r\n"
			 "Text based clients not supported."
			)

	try:
		#Provide the contents of the email.
		response = ses.send_email(
		Destination={
		'ToAddresses': RECIPIENTS,
		},
		Message={
		   "Body":{
			  "Html":{
				 "Charset":CHARSET,
				 "Data":BODY_HTML
			  },
			  "Text":{
				 "Charset":CHARSET,
				 "Data":BODY_TEXT
			  }
		   },
		   "Subject":{
			  "Charset":CHARSET,
			  "Data":SUBJECT
		   }
		},
		Source=SENDER,
		# If you are not using a configuration set, comment or delete the
		# following line
		#ConfigurationSetName=CONFIGURATION_SET,
		)
	# Display an error if something goes wrong.	
	except ClientError as e:
		print(e.response['Error']['Message'])
	else:
		print("Email sent! Message ID:")
		print(response['MessageId'])

################################################################################################
# Get events for the last hour block of time.
################################################################################################
def get_events_from_dynamodb():
	# Get current time.
	now = datetime.datetime.utcnow()

	# Go back N minutes plus 10 seconds more to create overlap to cover for
	# variations in how long the script might run. That way we will not miss
	# any events.
	minutes_ago = now - datetime.timedelta(minutes=int(email_summary_frequency),seconds=10)

	# Turn timestamps into strings
	start_time = minutes_ago.strftime('%FT%TZ')
	end_time   = now.strftime('%FT%TZ')

	# Date range object for dynamodb
	date_range = Key('event_time').between(start_time,end_time)

	parsed_events = []
	events_by_account = {}
	omit_count = 0
	omit_email = False
	try:
		resource = boto3.resource('dynamodb')
		table = resource.Table(table_name)

		scan_kwargs = {
			'FilterExpression': date_range
		}


		# Loop through all of the items in the table
		start_key = None
		events_scanned_count = 0
		events_count = 0
		while True:
			if start_key:
				scan_kwargs['ExclusiveStartKey'] = start_key
			response = table.scan(**scan_kwargs)
			if response.get('Items', {}):
				events_scanned_count += response['ScannedCount']
				for event in response['Items']:
					events_count += 1
					parsed_events.append(event)
			start_key = response.get('LastEvaluatedKey', None)
			if not start_key:
				break

		print(f'Scanned: {events_scanned_count}, Found: {events_count}')

		if parsed_events:
			all_events = []
			# Get list of all events in the correct format
			for parsed_event in parsed_events:
				omit = False

				# Get a clean version of the variable to use for checking
				event = json.loads(parsed_event['raw_event'])
				event_type = event['detail']['userIdentity']['type']
				if event_type == 'IAMUser':
					user_check = parsed_event['user']
				elif event_type == 'AssumedRole':
					user_arn = event['detail']['userIdentity']['arn']
					user_check = event['detail'].get('userIdentity', {}).get('sessionContext', {}).get('sessionIssuer', {}).get('userName', 'None')
				else:
					user_check = ""

				# If this is one of the ignored principals for summary
				# emails, do not include it in the email, +1 to omit count.
				for ignored_iam_principal in ignored_iam_principals:
					if ignored_iam_principal == user_check:
						omit_count += 1
						omit = True

				if not omit:
					this_event = {'account_id': parsed_event['account_id'], 
								  'account_alias': parsed_event['account_alias'], 
								  'user': parsed_event['user'],
								  'source_ip': parsed_event['source_ip'],
								  'geo_country': parsed_event['geo_country'], 
								  'source': parsed_event['source'], 
								  'event_name': parsed_event['event_name']}
					all_events.append(this_event)

			# Get list of unique events
			unique_events = []
			for this_event in all_events:
				if this_event not in unique_events:
					unique_events.append(this_event)

			# Check if the only unique events were 'ConsoleLogin'
			# If so, opt out of sending the email.
			all_event_names = []
			for this_event in unique_events:
				event_name = this_event['event_name']
				if event_name not in all_event_names:
					all_event_names.append(event_name)
			if len(all_event_names) == 1:
				if 'ConsoleLogin' in all_event_names:
					omit_email = True

			# Count the number of unique events and add that to the unique event dict
			unique_events_with_count = []
			for unique_event in unique_events:
				count = 0
				for this_event in all_events:
					if unique_event == this_event:
						count += 1
				unique_event['count'] = count
				unique_events_with_count.append(unique_event)

			# Store unique events in dict by account_id.
			for unique_event in unique_events_with_count:
				account_id = unique_event['account_id']
				account_alias = unique_event['account_alias']
				if not events_by_account.get(account_id, {}):
					events_by_account[account_id] = {}
					events_by_account[account_id]['events'] = []

				events_by_account[account_id]['account_id'] = account_id
				events_by_account[account_id]['account_alias'] = account_alias
				events_by_account[account_id]['events'].append(unique_event)

	except Exception as e:
		print('Could not get events. Exiting...')
		print(e)
		exit(1)

	return events_by_account, start_time, end_time, omit_email, events_scanned_count, omit_count


def lambda_handler(event, context):

	events_by_account, start_time, end_time, omit_email, events_scanned_count, omit_count = get_events_from_dynamodb()
	if events_by_account and not omit_email:
		send_email(events_by_account, start_time, end_time, events_scanned_count, omit_count)
	else:
		print(f'There were no events between {start_time} and {end_time}')

	return {
		'statusCode': 200,
		'body': json.dumps(f'{project_name} summary email logic successful.')
	}
