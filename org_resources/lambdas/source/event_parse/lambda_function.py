import json
import logging
import boto3
import os
import urllib3
import re
import datetime

from time import sleep
from random import randint
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Vars
################################################################################################
project_name	 = os.environ['project_name']
region			 = os.environ['region']
ses_region		 = os.environ['ses_region']
table_name 		 = os.environ['dynamodb_table']
alert_sender     = os.environ['alert_sender']
alert_recipients = json.loads(os.environ['alert_recipients'])

################################################################################################
# Get the descriptive alias of an account
################################################################################################
def get_account_alias(account):

	# This makes the names consistent and more friendly to work with
	def clean_account_name(account_name):
		chars_to_replace = "'\"()!@#$%^&*_+:;<>/?\\`~=,"
		for char in chars_to_replace:
			account_name = account_name.replace(char, "")
		return account_name.replace(" ", "-").lower()

	# Try to get it from AWS Organizations
	organizations = boto3.client('organizations', region_name=region)
	retry_limit = 3
	retries = 0
	while True:
		try:
			response = organizations.describe_account(AccountId=account)
			return clean_account_name(response['Account']['Name'])
		except Exception as e:
			print(f'Could not get account_alias for {account} from Organizations.')
			print(e)
			retries += 1
			sleep(1)
			if retries >= retry_limit:
				print(f'Tried {retry_limit} times but failed. Setting to "Unknown".')
				account_alias = 'Unknown'
				break

	return account_alias

def get_ip_location(ip):
	empty = {'status': 'success', 'country': '', 'regionName': '', 'city': '', 'isp': '', 'org': '',
		'asname': '', 'reverse': '', 'mobile': 'Unknown', 'proxy': 'Unknown', 'hosting': 'Unknown'}
	retry_limit = 3
	retries = 0
	while True:
		try:
			http = urllib3.PoolManager()
			response = http.request('GET', f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,asname,reverse,mobile,proxy,hosting')
			geo_dict = json.loads(response.data.decode())
			if geo_dict['status'] == 'success':
				break
			else:
				sleep(2)
				retries += 1
				if retries >= retry_limit:
					print(f'Tried {retry_limit} times but failed to get ip geo location for {ip}')
					print(response.data.decode())
					geo_dict = empty
					break
		except:
			print(f'Failed to get ip geo location for {ip}')
			retries += 1
			sleep(2)
			if retries >= retry_limit:
				geo_dict = empty
				break
	return geo_dict

def send_email(event, parsed_event, subject, header, message):
	ses = boto3.client('ses', region_name=ses_region)

	################################################################################################
	# CSS Style and HTML
	################################################################################################
	style = """<style>
	table {
	     display:table;
	     margin-right:auto;
	     margin-left:auto;
	     width:80%;
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
	  background-color: #ed0202 !important;
	  color: white !important;
	  font-size: 20px;
	}

	</style>"""

	geo_country = parsed_event['geo_country']['S']
	geo_region = parsed_event['geo_regionName']['S']
	geo_city = parsed_event['geo_city']['S']
	geo_isp = parsed_event['geo_isp']['S']

	account_alias = parsed_event['account_alias']['S']
	account_id = parsed_event['account_id']['S']

	html = """<table id="accounttable">
	  <thead id="accountheader"><tr><th colspan="2">""" + header + """</th></thead>
	<tbody>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">Account</td>   <td style="color: black; background-color: #d1d1d1;">"""  + account_alias + """ (""" + account_id + """)</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">User</td>      <td style="color: black; background-color: #fff;">"""	  + parsed_event['user']['S'] 		     + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">EventName</td> <td style="color: black; background-color: #d1d1d1;">"""  + parsed_event['event_name']['S']      + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">awsRegion</td> <td style="color: black; background-color: #fff;">""" 	  + parsed_event['region']['S'] 	     + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">SourceIP</td>  <td style="color: black; background-color: #d1d1d1;">"""  + parsed_event['source_ip']['S'] 	     + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">geoCountry</td><td style="color: black; background-color: #d1d1d1;">"""  + geo_country 						 + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">geoRegion</td> <td style="color: black; background-color: #fff;">""" 	  + geo_region 							 + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">geoCity</td>   <td style="color: black; background-color: #d1d1d1;">"""  + geo_city 							 + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">geoISP</td>    <td style="color: black; background-color: #fff;">""" 	  + geo_isp 							 + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">UserAgent</td> <td style="color: black; background-color: #d1d1d1;">"""  + parsed_event['user_agent']['S']      + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">EventId</td>   <td style="color: black; background-color: #fff;">""" 	  + parsed_event['event_id']['S'] 	     + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border-color: #c4c4c4;  border-style: solid; border-width: 1px 1px 0 1px; width: 100px; font-weight: bold;">Message</td>   <td style="color: black; background-color: #d1d1d1;">"""  + message 						     + """</td></tr>
	<tr><td colspan="2"><br><br></td></tr>
	<tr><td colspan="2" style="background-color: #808080; color: black; border: 1px solid #c4c4c4; font-weight: bold;">Request</td></tr>
	<tr><td colspan="2" style="color: black; background-color: #fff;"><pre style="max-width:600px;">""" 	  + parsed_event['request_params']['S']  + """</pre></td></tr>
	<tr><td colspan="2" style="background-color: #808080; color: black; border: 1px solid #c4c4c4; font-weight: bold;">Full JSON</td></tr>
	<tr><td colspan="2" style="color: black; background-color: #fff;"><pre style="max-width:600px;">""" 	  + parsed_event['raw_event']['S'] 		 + """</pre></td></tr>
	</tbody>
	</table>"""

	################################################################################################
	# Build/Send email with SES
	################################################################################################
	CHARSET = "UTF-8"
	#CONFIGURATION_SET = "ConfigSet"
	SENDER = f"\"{project_name}\" <{alert_sender}>"
	RECIPIENTS = alert_recipients
	SUBJECT = subject
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
	    exit()
	else:
	    print("Email sent! Message ID:")
	    print(response['MessageId'])


def check_urgency(parsed_event, event):

	# Default to False
	urgent = False
	subject = 'None'
	message = 'None'
	header = 'None'

	#####################
	# Root user activity
	#####################
	if parsed_event['event_type']['S'] == 'Root': # and parsed_event['detail_type'] == 'AWS Console Sign In via CloudTrail'

		# Random sleep because for some Root events there are
		# two copies of each event which causes two emails.
		# This random sleep helps each invocation run at separate
		# times so that when they check to see if the event already
		# exists they do not check at the exact same time.
		# ( not ideal but right now this seems to be the only workaround )
		sleep(randint(1,10))
		
		account_id = parsed_event['account_id']['S']
		event_id = parsed_event['event_id']['S']
		event_id_key = {'account_id': {'S': account_id}, 'event_id': {'S': event_id}}

		# Check if this event id already exists in dynamodb
		dynamodb = boto3.client('dynamodb', region_name=region)
		try:
			response = dynamodb.get_item(TableName=table_name, Key=event_id_key)
		except ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			print(error_code)
			print(error_message)
			response = {}

		# Make sure we haven't already alerted on this event
		if response.get('Item', {}).get('event_id', {}).get('S', '') != parsed_event['event_id']['S']:
			urgent = True
			subject = 'Root Account Activity'
			header = 'Root Account Activity'



	#######################
	# Failed Login Attempt
	#######################
	if event['detail'].get('responseElements', {}) != None:

		response_objects = ['ConsoleLogin', 'SwitchRole', 'ExitRole', 'CheckMfa', 'RenewRole']

		# Default to Success
		login_status = 'Success'
		# Check possible response objects for their existence in responseElements.
		# If one of them exists, this means there was some sort of login failure.
		for response_object in response_objects:
			status_check = event['detail'].get('responseElements', {}).get(response_object, '')
			if status_check:
				login_status = status_check
				break

		if login_status != 'Success':
			urgent  = True
			message = event['detail'].get('errorMessage', 'None')

			# If the user account doesn't exist, AWS will omit the username
			# We look for this and adjust the subject line accordingly
			user = parsed_event['user']['S']
			if user == 'HIDDEN_DUE_TO_SECURITY_REASONS':
				subject = 'Failed Console Login: Non-Existent User'
				header  = 'Failed Console Login'
			else:
				subject_user = (user[:55] + '..') if len(user) > 55 else user
				subject = f'Failed Console Login: {subject_user}'
				header  = 'Failed Console Login'

	return urgent, subject, header, message


def send_event_to_dynamodb(parsed_event):

	# Send all non-ignored events to dynamodb.
	ignored_events = ['SwitchRole', 'ExitRole', 'CheckMfa', 'RenewRole']
	event_name = parsed_event.setdefault('event_name', {})['S']

	if event_name not in ignored_events:
		dynamodb = boto3.client('dynamodb', region_name=region)

		# Put event into dynamodb
		try:
			dynamodb.put_item(TableName=table_name, Item=parsed_event)
			print(f'Put event into dynamodb successfully!')
		except Exception as e:
			raw_event = parsed_event['raw_event']['S']
			print(f'Failed to put event: {raw_event}')
			print(e)
			exit(1)

def parse_event(event):

	################################################################################################
	# Convert policy documents from strings to dictionaries
	################################################################################################
	document_types        = ['assumeRolePolicyDocument', 'policyDocument', 'document']
	raw_request_params    = event.get('detail', {}).get('requestParameters', {})
	raw_response_elements = event.get('detail', {}).get('responseElements', {})
	# Request Params
	if raw_request_params != "None" and raw_request_params != None:
		for t in document_types:
		    if event.get('detail', {}).get('requestParameters', {}).get(t, {}):
		        event['detail']['requestParameters'][t] = json.loads(event['detail']['requestParameters'][t])
	# Response Elements
	if raw_response_elements != "None" and raw_response_elements != None:
		for t in document_types:
		    if event.get('detail', {}).get('responseElements', {}).get('policyVersion', {}).get(t, {}):
		        event['detail']['responseElements']['policyVersion'][t] = json.loads(event['detail']['responseElements']['policyVersion'][t])
	################################################################################################

	validateip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

	parsed_event = {}

	# Set ttl to be one year from when the event was logged.
	now = datetime.datetime.utcnow()
	one_year_delta = now + datetime.timedelta(days=365)
	ttl = str(one_year_delta.timestamp())
	parsed_event.setdefault('ttl', {})['N'] = ttl

	request_params = event['detail'].get('requestParameters', {})
	parsed_event.setdefault('request_params', {})['S'] = json.dumps(request_params, indent=2) if request_params != None else '{}'

	parsed_event.setdefault('raw_event', {})['S'] = json.dumps(event, indent=2)
	parsed_event.setdefault('account_id', {})['S'] = event['detail']['userIdentity']['accountId']
	parsed_event.setdefault('account_alias', {})['S'] = get_account_alias(parsed_event['account_id']['S'])

	parsed_event.setdefault('read_only', {})['S'] = str(event['detail']['readOnly'])
	parsed_event.setdefault('source', {})['S'] = event['source']
	parsed_event.setdefault('detail_type', {})['S'] = event['detail-type']
	parsed_event.setdefault('event_type', {})['S'] = event['detail']['userIdentity']['type']
	parsed_event.setdefault('event_name', {})['S'] = event['detail']['eventName']
	parsed_event.setdefault('event_time', {})['S'] = event['detail']['eventTime']
	parsed_event.setdefault('region', {})['S'] = event['detail']['awsRegion']
	parsed_event.setdefault('source_ip', {})['S'] = event['detail']['sourceIPAddress']
	parsed_event.setdefault('user_agent', {})['S'] = event['detail']['userAgent']
	parsed_event.setdefault('event_id', {})['S'] = event['detail']['eventID']
	parsed_event.setdefault('access_key', {})['S'] = event['detail']['userIdentity'].get('accessKeyId', "None")

	# Determine the entity performing the action
	if parsed_event['event_type']['S'] == 'IAMUser':
		parsed_event.setdefault('user', {})['S'] = event['detail']['userIdentity']['userName']
	elif parsed_event['event_type']['S'] == 'AssumedRole':
		user_arn = event['detail']['userIdentity']['arn']
		if user_arn.find('AWSReservedSSO_') != -1:
			parsed_event.setdefault('user', {})['S'] = f'{user_arn.split("/")[1].split("_")[1]}/{user_arn.split("/")[2]}'
		else:
			parsed_event.setdefault('user', {})['S'] = f'{user_arn.split("/")[1]}/{user_arn.split("/")[2]}'
	elif parsed_event['event_type']['S'] == 'Root':
		parsed_event.setdefault('user', {})['S'] = 'Root'
	else:
		parsed_event.setdefault('user', {})['S'] = 'Unknown'

	if validateip.match(parsed_event['source_ip']['S']):
		try:
			geo_dict = get_ip_location(parsed_event['source_ip']['S'])

			geo_dict['mobile'] = str(geo_dict['mobile'])
			geo_dict['proxy'] = str(geo_dict['proxy'])
			geo_dict['hosting'] = str(geo_dict['hosting'])

			parsed_event.setdefault('geo_country', {})['S'] = geo_dict['country']
			parsed_event.setdefault('geo_regionName', {})['S'] = geo_dict['regionName']
			parsed_event.setdefault('geo_city', {})['S'] = geo_dict['city']
			parsed_event.setdefault('geo_isp', {})['S'] = geo_dict['isp']
			parsed_event.setdefault('geo_mobile', {})['S'] = geo_dict['mobile']
			parsed_event.setdefault('geo_proxy', {})['S'] = geo_dict['proxy']
			parsed_event.setdefault('geo_hosting', {})['S'] = geo_dict['hosting']
		except:
			pass
	else:
		parsed_event.setdefault('geo_country', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_regionName', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_city', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_isp', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_mobile', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_proxy', {})['S'] = 'Unknown'
		parsed_event.setdefault('geo_hosting', {})['S'] = 'Unknown'

	return parsed_event

def process_event(parsed_event, event):
	
	urgent, subject, header, message = check_urgency(parsed_event, event)

	if urgent: # If urgent, send email right away and then store in dynamodb
		send_event_to_dynamodb(parsed_event)
		parsed_event.setdefault('urgent', {})['BOOL'] = True
		send_email(event, parsed_event, subject, header, message)
	else: # if not, just store in dynamodb
		send_event_to_dynamodb(parsed_event)
		parsed_event.setdefault('urgent', {})['BOOL'] = False


def lambda_handler(event, context):

	try:
		parsed_event = parse_event(event)
		process_event(parsed_event, event)
	except Exception as e:
		print(e)
		print(f'Event: {event}')
		exit(1)

	return {
		'statusCode': 200,
		'body': json.dumps('CloudTrail event parsed.')
	}
