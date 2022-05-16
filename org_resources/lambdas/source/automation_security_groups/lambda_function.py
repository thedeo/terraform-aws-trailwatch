# This script is designed to automatically revert a Security Group rules that
# allow world access to specific management ports like SSH(22)/RDP(3389).

import json
import logging
import boto3
import os

from time import sleep
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Vars
################################################################################################
project_name	 	   	= os.environ['project_name']
region			 	   	= os.environ['region']
ses_region		 	   	= os.environ['ses_region']
alert_sender            = os.environ['alert_sender']
alert_recipients        = json.loads(os.environ['alert_recipients'])
member_role_name 		= os.environ['member_role_name']
principal_exceptions	= json.loads(os.environ['principal_exceptions'])
monitored_ports			= json.loads(os.environ['monitored_ports'])
session_name			= f'{project_name}-SecurityGroupAutomation'

################################################################################################
# Create cross account credentials - this is here because at the time it was too much trouble
# to create the rp_common layer in every region that this is needed in.
################################################################################################
def create_client(account, region, service):
    retry_limit = 1
    retries = 0
    while True:
        try:
            sts_connection = boto3.client('sts')
            external_account = sts_connection.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{member_role_name}",
                RoleSessionName=session_name
            )
            
            ACCESS_KEY    = external_account['Credentials']['AccessKeyId']
            SECRET_KEY    = external_account['Credentials']['SecretAccessKey']
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
            print(f'Error creating {service} client  -- {account}')
            print(e)
            retries += 1
            if retries >= retry_limit:
                print(f'Retry limit of 1 attempts reached. Giving up...')
                client = 'failed'
                break
            sleep(1)

    return client

################################################################################################
# Get the descriptive alias of an account_id
################################################################################################
def get_account_alias(account_id):

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
			response = organizations.describe_account(AccountId=account_id)
			return clean_account_name(response['Account']['Name'])
		except Exception as e:
			print(f'Could not get account_alias for {account_id} from Organizations.')
			print(e)
			retries += 1
			sleep(1)
			if retries >= retry_limit:
				print(f'Tried {retry_limit} times but failed. Setting to "Unknown".')
				account_alias = 'Unknown'
				break

	return account_alias


def send_email(remediation_exception, remediation_status, violating_resource, event):
	ses = boto3.client('ses', region_name=ses_region)

	################################################################################################
	# Variables
	################################################################################################
	pretty_event    = json.dumps(event, indent=2)
	pretty_request  = json.dumps(event['detail'].get('requestParameters', {}), indent=2)
	account_id       = violating_resource['account_id']
	account_alias   = violating_resource['account_alias']
	user            = violating_resource['user']
	source_ip       = violating_resource['source_ip']
	user_agent      = violating_resource['user_agent']
	access_key      = violating_resource['access_key']
	region          = violating_resource['region']
	sg_id           = violating_resource['sg_id']
	violating_ports = str(violating_resource['violating_ports']).strip('[]')
	cidr_removed    = str(violating_resource['cidr_removed']).strip('[]')

	if remediation_exception:
		status = 'EXCEPTION'
	else:
		status = 'SUCCESS'


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

	html = """<table id="accounttable">
	  <thead id="accountheader"><tr><th colspan="2">SG Remediation - """ + status + """</th></thead>
	<tbody>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">Account</td>   <td style="color: black; background-color: #d1d1d1;">"""  	   + account_alias + """ (""" + account_id + """)</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">Violating User</td><td style="color: black; background-color: #fff;">""" 	   + user					 		      + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">AccessKey</td> <td style="color: black; background-color: #d1d1d1;">"""  	   + access_key					          + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">Region</td> <td style="color: black; background-color: #fff;">""" 	  	  	   + region					 	     	  + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">SourceIP</td>  <td style="color: black; background-color: #d1d1d1;">"""  	   + source_ip					 	      + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">UserAgent</td>  <td style="color: black; background-color: #fff;">"""  	   + user_agent					 	      + """</td></tr>
	<tr><td colspan="2"><br><br></td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">SecurityGroupId</td><td style="color: black; background-color: #fff;">"""	   + sg_id						 		  + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">Violating ports</td><td style="color: black; background-color: #d1d1d1;">"""  + violating_ports			 	 	  + """</td></tr>
	<tr><td style="background-color: #808080; color: black; border: 1px solid #c4c4c4; width: 100px; font-weight: bold;">World access CIDRs</td> <td style="color: black; background-color: #fff;">""" + cidr_removed				 		  + """</td></tr>
	<tr><td colspan="2"><br><br></td></tr>
	<tr><td colspan="2" style="background-color: #808080; color: black; border: 1px solid #c4c4c4; font-weight: bold;">Request</td></tr>
	<tr><td colspan="2" style="color: black; background-color: #fff;"><pre style="max-width:600px;">""" 	  + pretty_request  	 + """</pre></td></tr>
	<tr><td colspan="2" style="background-color: #808080; color: black; border: 1px solid #c4c4c4; font-weight: bold;">Full JSON</td></tr>
	<tr><td colspan="2" style="color: black; background-color: #fff;"><pre style="max-width:600px;">""" 	  + pretty_event 		 + """</pre></td></tr>
	</tbody>
	</table>"""

	################################################################################################
	# Build/Send email with SES
	################################################################################################
	CHARSET = "UTF-8"
	#CONFIGURATION_SET = "ConfigSet"
	SENDER = f"\"Event Automation\" <{alert_sender}>"
	RECIPIENTS = alert_recipients
	SUBJECT = f"SecurityGroup Remediation - {status}"
	BODY_HTML = style + html

	BODY_TEXT = ("SecurityGroup Remediation\r\n"
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

def parse_event(event):

	# Ignore Events that had an Error
	# since an action that had an error
	# would not have opened any ports
	if event['detail'].get('errorCode', ''):
		print('Event was not successful so it is being ignored.')
		return False, None, None, None

	violation_exists      = False
	remediation_exception = False
	violating_resource    = {}
	violating_items       = []
	violating_ports       = []
	cidr_removed          = []
	

	# Extract information
	account_id    = event['detail']['userIdentity']['accountId']
	account_alias = get_account_alias(account_id)

	if account_alias == 'Unknown':
		remediation_exception = True
		print(f'Exception logged for {account_id} since we cannot authenticate with the account.')


	event_type = event['detail']['userIdentity']['type']
	event_name = event['detail']['eventName']
	region     = event['detail']['awsRegion']
	source_ip  = event['detail']['sourceIPAddress']
	user_agent = event['detail']['userAgent']
	access_key = event['detail']['userIdentity'].get('accessKeyId', "None")

	# Review principal
	if event_type == 'IAMUser':
		user       = event['detail']['userIdentity']['userName']
		user_check = user
	elif event_type == 'AssumedRole':
		user_arn   = event['detail']['userIdentity']['arn']
		user_check = event['detail'].get('userIdentity', {}).get('sessionContext', {}).get('sessionIssuer', {}).get('userName', 'None')
		user       = f'{user_arn.split("/")[1]}/{user_arn.split("/")[2]}'
		if user_arn.find('AWSReservedSSO_') != -1:
			user = f'{user_arn.split("/")[1].split("_")[1]}/{user_arn.split("/")[2]}'
		else:
			user = f'{user_arn.split("/")[1]}/{user_arn.split("/")[2]}'
	elif event_type == 'Root':
		user       = 'Root'
		user_check = user
	else:
		user       = 'Unknown (Refer to JSON below)'
		user_check = ""

	################################################
	#  Ignore roles/users in 'principal_exceptions'
	################################################
	for principal in principal_exceptions:
		if user_check.find(principal) != -1:
			print(f'Exception for {user_check}.')
			remediation_exception = True
	
	####################################
	#  Check for world access violation
	####################################
	request_params = event['detail'].get('requestParameters', {})
	sg_id          = request_params.get('groupId', '')
	items          = request_params['ipPermissions'].get('items', {})

	# This will handle situations where the sg_id doesn't exist in the request params
	if not sg_id and request_params.get('groupName', ''):
		group_name = request_params['groupName']
		try:
			ec2 = create_client(account_id, region, 'ec2')
			response = ec2.describe_security_groups(GroupNames=[group_name])
			sg_id = response['SecurityGroups'][0]['GroupId']
		except Exception as e:
			print(e)
			exit(1)


	# This is to allow for when the there is no items object.
	# Usually this happens when there is only one firewall entry.
	if not items:
		ip_protocol = request_params['ipProtocol']
		from_port   = request_params['fromPort']
		to_port     = request_params['toPort']
		cidr_ip     = request_params['cidrIp']

		items = [
			{
			"ipProtocol": ip_protocol,
			"fromPort": from_port,
			"toPort": to_port,
			"groups": {},
			"ipRanges": {
			 "items": [
			   {
			     "cidrIp": cidr_ip
			   }
			 ]
			},
			"ipv6Ranges": {}
			}
		]


	for item in items:

		# Find out what the ports are based on protocol
		ip_protocol  = item['ipProtocol']
		if ip_protocol == '-1':
			from_port = 0
			to_port   = 65535
		else:
			from_port = item['fromPort']
			to_port   = item['toPort']
		
		# Check if rule is for a single port
		get_single_port_bool = lambda f, t : True if (f == t) else False
		single_port          = get_single_port_bool(from_port, to_port)

		# Check if rule allows ipv4 world access
		ipv4_world_access = False
		ip_ranges = item.get('ipRanges', {}).get('items', [])
		for ip_range in ip_ranges:
			cidr_ip = ip_range['cidrIp']
			if cidr_ip == '0.0.0.0/0':
				ipv4_world_access = True
				if '0.0.0.0/0' not in cidr_removed:
					cidr_removed.append('0.0.0.0/0')

		# Check if rule allows ipv6 world access
		ipv6_world_access = False
		ipv6_ranges = item.get('ipv6Ranges', {}).get('items', [])
		for ipv6_range in ipv6_ranges:
			cidr_ipv6 = ipv6_range['cidrIpv6']
			if cidr_ipv6 == '::/0':
				ipv6_world_access = True
				if '::/0' not in cidr_removed:
					cidr_removed.append('::/0')

		# DEBUG
		# if account_id not in ['111111111111']:
		# 	ipv4_world_access = False
		# 	ipv6_world_access = False

		# Check what ip versions were used
		def get_ip_version(v4, v6):
			if (v4 == True) and (v6 == True):
				ip_version = 'both'
			elif v4 == True:
				ip_version = 'ipv4'
			elif v6 == True:
				ip_version = 'ipv6'

			return ip_version

		# Look to see if single port or port range contains a monitored port
		if single_port and (ipv4_world_access or ipv6_world_access):
			if from_port in monitored_ports:
				violation_exists = True
				ip_version = get_ip_version(ipv4_world_access, ipv6_world_access)
				violating_items.append( { 'single_port': single_port,
										  'port': from_port,
										  'ip_protocol': ip_protocol,
										  'ip_version': ip_version } )
				if from_port not in violating_ports:
					violating_ports.append(from_port)

		elif not single_port and (ipv4_world_access or ipv6_world_access):
			port_range = [i for i in range(from_port,to_port+1)]
			for this_port in port_range:
				if this_port in monitored_ports:
					violation_exists = True
					ip_version = get_ip_version(ipv4_world_access, ipv6_world_access)

					# Keep track of unique ranges that are violating
					item_entry = { 'single_port': single_port,
								   'from_port': from_port,
								   'to_port': to_port,
								   'ip_protocol': ip_protocol,
								   'ip_version': ip_version }
					if item_entry not in violating_items:
						violating_items.append( item_entry )

					# Keep track of unique ranges that are violating
					this_range = f'{from_port}-{to_port} ({ip_protocol})'
					if this_range not in violating_ports:
						violating_ports.append(f'{this_range}')
					

		# If a violation was found, capture key details
		if violation_exists == True:
			violating_resource = { 'account_id': account_id,
								   'account_alias': account_alias,
								   'user': user,
								   'source_ip': source_ip,
								   'user_agent': user_agent,
								   'access_key': access_key,
								   'region': region,
								   'sg_id': sg_id,
								   'violating_ports': violating_ports,
								   'cidr_removed': cidr_removed }

	return violation_exists, violating_resource, violating_items, remediation_exception

def remediate_violation(violating_resource, violating_items):

	remediation_status = True

	account_id    = violating_resource['account_id']
	account_alias = violating_resource['account_alias']
	user          = violating_resource['user']
	source_ip     = violating_resource['source_ip']
	user_agent    = violating_resource['user_agent']
	access_key    = violating_resource['access_key']
	region        = violating_resource['region']
	sg_id         = violating_resource['sg_id']

	ec2 = create_client(account_id, region, 'ec2')

	print(violating_items)

	for item in violating_items:

		single_port = item['single_port']
		ip_protocol = item['ip_protocol']
		ip_version = item['ip_version']
		
		##############################
		# Revoke single port rules
		##############################
		if single_port and ( ip_version == 'ipv4' or ip_version == 'both' ):
			port = item['port']
			try:
				ec2.revoke_security_group_ingress( GroupId=sg_id,
												   FromPort=port,
												   ToPort=port,
												   CidrIp='0.0.0.0/0',
												   IpProtocol=ip_protocol )
				print(f'REMEDIATED [ account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {port} -- IpProtocol: {ip_protocol} cidr: 0.0.0.0/0 ]')
			except Exception as e:
				print(e)
				print('Remediation - FAILED')
				print(f'account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {port} -- IpProtocol: {ip_protocol} ')
				remediation_status = False

		if single_port and ( ip_version == 'ipv6' or ip_version == 'both' ):
			port = item['port']
			try:
				ec2.revoke_security_group_ingress( GroupId=sg_id,
												   IpPermissions=[{
												   'FromPort': port,
												   'IpProtocol': ip_protocol,
												   'Ipv6Ranges': [
																	{
																		'CidrIpv6': '::/0'
																	}
												   ],
												   'ToPort': port
												   }])
				print(f'REMEDIATED [ account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {port} -- IpProtocol: {ip_protocol} cidr: ::/0 ]')
			except Exception as e:
				print(e)
				print('Remediation - FAILED')
				print(f'account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {port} -- IpProtocol: {ip_protocol} ')
				remediation_status = False


		##############################
		# Revoke port range rules
		##############################
		if not single_port and ( ip_version == 'ipv4' or ip_version == 'both' ):
			from_port = item['from_port']
			to_port = item['to_port']
			try:
				ec2.revoke_security_group_ingress( GroupId=sg_id,
												   FromPort=from_port,
												   ToPort=to_port,
												   CidrIp='0.0.0.0/0',
												   IpProtocol=ip_protocol )
				print(f'REMEDIATED [ account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {from_port}-{to_port} -- IpProtocol: {ip_protocol} cidr: 0.0.0.0/0 ]')
			except Exception as e:
				print(e)
				print('Remediation - FAILED')
				print(f'account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {from_port}-{to_port} -- IpProtocol: {ip_protocol} ')
				remediation_status = False

		if not single_port and ( ip_version == 'ipv6' or ip_version == 'both' ):
			from_port = item['from_port']
			to_port = item['to_port']
			try:
				ec2.revoke_security_group_ingress( GroupId=sg_id,
												   IpPermissions=[{
												   'FromPort': from_port,
												   'IpProtocol': ip_protocol,
												   'Ipv6Ranges': [
																	{
																		'CidrIpv6': '::/0'
																	}
												   ],
												   'ToPort': to_port
												   }])
				print(f'REMEDIATED [ account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {from_port}-{to_port} -- IpProtocol: {ip_protocol} cidr: ::/0 ]')
			except Exception as e:
				print(e)
				print('Remediation - FAILED')
				print(f'account_id: {account_id} -- region: {region}  -- SG: {sg_id} -- Port(s): {from_port}-{to_port} -- IpProtocol: {ip_protocol} ')
				remediation_status = False


	return remediation_status


def lambda_handler(event, context):

	violation_exists, violating_resource, violating_items, remediation_exception = parse_event(event)

	if violation_exists:
		# Set default to False in case there is a user exception.
		remediation_status = False

		# If this is not a user exception, remediate the violation
		if not remediation_exception:
			remediation_status = remediate_violation(violating_resource, violating_items)

		# If the remediation was successful or there was a user exception, send a report.
		if remediation_status or remediation_exception:
			send_email(remediation_exception, remediation_status, violating_resource, event)
	else:
		print('No violations found.')

	return {
		'statusCode': 200,
		'body': json.dumps('Event parsed.')
	}
