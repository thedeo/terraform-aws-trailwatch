import boto3
import re
import json
import logging
import datetime

from time import sleep
from botocore.exceptions import ClientError

from common import create_client
from common import retry
from common import clean_account_name
from common import create_report_table
from common import swap_report_table

logger = logging.getLogger()
logger.setLevel(logging.INFO)

################################################################################################
# Variables
################################################################################################
from common import project_name
from common import org_account_id

################################################################################################
# Mode A Logic
################################################################################################
def divide_list(l, n):
    # looping till length l
    for i in range(0, len(l), n): 
        yield l[i:i + n]

def get_iam_user_list(account_id):
	iam = create_client(account_id, 'us-east-1', 'iam')

	user_list = []
	# Get list of all users in paginated list
	next_marker = False
	while True:
		if not next_marker:
			try:
				response = iam.list_users()
				for user in response['Users']:
					# Reformat datetime objects so they can be json serialized
					user['CreateDate'] = user['CreateDate'].isoformat()
					if user.get('PasswordLastUsed',''):
						user['PasswordLastUsed'] = user['PasswordLastUsed'].isoformat()
				user_list = user_list + response['Users']
				if response.get('Marker', ''):
					next_marker = True
					marker = response['Marker']
				else:
					break # no more users left to list
			except Exception as e:
				print(e)
				exit(1)

		elif next_marker:
			try:
				response = iam.list_users(Marker=marker)
				for user in response['Users']:
					# Reformat datetime objects so they can be json serialized
					user['CreateDate'] = user['CreateDate'].isoformat()
					if user.get('PasswordLastUsed',''):
						user['PasswordLastUsed'] = user['PasswordLastUsed'].isoformat()
				user_list = user_list + response['Users']
				if response.get('Marker', ''):
					next_marker = True
					marker = response['Marker']
				else:
					break # no more users left to list
			except Exception as e:
				print(e)
				exit(1)
	return user_list


################################################################################################
# Mode B Logic
################################################################################################
def get_raw_user_data(account_id, account_alias, user_list):
	iam = create_client(account_id, 'us-east-1', 'iam')

	raw_user_data_list = []
	all_groups = []
	inline_group_policy_names = {}
	attached_group_policies = {}
	attached_user_policy_documents = {} # store attached policies for users to avoid repeat work
	inline_group_policy_documents = {} # store inline policies for groups to avoid repeat work
	attached_group_policy_documents = {} # store attached policies for groups to avoid repeat work
	retry_limit = 3

	for user in user_list:
		user_id = user.get('UserId', '')
		username = user.get('UserName', '')
		user_arn = user.get('Arn', '')
		user_path = user.get('Path', '')
		create_date = user.get('CreateDate', '')
		pw_last_used = user.get('PasswordLastUsed', '')
		permission_boundry_arn = user.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn', '')

		#############################################################
		# This API call is just to get 'PasswordResetRequired' bool
		#############################################################
		retry_count = 0
		try:
			response = iam.get_login_profile(UserName=username)
			password_reset_required = str(response.get('LoginProfile', {}).get('PasswordResetRequired', '-'))
			login_profile_exists = True
		except ClientError as e:
			error_code = e.response['Error']['Code']
			error_message = e.response['Error']['Message']
			#print(f'{error_code}: {error_message}')
			if error_code == 'NoSuchEntity':
				#print(f'LoginProfile does not exist for {username}.')
				login_profile_exists = False
				password_reset_required = '-'
			elif retry_count >= retry_limit:
				print(f'Reached limit of {retry_limit} retries to get \'{username}\' login profile. Exiting...')
				exit(1)
			else:
				retry_count += 1
				print(f'Retrying in {2*retry_count} seconds to get \'{username}\' login profile...')
				sleep(2*retry_count) # exponential backoff for rate limiting


		#############################################################
		# Check if user has mfa enabled
		#############################################################
		# I checked and the best way to tell if mfa is enabled is the
		# list_mfa_devices() api call. If the returned list has any
		# items in it, that means that there is at least one mfa device
		# associated with the user and hence MFA is enabled.
		retry_count = 0
		while True:
			try:
				response = iam.list_mfa_devices(UserName=username)
				if len(response['MFADevices']) > 0:
					mfa_enabled = True
				else:
					mfa_enabled = False
				break
			except Exception as e:
				retry_count = retry(e, f'Get \'{username}\' mfa status',
									retry_count, retry_limit)

		################################################################################################
		# USER POLICIES
		################################################################################################
		#############################################################
		# Get inline policy names for user
		#############################################################
		inline_user_policy_names = []
		# Get list of all policies in paginated list
		next_marker = False
		retry_count = 0
		while True:
			if not next_marker:
				try:
					response = iam.list_user_policies(UserName=username)
					inline_user_policy_names = inline_user_policy_names + response['PolicyNames']
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' inline policies',
										retry_count, retry_limit)

			elif next_marker:
				try:
					response = iam.list_user_policies(UserName=username,Marker=marker)
					inline_user_policy_names = inline_user_policy_names + response['PolicyNames']
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' inline policies',
										retry_count, retry_limit)


		#############################################################
		# Get attached policy name/arn for user
		#############################################################
		attached_user_policies = []
		# Get list of all policies in paginated list
		next_marker = False
		retry_count = 0
		while True:
			if not next_marker:
				try:
					response = iam.list_attached_user_policies(UserName=username)
					attached_user_policies = attached_user_policies + response['AttachedPolicies']
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' attached policies',
										retry_count, retry_limit)

			elif next_marker:
				try:
					response = iam.list_attached_user_policies(UserName=username,Marker=marker)
					attached_user_policies = attached_user_policies + response['AttachedPolicies']
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' attached policies',
										retry_count, retry_limit)


		###############################################################
		# Get detailed policy information for both inline and attached
		###############################################################
		inline_user_policy_documents = {}
		for inline_user_policy_name in inline_user_policy_names:
			while True:
				try:
					response = iam.get_user_policy(
						UserName=username,
						PolicyName=inline_user_policy_name
					)
					inline_user_policy_documents[inline_user_policy_name] = response['PolicyDocument']
					break
				except Exception as e:
					retry_count = retry(e, f'Get \'{inline_user_policy_name}\' data',
										retry_count, retry_limit)


		for attached_user_policy in attached_user_policies:
			attached_user_policy_name = attached_user_policy['PolicyName']
			attached_user_policy_arn = attached_user_policy['PolicyArn']
			# The following if condition will ensure we only pull data for attached policies once.
			# That will keep us from pulling information about the same policies over and over
			# just because multiple users/groups have them attached.
			if not attached_user_policy_documents.get(attached_user_policy_arn, ''):
				while True:
					try:
						response = iam.get_policy(PolicyArn=attached_user_policy_arn)
						policy_version_id = response['Policy']['DefaultVersionId']
						response = iam.get_policy_version(
							PolicyArn=attached_user_policy_arn,
							VersionId=policy_version_id
						)
						attached_user_policy_documents[attached_user_policy_arn] = response['PolicyVersion']['Document']
						break
					except Exception as e:
						retry_count = retry(e, f'Get \'{inline_user_policy_name}\' data',
											retry_count, retry_limit)

		################################################################################################
		# GROUP POLICIES
		################################################################################################
		###############################################################
		# Get list of groups that the user is a member of
		###############################################################
		user_groups = []
		next_marker = False
		retry_count = 0
		while True:
			if not next_marker:
				try:
					response = iam.list_groups_for_user(UserName=username)
					for group in response['Groups']:
						user_groups.append({'group_name': group['GroupName'], 'group_path': group['Path']})
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' groups',
										retry_count, retry_limit)

			elif next_marker:
				try:
					response = iam.list_groups_for_user(UserName=username,Marker=marker)
					for group in response['Groups']:
						user_groups.append({'group_name': group['GroupName'], 'group_path': group['Path']})
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' groups',
										retry_count, retry_limit)

		# For each group the user is a member of pull data
		for group in user_groups:
			group_name = group['group_name']
			group_path = group['group_path']
			inline_group_policy_names[group_name] = []
			attached_group_policies[group_name] = []
			if {'group_name': group_name, 'group_path': group_path} not in all_groups:
				all_groups.append({'group_name': group_name, 'group_path': group_path})
			#############################################################
			# Get inline policy names for user's groups
			#############################################################
			next_marker = False
			retry_count = 0
			while True:
				if not next_marker:
					try:
						response = iam.list_group_policies(GroupName=group_name)
						inline_group_policy_names[group_name] += response['PolicyNames']
						if response.get('Marker', ''):
							next_marker = True
							marker = response['Marker']
						else:
							break # no more policies left to list
					except Exception as e:
						retry_count = retry(e, f'Get \'{group_name}\' group inline policies',
											retry_count, retry_limit)

				elif next_marker:
					try:
						response = iam.list_group_policies(GroupName=group_name,Marker=marker)
						inline_group_policy_names[group_name] += response['PolicyNames']
						if response.get('Marker', ''):
							next_marker = True
							marker = response['Marker']
						else:
							break # no more policies left to list
					except Exception as e:
						retry_count = retry(e, f'Get \'{group_name}\' group inline policies',
											retry_count, retry_limit)


			#############################################################
			# Get attached policy name/arn for user's groups
			#############################################################
			next_marker = False
			retry_count = 0
			while True:
				if not next_marker:
					try:
						response = iam.list_attached_group_policies(
							GroupName=group_name,
							PathPrefix=group_path
						)
						attached_group_policies[group_name] += response['AttachedPolicies']
						if response.get('Marker', ''):
							next_marker = True
							marker = response['Marker']
						else:
							break # no more policies left to list
					except Exception as e:
						retry_count = retry(e, f'Get \'{group_name}\' group attached policies',
											retry_count, retry_limit)

				elif next_marker:
					try:
						response = iam.list_attached_group_policies(
							GroupName=group_name,
							PathPrefix=group_path,
							Marker=next_marker
						)
						attached_group_policies[group_name] += response['AttachedPolicies']
						if response.get('Marker', ''):
							next_marker = True
							marker = response['Marker']
						else:
							break # no more policies left to list
					except Exception as e:
						retry_count = retry(e, f'Get \'{group_name}\' group attached policies',
											retry_count, retry_limit)


		###############################################################
		# Get detailed policy information for both inline and attached
		###############################################################
		for group in user_groups:
			group_name = group['group_name']
			for inline_group_policy_name in inline_group_policy_names[group_name]:
				retry_count = 0
				while True:
					try:
						response = iam.get_group_policy(
							GroupName=group_name,
							PolicyName=inline_group_policy_name
						)
						inline_group_policy_documents.setdefault(group_name, {})[inline_group_policy_name] = response['PolicyDocument']
						break
					except Exception as e:
						retry_count = retry(e, f'Get \'{inline_group_policy_name}\' document',
											retry_count, retry_limit)


			for attached_group_policy in attached_group_policies[group_name]:
				attached_group_policy_arn = attached_group_policy['PolicyArn']
				# The following if condition will ensure we only pull data for attached policies once.
				# That will keep us from pulling information about the same policies over and over
				# just because multiple users/groups have them attached.
				if not attached_group_policy_documents.get(attached_group_policy_arn, ''):
					retry_count = 0
					while True:
						try:
							response = iam.get_policy(PolicyArn=attached_group_policy_arn)
							policy_version_id = response['Policy']['DefaultVersionId']
							response = iam.get_policy_version(
								PolicyArn=attached_group_policy_arn,
								VersionId=policy_version_id
							)
							attached_group_policy_documents[attached_group_policy_arn] = response['PolicyVersion']['Document']
							break
						except Exception as e:
							retry_count = retry(e, f'Get \'{attached_group_policy_arn}\' document',
												retry_count, retry_limit)


		################################################################################################
		# Access Key Data
		################################################################################################
		############################################
		# Get a list of access keys for this user
		############################################
		access_keys = []
		next_marker = False
		retry_count = 0
		while True:
			if not next_marker:
				try:
					response = iam.list_access_keys(UserName=username)
					for access_key in response['AccessKeyMetadata']:
						access_keys.append(access_key)
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' access keys',
										retry_count, retry_limit)

			elif next_marker:
				try:
					response = iam.list_access_keys(UserName=username,Marker=next_marker)
					for access_key in response['AccessKeyMetadata']:
						access_keys.append(access_key)
					if response.get('Marker', ''):
						next_marker = True
						marker = response['Marker']
					else:
						break # no more policies left to list
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' access keys',
										retry_count, retry_limit)


		############################################
		# Get 'AccessKeyLastUsed' of access keys
		############################################
		for access_key in access_keys:
			access_key_id = access_key['AccessKeyId']
			retry_count = 0
			while True:
				try:
					response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
					last_used = response['AccessKeyLastUsed']
					access_key['LastUsedDate'] = last_used.get('LastUsedDate', 'None')
					if not isinstance(access_key['LastUsedDate'], str):
						access_key['LastUsedDate'] = access_key['LastUsedDate'].isoformat()
					access_key['ServiceName'] = last_used.get('ServiceName', 'None')
					access_key['Region'] = last_used.get('Region', 'None')
					break # success
				except Exception as e:
					retry_count = retry(e, f'Get \'{username}\' access key metadata',
										retry_count, retry_limit)


		########################
		# Package Raw User Data
		########################
		raw_user_data_dict = {}
		raw_user_data_dict['user_id'] = user_id
		raw_user_data_dict['username'] = username
		raw_user_data_dict['user_arn'] = user_arn
		raw_user_data_dict['user_path'] = user_path
		raw_user_data_dict['create_date'] = create_date
		raw_user_data_dict['pw_last_used'] = pw_last_used
		raw_user_data_dict['permission_boundry_arn'] = permission_boundry_arn
		raw_user_data_dict['login_profile_exists'] = login_profile_exists
		raw_user_data_dict['password_reset_required'] = password_reset_required
		raw_user_data_dict['mfa_enabled'] = mfa_enabled
		raw_user_data_dict['inline_user_policy_names'] = inline_user_policy_names
		raw_user_data_dict['inline_user_policy_documents'] = inline_user_policy_documents
		raw_user_data_dict['attached_user_policies'] = attached_user_policies
		raw_user_data_dict['user_groups'] = user_groups
		raw_user_data_dict['access_keys'] = access_keys
		raw_user_data_list.append(raw_user_data_dict)

		packaged_raw_user_data = {}
		packaged_raw_user_data['raw_user_data_list'] = raw_user_data_list
		packaged_raw_user_data['all_groups'] = all_groups
		packaged_raw_user_data['inline_group_policy_names'] = inline_group_policy_names
		packaged_raw_user_data['attached_group_policies'] = attached_group_policies
		packaged_raw_user_data['attached_user_policy_documents'] = attached_user_policy_documents
		packaged_raw_user_data['inline_group_policy_documents'] = inline_group_policy_documents
		packaged_raw_user_data['attached_group_policy_documents'] = attached_group_policy_documents

	return packaged_raw_user_data


################################################################################################
# Analyze and format data to be inserted into DynamoDB
################################################################################################
is_aws_managed_policy = re.compile("^arn:aws:iam::aws:policy/.+", re.IGNORECASE) # regex for aws managed policies
is_fullaccess_policy = re.compile("^.*FullAccess.*$", re.IGNORECASE) # check if policy is FullAccess

def check_statement_for_admin(statement):

	effect = statement['Effect']
	action = statement.get('Action', '')
	not_action = statement.get('NotAction', '')
	resource = statement['Resource']

	if effect == 'Deny': # Deny statements are not permissive
		return False

	# This is tricky, but flag as admin if NotAction doesn't include IAM.
	# And if the resource is '*' or an iam resource.
	if not_action:
		not_action_flag = False
		not_action_resource_flag = False

		# ACTION
		# If there are NO iam actions listed for this
		# 'NotAction' statement, the user could poossibly
		# have IAM permissions and therefore escalate perms.
		if isinstance(not_action, str):
			if not re.search(r'^iam:\*$', not_action):
				not_action_flag = True
		elif isinstance(not_action, list):
			not_actions_list = []
			for this_not_action in not_action:
				if re.search(r'^iam:\*$', this_not_action): # if 'iam:*' is found
					not_actions_list.append(False)
				else:
					not_actions_list.append(True)
			if not any(not_actions_list): # If none in list are true, then there was no iam:* found and we flag it.
				not_action_flag = True

		# RESOURCE
		# If there ARE any() iam resources listed for this
		# 'NotAction' statement resource, the user could poossibly
		# have IAM permissions and therefore escalate perms.
		if isinstance(resource, str):
			if re.search(r'^arn:aws:iam.*$', resource) or resource == '*':
				not_action_resource_flag = True
		elif isinstance(resource, list):
			iam_resources_list = [False] # default to false
			for this_resource in resource:
				if re.search(r'^arn:aws:iam.*$', resource) or resource == '*': # if iam resource found
					iam_resources_list.append(True)
			if any(iam_resources_list):
				not_action_resource_flag = True

		# If both flags are true, this means the user likely
		# has IAM permissions to escalate their user perms.
		if not_action_flag and not_action_resource_flag:
			return True
		else:
			return False

	# Evaluate action and resource seperately since they
	# can be a combination of string or list.
	contains_wildcard = {}
	contains_wildcard['Action'] = False
	contains_wildcard['Resource'] = False
	keys = ['Action', 'Resource']
	for key in keys:
		if isinstance(statement[key], str):
			if statement[key] == '*':
				contains_wildcard[key] = True
		elif isinstance(statement[key], list):
			if '*' in statement[key]:
				contains_wildcard[key] = True

	if contains_wildcard['Action'] and contains_wildcard['Resource'] and effect == 'Allow': # consider as admin
		return True
	else:
		return False


def check_statement_for_fullacess(statement):

	effect = statement['Effect']
	action = statement.get('Action', '')
	not_action = statement.get('NotAction', '')
	resource = statement['Resource']

	if effect == 'Deny': # Deny statements are not permissive
		return False

	# If you're using 'notaction' it is EXTREMELY likely
	# that user has full access to at least one service.
	# In order to make an Allow statement with NotAction
	# that doesn't provide full access to something, you
	# would have to list every AWS service or every possible
	# AWS resource type.
	if not_action:
		return True # consider as full access

	# Assume these are false
	action_flag = False
	resource_flag = False

	# ACTION
	# If there are any service wildcards like iam:* or ec2:*
	# flag this statement action
	if isinstance(action, str):
		if re.search(r'^.+:\*$', action):
			action_flag = True
	elif isinstance(action, list):
		actions_list = [False]
		for this_action in action:
			if re.search(r'^.+:\*$', this_action):
				actions_list.append(True)
		if any(actions_list):
			action_flag = True

	# RESOURCE
	# If there are any occurances of just '*' as a resource
	# flag this statement resource.
	if isinstance(resource, str):
		if resource == '*':
			resource_flag = True
	elif isinstance(resource, list):
		iam_resources_list = [False]
		for this_resource in resource:
			if resource == '*':
				iam_resources_list.append(True)
		if any(iam_resources_list):
			resource_flag = True

	if action_flag and resource_flag: # consider as full access
		return True
	else:
		return False

def run_check(check_type, policy_document):
	if check_type == 'admin':
		if isinstance(policy_document['Statement'], list):
			for statement in policy_document['Statement']:
				if check_statement_for_admin(statement):
					return True

		elif isinstance(policy_document['Statement'], dict):
			if check_statement_for_admin(policy_document['Statement']):
				return True
	elif check_type == 'fullaccess':
		if isinstance(policy_document['Statement'], list):
			for statement in policy_document['Statement']:
				if check_statement_for_fullacess(statement):
					return True

		elif isinstance(policy_document['Statement'], dict):
			if check_statement_for_fullacess(policy_document['Statement']):
				return True
	return False # default response


def analyze_user_data(account_id, account_alias, packaged_raw_user_data):

	processed_user_data_list = []

	all_groups = packaged_raw_user_data['all_groups']
	inline_group_policy_names = packaged_raw_user_data['inline_group_policy_names']
	attached_group_policies = packaged_raw_user_data['attached_group_policies']
	attached_user_policy_documents = packaged_raw_user_data['attached_user_policy_documents']
	inline_group_policy_documents = packaged_raw_user_data['inline_group_policy_documents']
	attached_group_policy_documents = packaged_raw_user_data['attached_group_policy_documents']

	########################
	# USER'S GROUPS
	########################
	# Iterate over all represented groups and see if they provide admin.
	# This information will be used when evaluating groups a user is a member of.
	admin_groups = []
	fullaccess_groups = []
	group_admin_policies = {}
	group_fullaccess_policies = {}
	for group in all_groups:
		group_is_admin = False
		group_is_fullaccess = False
		group_name = group['group_name']

		group_admin_policies[group_name] = []
		group_fullaccess_policies[group_name] = []

		# Inline Group Policies
		for inline_group_policy_name in inline_group_policy_names[group_name]:
			policy_document = inline_group_policy_documents[group_name][inline_group_policy_name]
			# Check Admin
			if run_check('admin', policy_document):
				group_is_admin = True
				if inline_group_policy_name not in group_admin_policies[group_name]:
					group_admin_policies[group_name].append(inline_group_policy_name)
				if group_name not in admin_groups:
					admin_groups.append(group_name)
			# Check FullAccess
			if run_check('fullaccess', policy_document):
				group_is_fullaccess = True
				if inline_group_policy_name not in group_fullaccess_policies[group_name]:
					group_fullaccess_policies[group_name].append(inline_group_policy_name)
				if group_name not in fullaccess_groups:
					fullaccess_groups.append(group_name)

		# Attached Group Policies
		for attached_group_policy in attached_group_policies[group_name]:
			policy_arn = attached_group_policy['PolicyArn']
			# Check Admin
			if policy_arn == 'arn:aws:iam::aws:policy/AdministratorAccess':
				group_is_admin = True
				if policy_arn not in group_admin_policies[group_name]:
					group_admin_policies[group_name].append(policy_arn)
				if group_name not in admin_groups:
					admin_groups.append(group_name)
			elif is_aws_managed_policy.match(policy_arn):
				pass # we are only concerned in checking customer managed policies
			else:
				policy_document = attached_group_policy_documents[policy_arn]
				# Check Admin
				if run_check('admin', policy_document):
					group_is_admin = True
					if policy_arn not in group_admin_policies[group_name]:
						group_admin_policies[group_name].append(policy_arn)
					if group_name not in admin_groups:
						admin_groups.append(group_name)
				# Check FullAccess
				if run_check('fullaccess', policy_document):
					group_is_fullaccess = True
					if policy_arn not in group_fullaccess_policies[group_name]:
						group_fullaccess_policies[group_name].append(policy_arn)
					if group_name not in fullaccess_groups:
						fullaccess_groups.append(group_name)

		# Check FullAccess
		for attached_group_policy in attached_group_policies[group_name]:
			policy_arn = attached_group_policy['PolicyArn']
			if is_fullaccess_policy.match(policy_arn):
				group_is_fullaccess = True
				if policy_arn not in group_fullaccess_policies[group_name]:
					group_fullaccess_policies[group_name].append(policy_arn)
				if group_name not in fullaccess_groups:
					fullaccess_groups.append(group_name)


	########################
	# USERS
	########################
	now = datetime.datetime.now() # used for key & pw ages
	for user in packaged_raw_user_data['raw_user_data_list']:
		user_admin_policies = []
		user_fullaccess_policies = []
		is_admin = False
		is_fullaccess = False
		username = user['username']

		########################################################
		# Check if user is Admin based on user level policies
		########################################################
		# User Inline Policies
		for policy_name in user['inline_user_policy_names']:		
			policy_document = user['inline_user_policy_documents'][policy_name]
			# Check Admin
			if run_check('admin', policy_document):
				is_admin = True
				if policy_name not in user_admin_policies:
					user_admin_policies.append(policy_name)
			# Check FullAccess
			if run_check('fullaccess', policy_document):
				is_fullaccess = True
				if policy_name not in user_fullaccess_policies:
					user_fullaccess_policies.append(policy_name)

		# User Attached Policies
		for policy in user['attached_user_policies']:
			policy_arn = policy['PolicyArn']
			if policy_arn == 'arn:aws:iam::aws:policy/AdministratorAccess':
				is_admin = True
				if policy_arn not in user_admin_policies:
					user_admin_policies.append(policy_arn)
			elif is_aws_managed_policy.match(policy_arn):
				pass # we are only concerned in checking customer managed policies
			else:
				policy_document = attached_user_policy_documents[policy_arn]
				# Check Admin
				if run_check('admin', policy_document):
					is_admin = True
					if policy_arn not in user_admin_policies:
						user_admin_policies.append(policy_arn)
				# Check FullAccess
				if run_check('fullaccess', policy_document):
					is_fullaccess = True
					if policy_arn not in user_fullaccess_policies:
						user_fullaccess_policies.append(policy_arn)


		# Check FullAccess
		for policy in user['attached_user_policies']:
			policy_arn = policy['PolicyArn']
			if is_fullaccess_policy.match(policy_arn):
				is_fullaccess = True
				if policy_arn not in user_fullaccess_policies:
					user_fullaccess_policies.append(policy_arn)

		########################################################
		# Check if user is Admin based on group level policies
		########################################################
		# Check to see if the user's group is admin.
		for group in user['user_groups']:
			group_name = group['group_name']
			if group_name in admin_groups:
				is_admin = True
				user_admin_policies += group_admin_policies[group_name]

		# Check to see if the user's group has fullaccess.
		for group in user['user_groups']:
			group_name = group['group_name']
			if group_name in fullaccess_groups:
				is_fullaccess = True
				user_fullaccess_policies += group_fullaccess_policies[group_name]

		################################################################################################
		# Package Processed User Data
		################################################################################################
		item = {}
		item.setdefault('account_id', {})['S'] = account_id
		item.setdefault('account_alias', {})['S'] = account_alias
		item.setdefault('user_id', {})['S'] = user['user_id']
		item.setdefault('username', {})['S'] = user['username']
		item.setdefault('user_arn', {})['S'] = user['user_arn']
		item.setdefault('user_path', {})['S'] = user['user_path']
		item.setdefault('create_date', {})['S'] = user['create_date']
		item.setdefault('pw_last_used', {})['S'] = user['pw_last_used']
		item.setdefault('permission_boundry_arn', {})['S'] = user['permission_boundry_arn']
		item.setdefault('login_profile_exists', {})['S'] = str(user['login_profile_exists']).lower()
		item.setdefault('password_reset_required', {})['S'] = user['password_reset_required'].lower()
		item.setdefault('mfa_enabled', {})['S'] = str(user['mfa_enabled']).lower()

		# New attributes from processed data
		item.setdefault('is_admin', {})['S'] = str(is_admin).lower()
		item.setdefault('is_fullaccess', {})['S'] = str(is_fullaccess).lower()
		item.setdefault('user_admin_policies', {})['S'] = json.dumps('<br>'.join(set(user_admin_policies))).replace('"', '') if user_admin_policies else '-'
		item.setdefault('user_fullaccess_policies', {})['S'] = json.dumps('<br>'.join(set(user_fullaccess_policies))).replace('"', '') if user_fullaccess_policies else '-'

		#####################
		# Access Keys
		#####################
		def key_exists(var, i):
			# check if key list index exists
			try:
				if var[i]:
					return True
				else:

					return False
			except Exception as e:
				return False

		for i in [0, 1]: # check for two keys
			keys = user['access_keys']
			k = i+1 # key number is i+1
			item.setdefault(f'AccessKey{k}', {})['S'] = keys[i]['AccessKeyId'] if key_exists(keys, i) else '-' # add [-4:] to get last 4 char
			item.setdefault(f'AccessKey{k}Id', {})['S'] = keys[i]['AccessKeyId'] if key_exists(keys, i) else '-'
			item.setdefault(f'AccessKey{k}Status', {})['S'] = keys[i]['Status'].lower() if key_exists(keys, i) else '-'
			item.setdefault(f'AccessKey{k}CreateDate', {})['S'] = keys[i]['CreateDate'].isoformat() if key_exists(keys, i) else '-'
			item.setdefault(f'AccessKey{k}LastUsedDate', {})['S'] = keys[i]['LastUsedDate'] if key_exists(keys, i) else '-'
			item.setdefault(f'AccessKey{k}ServiceName', {})['S'] = keys[i]['ServiceName'] if key_exists(keys, i) else '-'
			item.setdefault(f'AccessKey{k}Region', {})['S'] = keys[i]['Region'] if key_exists(keys, i) else '-'

			# Set Key age if exists
			if key_exists(keys, i):
				create_date = keys[i]['CreateDate'].replace(tzinfo=None)
				key_age = now - create_date # get days since creation
				item.setdefault(f'AccessKey{k}Age', {})['N'] = f'{key_age.days}'
			else:
				item.setdefault(f'AccessKey{k}Age', {})['N'] = '0'

			# Set Key last used if exists
			if key_exists(keys, i):
				if keys[i]['LastUsedDate'] != 'None':
					key_last_used_date = datetime.datetime.strptime(keys[i]['LastUsedDate'].replace('+00:00', ''), '%Y-%m-%dT%H:%M:%S')
					key_last_used_age = now - key_last_used_date # get days since last used
					item.setdefault(f'AccessKey{k}LastUsedDays', {})['N'] = f'{key_last_used_age.days}'
				else:
					item.setdefault(f'AccessKey{k}LastUsedDays', {})['N'] = '0'
			else:
				item.setdefault(f'AccessKey{k}LastUsedDays', {})['N'] = '0'

		# Set password last used age
		if user['pw_last_used']:
			pw_last_used_date = datetime.datetime.strptime(user['pw_last_used'].replace('+00:00', ''), '%Y-%m-%dT%H:%M:%S')
			pw_last_used_age = now - pw_last_used_date # get days since last used
			item.setdefault(f'PasswordLastUsedDays', {})['N'] = f'{pw_last_used_age.days}'
		else:
			item.setdefault(f'PasswordLastUsedDays', {})['N'] = '0'

		processed_user_data_list.append({"PutRequest": {"Item": item}})

	return processed_user_data_list


def send_to_dynamodb(account_id, account_alias, processed_user_data_list, report_table):
	dynamodb = boto3.client('dynamodb', region_name='us-east-1')

	request_items_batch = []
	count = 0
	retry_limit = 3
	total_put_request = len(processed_user_data_list)

	# Create Batches of 25 request items
	for put_request in processed_user_data_list:

		request_items_batch.append(put_request)
		count += 1
		total_put_request -= 1

		if count > 24:
			# Put batch into dynamodb
			retry_count = 0
			while True:
				try:
					dynamodb.batch_write_item(RequestItems={f"{report_table}": request_items_batch})
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
					dynamodb.batch_write_item(RequestItems={f"{report_table}": request_items_batch})
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

	if not report_type == 'user':
		print('Event does not match report type "user".')
		print(event)
		exit(1)

	if mode == 'bootstrap':
		report_table = create_report_table(project_name, report_type, 'account_id', 'user_arn')

		return {
			'statusCode':   200,
			'report_table': report_table
		}

	if mode == 'a':

		# Mode a collects a list of users, divide them into 50 user chunks for processing.
		account_id 	  = event['payload']['Id']
		account_name  = event['payload']['Name']
		account_alias = clean_account_name(account_name)
		
		print(f'Getting user list for {account_alias}({account_id})')
		user_list = get_iam_user_list(account_id)
		
		print(f'Distributing {len(user_list)} users among sub functions...')
		user_lists = list(divide_list(user_list, 50))

		return {
			'statusCode':    200,
			'account_id':    account_id,
			'account_name':  account_name,
			'account_alias': account_alias,
			'report_type':   report_type,
			'report_table':  report_table,
			'mode':          'b',
			'user_lists':    user_lists
		}

	if mode == 'b':
		# Mode b collects detailed user data and perform analysis on it. The result is stored in DynamoDB.
		account_id = event['account_id']
		account_alias = event['account_alias']
		user_list = event['user_list']
		num_users = len(user_list)
		report_table = event['report_table']

		print(f'Getting detailed data for {num_users} users in {account_alias}({account_id})...')
		packaged_raw_user_data = get_raw_user_data(account_id, account_alias, user_list)

		print(f'Organizing data for {num_users} users in {account_alias}({account_id})...')
		processed_user_data_list = analyze_user_data(account_id, account_alias, packaged_raw_user_data)

		print(f'Sending data for {num_users} users in {account_alias}({account_id}) to DynamoDB...')
		send_to_dynamodb(account_id, account_alias, processed_user_data_list, report_table)

	if mode == 'cleanup':
		# We will update the active table to the one we just created in mode a.
		swap_report_table(project_name, report_type)
