from django.shortcuts import render

# Create your views here.
from django.template import loader
from django.http import HttpResponse

from dashboard.vars import *

import boto3
import json
import botocore
import datetime

def get_params(request):
	requested_tab = request.GET.get('tab', 'automations') #default to the automations tab
	params = {}
	params['requested_tab'] = requested_tab
	return params

def get_automation_list():
	automations = []
	try:
		session = boto3.Session(region_name=region)
		resource = session.resource('dynamodb')
		table = resource.Table(f'{project_name}-automations-metadata')
	except botocore.exceptions.ClientError as e:
		return 'failed'
	else:

		scan_kwargs = {}

		start_key = None
		while True:
			if start_key:
				scan_kwargs['ExclusiveStartKey'] = start_key
			response = table.scan(**scan_kwargs)
			if response.get('Items', {}):
				for automation in response['Items']:
					automation['status_color'] = '#fff'
					if automation['overall_status'] == 'OK':
						automation['status_color'] = '#00ff00'
					elif automation['overall_status'] == 'ERROR':
						automation['status_color'] = '#ff0000'
					elif automation['overall_status'] == 'RUNNING':
						automation['overall_status'] = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
						automation['status_color'] = '#04ffff'
					automations.append(automation)
			start_key = response.get('LastEvaluatedKey', None)
			if not start_key:
				break

	automations_sorted = sorted(automations, key=lambda k: k['automation_name']) #sort by name
	return automations_sorted

def get_report_list():
	reports = []
	try:
		session = boto3.Session(region_name=region)
		resource = session.resource('dynamodb')
		table = resource.Table(f'{project_name}-reports-metadata')
	except botocore.exceptions.ClientError as e:
		return 'failed'
	else:

		scan_kwargs = {}

		start_key = None
		while True:
			if start_key:
				scan_kwargs['ExclusiveStartKey'] = start_key
			response = table.scan(**scan_kwargs)
			if response.get('Items', {}):
				for report in response['Items']:
					report['status_color'] = '#fff'
					if report['overall_status'] == 'OK':
						report['status_color'] = '#00ff00'
					elif report['overall_status'] == 'ERROR':
						report['status_color'] = '#ff0000'
					elif report['overall_status'] == 'RUNNING':
						report['overall_status'] = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
						report['status_color'] = '#04ffff'
					reports.append(report)
			start_key = response.get('LastEvaluatedKey', None)
			if not start_key:
				break

	reports_sorted = sorted(reports, key=lambda k: k['report_name']) #sort by name
	return reports_sorted

def run_automation(automation_to_run):
	lambda_client = boto3.client('lambda', region_name=region)
	payload = {} # empty payload will start the 'master' logic for an automation
	payload_bytes = json.dumps(payload).encode('utf-8')
	try:
		response = lambda_client.invoke(
		    FunctionName=automation_to_run,
		    InvocationType='Event',
		    Payload=payload_bytes
		)
		print(f'Spawned lambda function for {automation_to_run}.')
		status = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
		status_color = '#04ffff'
	except Exception as e:
		print(e)
		status = f'INVOKE FAILED'
		status_color = '#ff0000'
	return status, status_color

def run_report(report_to_run):
	lambda_client = boto3.client('lambda', region_name=region)
	payload = {} # empty payload will start the 'master' logic for an automation
	payload_bytes = json.dumps(payload).encode('utf-8')
	try:
		response = lambda_client.invoke(
		    FunctionName=report_to_run,
		    InvocationType='Event',
		    Payload=payload_bytes
		)
		print(f'Spawned lambda function for {report_to_run}.')
		status = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
		status_color = '#04ffff'
	except Exception as e:
		print(e)
		status = f'INVOKE FAILED'
		status_color = '#ff0000'
	return status, status_color

def search(request):
	data = {'username':'','automations':[],'reports':[],'requested_tab':'automations'}

	# Validate user
	username = request.user.username.lower()
	is_admin = request.user.groups.filter(name='CloudAdmin').exists()
	is_engineer = request.user.groups.filter(name='CloudEngineer').exists()
	is_admin = True
	if is_admin:
		template = loader.get_template('admin.html')
		username = 'admin/' + username
	elif is_engineer:
		template = loader.get_template('engineer.html')
		username = 'engineer/' + username
	else:
		template = loader.get_template('user.html')
		username = 'user/' + username

	automations = get_automation_list()
	reports = get_report_list()
	data['username'] = username
	data['automations'] = automations
	data['reports'] = reports

	# Get selected tab if exists
	if request.method == 'GET' and request.GET.get('tab'):
		selected_tab = request.GET.get('tab')
		data['requested_tab'] = selected_tab

	# If the user is an admin and the request was POST
	if is_admin:
		params = get_params(request)
		if request.method == 'POST':
			# Run automation
			if request.POST.get('automation_to_run'):
				automation_to_run = request.POST.get('automation_to_run')

				# Call automation lambda function
				status, status_color = run_automation(automation_to_run)
				for automation in data['automations']:
					if automation['lambda_function_name'] == automation_to_run:
						automation['overall_status'] = status
						automation['status_color'] = status_color
				data['requested_tab'] = 'automations'
			
			# Run report
			if request.POST.get('report_to_run'):
				report_to_run = request.POST.get('report_to_run')

				# Call automation lambda function
				status, status_color = run_automation(report_to_run)
				for automation in data['reports']:
					if automation['lambda_function_name'] == report_to_run:
						automation['overall_status'] = status
						automation['status_color'] = status_color
				data['requested_tab'] = 'reports'

	return HttpResponse(template.render(data, request))