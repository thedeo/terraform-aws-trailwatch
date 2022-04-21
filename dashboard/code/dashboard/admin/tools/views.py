from django.shortcuts import render

# Create your views here.
from django.template import loader
from django.http import HttpResponse

from dashboard.vars import *
from dashboard.aws_functions import get_report_table
from dashboard.aws_functions import get_step_function_status

import boto3
import json
import botocore
import datetime

def get_params(request):
	requested_tab = request.GET.get('tab', 'reports') #default to the automations tab
	params = {}
	params['requested_tab'] = requested_tab
	return params

def get_report_list():
	reports = {}
	try:
		session = boto3.Session(region_name=region)
		resource = session.resource('dynamodb')
		table = resource.Table(f'{project_name}-report-active-tables')
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
					report_type = report['report_type']
					reports[report_type] = {
						'report_name': f'{project_name}-report-{report_type}',
						'report_arn': f'arn:aws:states:{region}:{account_id}:stateMachine:{project_name}-report-{report_type}'
						}
			start_key = response.get('LastEvaluatedKey', None)
			if not start_key:
				break

		for report_type in reports.keys():
			try:
				stepfunctions = boto3.client('stepfunctions', region_name=region)
				response = stepfunctions.list_executions(stateMachineArn=reports[report_type]['report_arn'], maxResults=1)
			except Exception as e:
				print(f'Could not list_executions for {report_type} report.')
				print(e)
				exit(1)

			reports[report_type]['report_status'] = response['executions'][0]['status']
			# Stop date which is used for knowing the last run time
			# will not be available if the execution is in running status.
			# This logic will handle that scenario.
			stop_date_obj = response['executions'][0].get('stopDate', '')
			if stop_date_obj:
				stop_date = stop_date_obj.isoformat()
			else:
				stop_date = '-'
			reports[report_type]['report_stop_date'] = stop_date

			# Set values to modify styling based on status
			reports[report_type]['report_status_color'] = '#fff'
			if reports[report_type]['report_status'] == 'SUCCEEDED':
				reports[report_type]['report_status_color'] = '#00ff00'
				reports[report_type]['report_status_html']  = reports[report_type]['report_status']
			elif reports[report_type]['report_status'] in ['FAILED','TIMED_OUT','ABORTED']:
				reports[report_type]['report_status_color'] = '#ff0000'
				reports[report_type]['report_status_html']  = reports[report_type]['report_status']
			elif reports[report_type]['report_status'] == 'RUNNING':
				reports[report_type]['report_status_html']  = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
				reports[report_type]['report_status_color'] = '#04ffff'

	return reports

def run_report(report_type, report_arn):
	stepfunctions = boto3.client('stepfunctions', region_name=region)
	payload       = {} # empty payload will start the 'master' logic for an automation
	payload_bytes = json.dumps(payload).encode('utf-8')
	timestamp     = datetime.datetime.now().timestamp()
	try:
		response = stepfunctions.start_execution(
			stateMachineArn=report_arn,
			name=f'manual-execution-{timestamp}',
			input='{}'
		)
		print(f'Spawned state machine execution for {report_arn}.')
		status = '<i class="fa fa-gear fa-spin" style="font-size:14px;color:#00ff00;"></i> RUNNING'
		status_color = '#04ffff'
	except Exception as e:
		print(e)
		status       = f'INVOKE FAILED'
		status_color = '#ff0000'
	return status, status_color

def search(request):
	template 			 		= loader.get_template('admin.html')
	data                 		= {'reports':{},'requested_tab':'reports'}
	reports              		= get_report_list()
	data['reports']      		= reports
	data['project_name'] 		= project_name
	data['static_files_domain'] = static_files_domain

	# Get selected tab if exists
	if request.method == 'GET' and request.GET.get('tab'):
		selected_tab          = request.GET.get('tab')
		data['requested_tab'] = selected_tab

	params = get_params(request)
	if request.method == 'POST':

		# Run report
		if request.POST.get('report_type'):
			report_type = request.POST.get('report_type')

			if data['reports'][report_type]['report_status'] != 'RUNNING':
				# Call automation lambda function
				report_arn = data['reports'][report_type]['report_arn']
				status, status_color = run_report(report_type, report_arn)
				data['reports'][report_type]['report_status_html']  = status
				data['reports'][report_type]['report_status_color'] = status_color
				data['requested_tab']                               = 'reports'

	return HttpResponse(template.render(data, request))