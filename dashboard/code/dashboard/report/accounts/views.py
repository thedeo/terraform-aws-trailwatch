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

from boto3.dynamodb.conditions import Key, Attr

report_type = 'account'

def get_params(request):
    
    account_id = request.GET.get('account_id')

    params = {}
    params['account_id'] = account_id
    
    return params

def get_items(params):
    report_table  = get_report_table(report_type)
    try:    
        last_run_date = get_step_function_status(report_type)['stopDate'].isoformat()
    except Exception as e:
        last_run_date = "None"
    accounts = []
    try:
        session = boto3.Session(region_name=region)
        resource = session.resource('dynamodb')
        table = resource.Table(report_table)
    except botocore.exceptions.ClientError as e:
        return 'failed'
    else:

        scan_kwargs = {}

        # If the account_id was passed as an argument, only pull back that accounts records.
        account_id = params['account_id']
        if account_id:
            account_filter = Attr('account_id').eq(account_id)
            scan_kwargs['FilterExpression'] = account_filter

        start_key = None
        while True:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = table.scan(**scan_kwargs)
            if response.get('Items', {}):
                for account in response['Items']:
                    accounts.append(account)
            start_key = response.get('LastEvaluatedKey', None)
            if not start_key:
                break

    account_count = len(accounts)

    return accounts, account_count, last_run_date

def search(request):
    template = loader.get_template('accounts.html')

    # Validate user
    if request.user.get_username():
        username = request.user.username.lower()
    else:
        username = 'none'
        #groups = request.user.groups
        #is_admin = user.groups.filter(name='CloudAdmin').exists()
    # if not is_admin:
    #     return render(request, '404.html', {})

    params = get_params(request)
    accounts, account_count, last_run_date = get_items(params)
    data = {
        'data': accounts, 
        'params': params, 
        'account_count': account_count, 
        'last_run_date': last_run_date, 
        'username': username, 
        'project_name': project_name,
        'static_files_domain': static_files_domain
    }

    return HttpResponse(template.render(data, request))

