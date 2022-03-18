from django.shortcuts import render

# Create your views here.
from django.template import loader
from django.http import HttpResponse

from dashboard.vars import *

import boto3
import json
import botocore
import datetime

from boto3.dynamodb.conditions import Key, Attr

def get_params(request):
    
    account_id = request.GET.get('account_id')

    params = {}
    params['account_id'] = account_id
    
    return params

def get_report_metadata():

    dynamodb = boto3.client('dynamodb', region_name=region)

    key = {}
    key.setdefault('report_name', {})['S'] = 'SecurityGroup'

    try:
        response = dynamodb.get_item(TableName=f'{project_name}-reports-metadata', Key=key)
        last_run_date = response['Item']['last_run_date']['S']
    except Exception as e:
        print(e)
        exit(1)

    return last_run_date


def get_items(params):
    rules = []
    try:
        session = boto3.Session(region_name=region)
        resource = session.resource('dynamodb')
        table = resource.Table(f'{project_name}-sg-report')
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
                for rule in response['Items']:
                    rules.append(rule)
            start_key = response.get('LastEvaluatedKey', None)
            if not start_key:
                break

    rule_count = len(rules)

    return rules, rule_count

def search(request):
    template = loader.get_template('securitygroups.html')

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
    last_run_date = get_report_metadata()
    rules, rule_count = get_items(params)
    data = {
        'data': rules, 
        'params': params, 
        'rule_count': rule_count, 
        'last_run_date': last_run_date, 
        'username': username, 
        'project_name': project_name,
        'static_files_domain': static_files_domain
    }

    return HttpResponse(template.render(data, request))

