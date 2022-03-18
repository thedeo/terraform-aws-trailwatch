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
    
    start = request.GET.get('start')
    end   = request.GET.get('end')

    # Set default timestamp if none provided in URI
    if start == None or start == '' or end == None or end == '' :
        # Get current time.
        now = datetime.datetime.utcnow()
        one_hour_ago = now - datetime.timedelta(hours=1)
        start = one_hour_ago.strftime('%FT%TZ')
        end   = now.strftime('%FT%TZ')

    params = {}
    params['start'] = start
    params['end'] = end
    
    return params

def get_events(params):
    events = []
    try:
        session = boto3.Session(region_name=region)
        resource = session.resource('dynamodb')
        table = resource.Table(f'{project_name}-events')
    except botocore.exceptions.ClientError as e:
        return 'failed'
    else:
        start = params['start']
        end   = params['end']
        date_range = Key('event_time').between(start,end)

        scan_kwargs = {
            'FilterExpression': date_range
        }

        start_key = None
        while True:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = table.scan(**scan_kwargs)
            if response.get('Items', {}):
                for event in response['Items']:
                    events.append(event)
            start_key = response.get('LastEvaluatedKey', None)
            if not start_key:
                break

    event_count = len(events)

    return events, event_count

def search(request):
    template = loader.get_template('events.html')

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
    events, event_count = get_events(params)
    data = {
        'data': events, 
        'params': params, 
        'event_count': event_count, 
        'username': username, 
        'project_name': project_name,
        'dashboard_domain': dashboard_domain,
        'static_files_domain': static_files_domain
    }

    return HttpResponse(template.render(data, request))

