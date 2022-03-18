from django.shortcuts import render

# Create your views here.
from django.template import loader
from django.http import HttpResponse

from dashboard.vars import *

def search(request):
	template = loader.get_template('home.html')
	
	# Validate user
	if request.user.get_username():
		username = request.user.username.lower()
	else:
		username = 'none'
		groups = ''
		#is_admin = request.user.groups.filter(name='CloudAdmin').exists()
	# if not is_admin:
	# 	return render(request, '404.html', {})
	data = {
		'username': username, 
		'groups': groups, 
		'project_name': project_name,
		'static_files_domain': static_files_domain
	}

	return HttpResponse(template.render(data, request))

