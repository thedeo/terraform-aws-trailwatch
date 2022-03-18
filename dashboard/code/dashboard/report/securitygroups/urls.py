from django.conf.urls import url
from report.securitygroups import views

urlpatterns = [
	url(r'^security-groups/?', views.search, name='report'),
]