from django.conf.urls import url
from report.amis import views

urlpatterns = [
	url(r'^amis/?', views.search, name='amis'),
]