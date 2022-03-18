from django.conf.urls import url
from report.accounts import views

urlpatterns = [
	url(r'^accounts/?', views.search, name='report'),
]