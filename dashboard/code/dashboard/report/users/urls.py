from django.conf.urls import url
from report.users import views

urlpatterns = [
	url(r'^users/?', views.search, name='report'),
]