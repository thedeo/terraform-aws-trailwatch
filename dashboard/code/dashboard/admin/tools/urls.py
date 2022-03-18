from django.conf.urls import url
from admin.tools import views

urlpatterns = [
	url('', views.search, name='tools'),
]