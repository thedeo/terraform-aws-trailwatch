from django.conf.urls import url
from menu.home import views

urlpatterns = [
	url('', views.search, name='home'),
]