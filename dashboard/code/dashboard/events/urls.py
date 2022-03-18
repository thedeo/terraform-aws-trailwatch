from django.conf.urls import url
from events import views

urlpatterns = [
	url('', views.search, name='events'),
]