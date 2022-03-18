"""dashboard URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path, include

handler404 = 'dashboard.views.custom_page_not_found_view'
handler500 = 'dashboard.views.custom_error_view'
# handler403 = 'dashboard.views.custom_permission_denied_view'
# handler400 = 'dashboard.views.custom_bad_request_view'

urlpatterns = [
    # path('oauth2/', include('django_auth_adfs.urls')),
    #path('admin/', admin.site.urls),
    path('admin-tools', include('admin.tools.urls')),
    path('events/', include('events.urls')),
    path('report/', include('report.users.urls')),
    path('report/', include('report.securitygroups.urls')),
    path('report/', include('report.accounts.urls')),
    path('report/', include('report.amis.urls')),
    path('healthcheck/', include('healthcheck.urls')),
    path('', include('menu.home.urls')),
]
