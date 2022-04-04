from django.shortcuts import render
from dashboard.vars import dashboard_domain

def custom_page_not_found_view(request, exception):
    return render(request, '404.html', {'dashboard_domain': dashboard_domain})

def custom_error_view(request, exception=None):
    return render(request, '500.html', {'dashboard_domain': dashboard_domain})

# def custom_permission_denied_view(request, exception=None):
#     return render(request, "templates/403.html", {})

# def custom_bad_request_view(request, exception=None):
#     return render(request, "templates/400.html", {})