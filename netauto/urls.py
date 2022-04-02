from django.urls import include, path
from autonetapi import settings
from . import views
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from rest_framework import routers

# django rest routers
router = routers.DefaultRouter()
router.register(r'attacklog', views.AttackLogViewSet)
router.register(r'log', views.LogViewset)

urlpatterns = [
    # basic
    path('', views.home, name='home'),
    path('devices/', views.devices, name='devices'),
    path('add_ip/', views.add_ip, name='add_ip'),
    path('result/', views.show_config, name='result'),
    path('log/', views.log, name='log'),
    path('static_route/', views.static_route, name='static'),
    path('ospf/', views.ospf, name='ospf'),
    path('bgp/', views.bgp, name='bgp'),
    path('syslog/', views.syslog, name='syslog'),
    path('custom/', views.custom, name='custom'),
    # mitigation
    path('show/acl/', views.manage_acl_0, name='manage_acl_0'),
    path('show/acl/<str:router_id>/', views.manage_acl_1, name='manage_acl_1'),
    path('show/acl/<str:router_id>/_add/', views.manage_acl_1_add, name='manage_acl_1_add'),
    path('show/acl/<str:router_id>/<str:acl_id>/', views.manage_acl_2, name='manage_acl_2'),
    path('show/acl/<str:router_id>/<str:acl_id>/_delete/', views.manage_acl_2_delete, name='manage_acl_2_delete'),
    path('show/acl/<str:router_id>/<str:acl_id>/add_rule/', views.add_acl_rule, name='add_acl_rule'),
    path('show/acl/<str:router_id>/<str:acl_id>/add_interface/', views.add_acl_interface, name='add_acl_interface'),
    path('attacklog/', views.attacklog, name='attacklog'),
    # mitigation internal api endpoint
    path('api/', include(router.urls)),
    path('api/get_time/', views.get_time),
    #path('api/report/', views.mitigation_api),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    # detector
    path('detectors/', views.detectors, name='detectors'),
    path('login/', auth_views.LoginView.as_view(template_name="registration/login.html", redirect_authenticated_user=True), name='login'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
