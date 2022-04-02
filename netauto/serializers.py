from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import Device, AttackLog, Log

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']

class DeviceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Device
        fields = ['ip_address', 'hostname']

class AttackLogSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = AttackLog
        fields = [ 'detection_time', 'source_ip', 'dst_ip', 'dst_port', 'conn_protocol']

class LogSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Log
        fields = ['action', 'status', 'messages', 'time', 'user']

#target = models.CharField(max_length=200)
#action = models.CharField(max_length=200)
#status = models.CharField(max_length=200)
#messages = models.CharField(max_length=255, blank=True)
#time = models.DateTimeField(null=True)
#user = models.CharField(max_length=200, default='Anonymous')

# class AttackLogSerializer(serializers.HyperlinkedModelSerializer):
#     class Meta:
#         model = AttackLog
#         fields = ['']
