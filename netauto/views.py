import django.contrib.auth
from django.core.handlers.wsgi import WSGIRequest
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
from django.utils.timezone import make_aware, make_naive
# from .forms import Scripts
from .models import Device, Log, Detector, AttackLog, ExecTime
import requests
import urllib3
import json
from datetime import datetime
from .decorators import superadmin_only
from asgiref.sync import async_to_sync, sync_to_async
import hashlib
import time
from timer import timer
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action, api_view
from rest_framework.views import APIView
#from rest_framework import permissions
from .serializers import AttackLogSerializer, LogSerializer
from .pycsrmgmt import api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


FILE_TYPE = ['txt', 'conf']


# Check if the user is superadmin or not.

def check_superadmin(request, *args, **kwargs):
    if request.user.groups.filter(name='superadmin').exists():
        return True
    else:
        return False


# Getting the token of the device

# --------------------------------------------
# - Functions / helpers / API endpoints
# --------------------------------------------

# Get time endpoint
@api_view(['GET'])
def get_time(request, format=None):
    x = datetime.now()
    return Response(x)

# Somehow I need one more API to input the detection system result for newer implementation.

class LogViewset(viewsets.ModelViewSet):
    queryset = Log.objects.all()
    serializer_class = LogSerializer

    def create(self, request):
        serializer = LogSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid() == True:
            # insert your parameters here
            action = serializer.data['action']
            stat = serializer.data['status']
            messages = serializer.data['messages']
            time = serializer.data['time']
            user = serializer.data['user']

            #time_convert = datetime.fromtimestamp(time)

            log = Log(target='System', action=action, status=stat, messages=messages, time=time, user=user)
            log.save()

            return Response({'status': 'valid'}, status=status.HTTP_200_OK)
        else:
            return Response({'status': 'invalid'}, status=status.HTTP_400_BAD_REQUEST)

# Attack logging
class AttackLogViewSet(viewsets.ModelViewSet):
    queryset = AttackLog.objects.all()
    serializer_class =  AttackLogSerializer

    # This is the alerting API
    def create(self, request):

        serializer = AttackLogSerializer(data=request.data)
        if serializer.is_valid() == True:
            
            detection_time = serializer.data['detection_time']
            attacker_ip = serializer.data['source_ip'] + "/32"
            victim_ip = serializer.data['dst_ip'] + "/32"
            victim_port = serializer.data['dst_port']
            protocol = serializer.data['conn_protocol']

            #dt_convert = datetime.fromtimestamp(detection_time)
            dt_convert = datetime.fromtimestamp(int(detection_time)) #.strptime("%m/%d/%Y %H:%M:%S.000000")
            dt_now = datetime.now()
            print(type(dt_now))
            print(type(dt_convert))
            print(detection_time)
            print(dt_convert)
            #print (detection_time)

            #print(victim_ip)

            # Default action taken when an attack was detected
            #block_action = 'block-single'
            block_action = 'block-ip-port'
            #print(block_action)

            # Hash encryption
            def encrypt_hash(hash_string):
                sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
                return sha_signature

            try:
                auto_devices = Device.objects.all().filter(auto_mitigate=True)
                attacker_list = AttackLog.objects.all().filter(source_ip=attacker_ip)
                victim_list = AttackLog.objects.all().filter(dst_ip=victim_ip)

                attacker_attempts = len(attacker_list) + 1

                # hash the epoch and ip addresses
                check_string = detection_time + "_" + attacker_ip + "_" + victim_ip
                hash_data = encrypt_hash(check_string)

                # here is the function for checking existing records
                attacklog_hash = AttackLog.objects.all().filter(hash_id=hash_data)

                #print(attacker_ip)

                # Logging function here
                def attack_logging():
                    log = AttackLog(hash_id=hash_data, time=datetime.now(), detection_time=dt_convert, source_ip=attacker_ip, dst_ip=victim_ip, dst_port=victim_port, conn_protocol=protocol, status=block_action)
                    log.save()
                    print('[notification] Log saved successfully.')

                def self_recover():
                    #time_wait = 15
                    #print('[notification] ' + '15' + ' sec await')
                    #time.sleep(15)
                    print('[warning] self-recover initiated')
                    for i in auto_devices:
                        try:
                            token = api.device(i.ip_address, i.username, i.password).token()
                            print('token is ' + token)
                            print(serializer.data['source_ip'])
                            unblock_acl = api.acl(i.ip_address, token).remove_existing_src_dst(i.default_acl_id, serializer.data['source_ip'], serializer.data['dst_ip'])
                        except:
                            pass

                # Main automatic mitigation function here
                def auto_mitigate_start():
                    #time_start_mitigate = time.time()
                    #time_mitigate = Timer()
                    #time_mitigate.start()
                    for i in auto_devices:
                        token = api.device(i.ip_address, i.username, i.password).token()
                        print('token is ' + token)
                        #token = get_token()
                        get_acl = api.acl(i.ip_address, token).get(i.default_acl_id)
                        json_data = json.loads(get_acl.replace("\"acl-id\":", "\"acl_id\":"))
                        acl_rule_id_list = []
                        acl_rule_src_list = []
                        if json_data['rules']:
                            for x in range(len(json_data['rules'])):
                                acl_rule_id_list.append(json_data['rules'][x]['sequence'])
                                acl_rule_src_list.append(json_data['rules'][x]['source'])

                        #print('[csr-api] if the attack successfully mitigated, then any output from api should appear here')
                        #print(block_with_acl)

                        # TODO replace this thing with something (i mean just receive)
                        
                        for ex in (list(range(30,1000))):
                            try:
                                if ex in acl_rule_id_list:
                                    pass
                                    #print('occupied')
                                else:
                                    if block_action == 'block-all':
                                        block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, 'all', attacker_ip, 'any', 'deny')
                                        #print('[csr-api] Reply from router: ')
                                        print (block_with_acl)
                                        break #return Response({'status': 'post'}, status=status.HTTP_200_OK)
                                    elif block_action == 'block-ip-port':
                                        if protocol.lower() == 'tcp' or 'udp':
                                            block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, protocol.lower(), attacker_ip, victim_ip, 'deny', dstop='eq',dstport=victim_port)
                                            print (block_with_acl)
                                            break# return Response({'status': 'post'}, status=status.HTTP_200_OK)      
                                        elif protocol == 'icmp':
                                            block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, 'icmp', attacker_ip, victim_ip, 'deny')
                                            #print('[csr-api] Reply from router: ')
                                            print (block_with_acl)
                                            break# return Response({'status': 'post'}, status=status.HTTP_200_OK)                                                                                  
                                    elif block_action == 'block-single':
                                        block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, 'all', attacker_ip, victim_ip, 'deny')
                                        #print('[csr-api] Reply from router: ')
                                        print (block_with_acl)
                                        break# return Response({'status': 'post'}, status=status.HTTP_200_OK)
                                    elif block_action == 'ignore':
                                        pass
                                        break
                                    else:
                                        break #pass
                                    break
                            except:
                                pass
                    
                    #time_mitigate.stop()
                    #print(time_mitigate)
                    #time_finish_mitigate = time.time()
                    #time_taken_mitigate = time_finish_mitigate - time_start_mitigate
                    #print("Time taken for mitigation : ", time_taken_mitigate)
                    print('blocked')
                        
                    if block_action != 'ignore':
                        pass
                        # log = AttackLog(hash_id=hash_data, time=datetime.now(), detection_time=dt_convert, source_ip=attacker_ip, dst_ip=victim_ip, dst_port=victim_port, status=block_action)
                        # log.save()
                    else:
                        pass
                    #return Response({'status': 'post'}, status=status.HTTP_200_OK)

                if len(attacklog_hash) >= 1:
                    return Response({'status': 'invalid'}, status=status.HTTP_400_BAD_REQUEST)
                    #respond = send_response("invalid")
                    #return respond
                else:
                    print("[alert] Attack detected: " + victim_ip, attacker_ip, block_action, detection_time)
                    attack_logging()
                    #asyncio.run(attack_logging())
                    #await asyncio.gather(auto_mitigate_start(), self_recover())
                    try:
                        time_start_mitigate = time.time()
                        auto_mitigate_start()
                        time_stop_mitigate = time.time()
                        time_elapsed_mitigate = time_stop_mitigate - time_start_mitigate
                        mitigate_log_time = ExecTime(time=time_elapsed_mitigate, exec_name='mitigation', comment=(attacker_ip, victim_ip))
                        mitigate_log_time.save()
                        print(time_elapsed_mitigate)
                    except:
                        pass
                    print("[DEBUG] If this is shown, the mitigation process should be finished.")
                    
                    # Self-healing / Self-recovery feature to reopen attacker connection
                    # To test whether the method is successful or not, i should disable this for good, at least for now
                    #print("[DEBUG] If this is shown, it should do the self recover after this.")
                    # try:
                    #     time.sleep(150)
                    #     time_start_recover = time.time()
                    #     self_recover()
                    #     time_stop_recover = time.time()
                    #     time_elapsed_recover = time_stop_recover - time_start_recover
                    #     recover_log_time = ExecTime(time=time_elapsed_recover, exec_name='recovery', comment=(attacker_ip, victim_ip))
                    #     recover_log_time.save()
                    #     print(time_elapsed_recover)
                    # except:
                    #     pass

                    return Response({'status': 'valid'}, status=status.HTTP_200_OK)

                    # asyncio.run(auto_mitigate_start())
                    # asyncio.run(self_recover())
                    #return Response({'status': 'post'}, status=status.HTTP_200_OK)
                return Response({'status': 'valid'}, status=status.HTTP_200_OK)
            except Exception as e:
                print('Error: ' + str(e))
                return Response({'status': 'error'}, status=status.HTTP_200_OK)

# --------------------------------------------
# - Start of the app views.
# --------------------------------------------

@login_required
def home(request):
    total_devices = Device.objects.all()
    last_event = Log.objects.all().order_by('-id')[:10]
    context = {
        'total_devices': len(total_devices),
        'last_event': last_event,
        'superadmin': check_superadmin(request),
    }

    return render(request, 'netauto/home.html', context)

# --------------------------------------------
# - Basic functions
# --------------------------------------------

@login_required
def devices(request):
    all_devices = Device.objects.all()

    context = {
        'all_devices': all_devices,
        'superadmin': check_superadmin(request),
    }
    return render(request, 'netauto/devices.html', context)


@login_required
@superadmin_only
def add_ip(request):
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                interface = request.POST['interface' + x]
                new_ip_addr = request.POST['ip_address' + x]
                new_subnetmask = request.POST['subnetmask' + x]

                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password)
                    headers = {'Content-Type': 'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def put_interface(token, interface):
                    url = 'https://%s:55443/api/v1/interfaces/%s' % (dev.ip_address, interface)
                    headers = {'Content-Type': 'application/json', 'X-auth-token': token}

                    payload = {
                        'type': 'ethernet',
                        'if-name': interface,
                        'ip-address': new_ip_addr,
                        'subnet-mask': new_subnetmask,
                        'description': 'Configured via AUTONETAPI'
                    }

                    response = requests.put(url, headers=headers, json=payload, verify=False)
                    if response.status_code >= 400:
                        message = json.loads(response.text)['error-message']
                    else:
                        message = 'Success'
                    return message

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Put new interface.
                put_interface(token, interface)
                if put_interface(token, interface) == "Success":
                    log = Log(target=dev.ip_address, action="Modify IP Address", status="Successful",
                              time=datetime.now(), user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Modify IP Address", status="Error", time=datetime.now(),
                              user=request.user.username, messages=put_interface(token, interface))
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Modify IP Address", status="Error", time=datetime.now(),
                          user=request.user.username,
                          messages="Failed establishing connection to device or requirements not match")
                log.save()
        return redirect('home')
    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/add_ip.html', context)


@login_required
@superadmin_only
def static_route(request):
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                dest_network = request.POST['dest' + x] + '/' + request.POST['prefix' + x]
                next_hop = request.POST['next_hop' + x]
                outinterface = request.POST['outinterface' + x]
                admin_distance = request.POST['admin_distance' + x]

                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password)
                    headers = {'Content-Type': 'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def post_static_route(token, outinterface):
                    url = 'https://%s:55443/api/v1/routing-svc/static-routes' % dev.ip_address
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-auth-token': token}
                    payload = {
                        "destination-network": dest_network,
                        "next-hop-router": next_hop,
                        "outgoing-interface": outinterface,
                        "admin-distance": int(admin_distance)
                    }
                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    if response.status_code >= 400:
                        message = json.loads(response.text)['error-message']
                    else:
                        message = 'Success'
                    return message

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Post static route.
                hasil = post_static_route(token, outinterface)

                if hasil == "Success":
                    log = Log(target=dev.ip_address, action="Add Static Route", status="Successful",
                              time=datetime.now(), user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Add Static Route", status="Error", time=datetime.now(),
                              user=request.user.username, messages=post_static_route(token, outinterface))
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Add Static Route", status="Error", time=datetime.now(),
                          user=request.user.username,
                          messages="Failed establishing connection to device or requirements not match")
                log.save()
        return redirect('home')


    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/static_route.html', context)


@login_required
@superadmin_only
def ospf(request):
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                ospf_process_id = request.POST['ospf_process_id' + x]
                network = request.POST['network' + x] + '/' + request.POST['prefix' + x]
                area = request.POST['area' + x]

                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password)
                    headers = {'Content-Type': 'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def create_ospf(token):
                    url = 'https://%s:55443/api/v1/routing-svc/ospf' % dev.ip_address
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-auth-token': token}
                    payload = {
                        "routing-protocol-id": ospf_process_id
                    }
                    response = requests.post(url, headers=headers, json=payload, verify=False)

                def post_ospf(token):
                    url = 'https://%s:55443/api/v1/routing-svc/ospf/%s/networks' % (dev.ip_address, ospf_process_id)
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-auth-token': token}
                    payload = {
                        "network": network,
                        "area": area
                    }
                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    if response.status_code >= 400:
                        message = json.loads(response.text)['error-message']
                    else:
                        message = 'Success'
                    return message

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Create OSPF Process ID
                create_ospf(token)

                # Post OSPF.
                hasil = post_ospf(token)
                if hasil == "Success":
                    log = Log(target=dev.ip_address, action="Add OSPF Route", status="Successful", time=datetime.now(),
                              user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Add OSPF Route", status="Error", time=datetime.now(),
                              user=request.user.username, messages=post_ospf(token))
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Add OSPF Route", status="Error", time=datetime.now(),
                          user=request.user.username,
                          messages="Failed establishing connection to device or requirements not match")
                log.save()

        return redirect('home')

    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/ospf.html', context)


@login_required
@superadmin_only
def bgp(request):
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                bgp_instance_id = request.POST['bgp_instance_id' + x]
                network = request.POST['network' + x] + '/32'

                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password)
                    headers = {'Content-Type': 'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def create_bgp(token):
                    url = 'https://%s:55443//api/v1/routing-svc/bgp' % dev.ip_address
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-auth-token': token}
                    payload = {
                        "routing-protocol-id": bgp_instance_id
                    }
                    response = requests.post(url, headers=headers, json=payload, verify=False)

                def post_bgp(token):
                    url = 'https://%s:55443/api/v1/routing-svc/bgp/%s/networks' % (dev.ip_address, bgp_instance_id)
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-auth-token': token}
                    payload = {
                        "network": network
                    }
                    response = requests.post(url, headers=headers, json=payload, verify=False)
                    if response.status_code >= 400:
                        message = json.loads(response.text)['error-message']
                    else:
                        message = 'Success'
                    return message

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Create BGP ASN
                create_bgp(token)

                # Post BGP.
                hasil = post_bgp(token)
                if hasil == "Success":
                    log = Log(target=dev.ip_address, action="Add BGP Route", status="Successful", time=datetime.now(),
                              user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Add BGP Route", status="Error", time=datetime.now(),
                              user=request.user.username, messages=post_bgp(token))
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Add BGP Route", status="Error", time=datetime.now(),
                          user=request.user.username,
                          messages="Failed establishing connection to device or requirements not match")
                log.save()

        return redirect('home')
    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/bgp.html', context)


@login_required
def show_config(request):
    if request.method == "POST":
        head = 'The Configuration Result'
        cisco_command = request.POST['cisco_command']
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                auth = (dev.username, dev.password)
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, auth=auth, headers=headers, verify=False)
                json_data = json.loads(response.text)
                token = json_data['token-id']
                return token

            def send_cli(token):
                url = 'https://%s:55443/api/v1/global/cli' % dev.ip_address
                headers = {'Content-Type': 'application/json', 'X-auth-token': token}
                payload = {
                    "exec": cisco_command
                }
                response = requests.put(url, headers=headers, json=payload, verify=False)
                json_data = json.loads(response.text)
                # print(json.dumps(json_data, indent=4, separators=(',', ': ')))
                if response.status_code >= 400:
                    return (json_data['detail'], 'gabisa')
                else:
                    return (json_data['results'], 'bisa')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            token = get_token()

            # Put the CLI Command
            send_cli(token)
            if send_cli(token)[1] == "bisa":
                log = Log(target=dev.ip_address, action="Validate Configuration", status="Successful",
                          time=datetime.now(), user=request.user.username, messages="No Error")
                log.save()
            else:
                log = Log(target=dev.ip_address, action="Validate Configuration", status="Error", time=datetime.now(),
                          user=request.user.username, messages="Invalid Cisco Command")
                log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Validate Configuration", status="Error", time=datetime.now(),
                      user=request.user.username,
                      messages="Failed establishing connection to device or requirements not match")
            log.save()
        context = {
            'head': head,
            'status': send_cli(token)[0],
        }
        return render(request, 'netauto/result.html', context)
    else:
        head = 'Validate your configuration'
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'head': head,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/validate.html', context)


@login_required
def syslog(request):
    if request.method == "POST":
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                auth = (dev.username, dev.password)
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, auth=auth, headers=headers, verify=False)
                json_data = json.loads(response.text)
                token = json_data['token-id']
                return token

            def get_syslog(token):
                url = 'https://%s:55443/api/v1/global/syslog' % dev.ip_address
                headers = {'Accept': 'application/json', 'X-auth-token': token}
                response = requests.get(url, headers=headers, verify=False)
                json_data = json.loads(response.text)
                syslog = json_data['messages']
                return syslog

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            token = get_token()

            get_syslog(token)
            log = Log(target=dev.ip_address, action="Export Syslog", status="Successful", time=datetime.now(),
                      user=request.user.username, messages="No Error")
            log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Export Syslog", status="Error", time=datetime.now(),
                      user=request.user.username,
                      messages="Failed establishing connection to device or requirements not match")
            log.save()

        filename_date = str(datetime.now())
        filename = "syslog_" + str(dev.ip_address) + "_" + filename_date + ".txt"
        content = get_syslog(token)
        response = HttpResponse(content, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename={0}'.format(filename)
        return response
    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/syslog.html', context)


@login_required
@superadmin_only
def custom(request):
    all_devices = Device.objects.all()
    if request.method == "POST" and request.FILES['myScript']:
        myScript = request.FILES['myScript']
        fs = FileSystemStorage()
        scriptName = fs.save(myScript.name, myScript)
        uploaded_file_url = fs.url(scriptName)
        file_type = uploaded_file_url.split('.')[-1]
        file_type = file_type.lower()
        if file_type not in FILE_TYPE:
            fs.delete(myScript.name)
            return render(request, 'netauto/500.html')
        else:
            with open(uploaded_file_url) as f:
                handler = f.read().strip()
            cisco_command = {
                'config': handler
            }
            selected_device_id = request.POST['router']
            dev = get_object_or_404(Device, pk=selected_device_id)
            try:
                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password)
                    headers = {'Content-Type': 'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def send_cli(token):
                    url = 'https://%s:55443/api/v1/global/cli' % dev.ip_address
                    headers = {'Content-Type': 'application/json', 'X-auth-token': token}
                    response = requests.put(url, headers=headers, json=cisco_command, verify=False)
                    json_data = json.loads(response.text)
                    # print(json.dumps(json_data, indent=4, separators=(',', ': ')))
                    if response.status_code >= 400:
                        return (json_data['detail'], 'gabisa')
                    else:
                        return ('bisa')

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Put the CLI Command
                send_cli(token)
                if send_cli(token) == "gabisa":
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Error", time=datetime.now(),
                              user=request.user.username, messages="Invalid Script")
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Successful",
                              time=datetime.now(), user=request.user.username, messages="No Error")
                    log.save()
            except Exception as e:
                error_false = "Expecting value: line 1 column 1 (char 0)"
                if error_false not in str(e):
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Error", time=datetime.now(),
                              user=request.user.username,
                              messages="Failed establishing connection to device or requirements not match")
                else:
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Successful",
                              time=datetime.now(), user=request.user.username, messages="No Error")
                log.save()

            fs.delete(myScript.name)
            return redirect('home')
    else:
        context = {
            'all_devices': all_devices,
            'superadmin': check_superadmin(request),
        }
        return render(request, 'netauto/custom.html', context)


# --------------------------------------------
# - Additional ACL Configuration
# --------------------------------------------

# Manage ACL - Device selection page
@login_required
def manage_acl_0(request):
    if request.method == "POST":
        head = 'List of registered ACL'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)

        return redirect('/show/acl/'+selected_device_id+'/')
        #return render(request, 'netauto/acl_table.html', context)
    else:
        head = 'Show ACL lists'
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'head' : head,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/device_select_acl.html', context)
    #return redirect()

# Manage ACL - ACL ID selection page
@login_required
def manage_acl_1(request, router_id):
    selected_device_id = router_id
    dev = get_object_or_404(Device, pk=selected_device_id)
    #selected_acl_id = acl_id
    #x = (dev)
    #return HttpResponse(x)
    if request.method == "POST":
        head = 'List of registered ACL'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get_all()
                json_data =json.loads(get_acl.replace("-id\":", "\"_id\":"))
                acl_id_list = []
                #acl_rule_list = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        acl_id_list.append(json_data['items'][x])
                        #acl_rule_list.append(json_data['items'][x]['rules'])
                    return ('bisa', acl_id_list)
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_acl_data(token)
            if get_acl_data(token)[0] == "bisa":
                pass
            else:
                pass
        except Exception as e:
            pass
        get_the_data = get_acl_data(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
        }
        #print(get_acl_data(token)[1])
        return redirect('/show/acl/'+selected_device_id+'/')
        #return render(request, 'netauto/acl_table.html', context)
    if request.method == "GET":
        head = 'List of registered ACL rule'
        selected_device_id = router_id
        router_name = dev.hostname
        #acl_select = get_object_or_404(AccessControlID, pk=selected_acl_id)
        #print(acl_select.objects.select_related)
        #dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get_all()
                json_data = json.loads(get_acl.replace("\"acl-id\":", "\"acl_id\":"))
                acl_id_list = []
                acl_rule_list = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        acl_id_list.append(json_data['items'][x])
                        acl_rule_list.append(json_data['items'][x]['rules'])
                    return ('bisa', acl_id_list, acl_rule_list)
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_acl_data(token)

        except Exception as e:
            pass
        token = get_token()
        get_the_data = get_acl_data(token)
        context = {
            'head' : head,
            'router_name': router_name,
            'acl_list' : get_the_data[1],
        }
        print(get_acl_data(token)[1])
        return render(request, 'netauto/acl_table.html', context)
    else:
        return redirect('/show/acl/')

# Manage ACL - Add ACL function
@login_required
def manage_acl_1_add(request, router_id):
    if request.method == "GET":
        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        token = api.device(dev.ip_address, dev.username, dev.password).token()
        add_acl = api.acl(dev.ip_address, token).create()

        return redirect('/show/acl/'+selected_device_id+'/')
        #post_data = json.loads(add_acl)
        #if 'error-code' in post_data:
        #    return redirect('/show/acl/')
        #else:
        #    return redirect('/show/acl/'+selected_device_id+'/')
    else:
        return redirect('/show/acl/')

def manage_acl_1_delete(request, router_id):
    if request.method == "POST":
        return redirect('/show/acl')
    elif request.method == "GET":
        pass # show selection page

# Manage ACL - Delete ACL rule page 
@login_required
def manage_acl_2(request, router_id, acl_id):

    if request.method == "POST":
        if 'delete' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            selected_rule = request.POST.getlist('acl_rule')
            print (request.POST)

            for x in selected_rule:    
                try:
                    dev = get_object_or_404(Device, pk=selected_device_id)

                    # get token
                    get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                    # delete acl rule
                    post_del_rules = api.acl(dev.ip_address, get_token).remove_existing(selected_acl_id, x)

                    # Put new interface.
                    if 'error-code' not in json.loads(post_del_rules):
                        log = Log(target=dev.ip_address, action="Delete ACL rule", status="Successful", time= datetime.now(), user=request.user.username, messages='No Error')
                        log.save()
                    else:
                        log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                        log.save()
                except Exception as e:
                    log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
                    log.save()
            return redirect('home')
        else:
            return redirect(request.META['HTTP_REFERER'])

    elif request.method == "GET":
        head = 'List of registered ACL rule'
        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        router_name = dev.hostname
        selected_acl_id = acl_id

        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get(selected_acl_id)
                json_data = json.loads(get_acl.replace("-", "_"))
                #acl_id_list = []
                acl_rule_list = []
                #acl_rule_list = json_data['rules']
                if 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                elif 'rules' in json_data:
                    for x in range(len(json_data['rules'])):
                        acl_rule_list.append(json_data['rules'][x])
                    return ('bisa', acl_rule_list)
                else:
                    return ('gabisa', 'null')
            def get_acl_interfaces(token):
                acl_int = api.acl(dev.ip_address, token).get_interfaces(selected_acl_id)
                json_data = json.loads(acl_int.replace("-id\":", "_id\":"))
                list_int = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        list_int.append(json_data['items'][x])
                    return ('bisa', list_int)
                elif 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_payload = get_acl_data(token)
            if get_payload[0] == "bisa":
                pass
            else:
                return redirect('manage_acl_1', selected_device_id)
        except Exception as e:
            pass
            #return redirect('manage_acl_0')
        token = get_token()
        get_the_data = get_acl_data(token)
        acl_int_payload = get_acl_interfaces(token)
        context = {
            'head' : head,
            'acl_id': acl_id,
            'router_name': router_name,
            'acl_list' : get_the_data[1],
            'int_list' : acl_int_payload[1]
        }
        print(get_acl_data(token)[1])
        #return render(request, 'netauto/acl_rules_table.html', context)
        return render(request, 'netauto/acl_rules_table_check.html', context)
    else:
        return redirect('delete_acl_rule_0')

    #selected_acl_rule = acl_rule
    #x = (dev, acl_id)
    #return HttpResponse(x)
    #return render(request, 'netauto/device_select_acl_rule.html', context)

@login_required
def manage_acl_2_delete(request, router_id, acl_id):

    if request.method == "POST":
        if 'delete' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            selected_rule = request.POST.getlist('acl_rule')
            print (request.POST)
   
            try:
                dev = get_object_or_404(Device, pk=selected_device_id)

                # get token
                get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                # delete acl rule
                #post_del_rules = api.acl(dev.ip_address, get_token).remove_existing(selected_acl_id, x)
                post_del_acl =  api.acl(dev.ip_address, get_token).delete(selected_acl_id)

                # Put new interface.
                if 'error-code' not in json.loads(post_del_acl):
                    log = Log(target=dev.ip_address, action="Delete ACL rule", status="Successful", time= datetime.now(), user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
                log.save()
            
            return redirect('home')
        else:
            selected_device_id = router_id
            selected_acl_id = acl_id
            return redirect('/show/acl/'+selected_device_id+'/'+selected_acl_id+'/')
            #return redirect(request.META['HTTP_REFERER'])
            

    elif request.method == "GET":
        head = 'Delete ACL ID'
        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        selected_acl_id = acl_id


         #return redirect('manage_acl_0')
        acl_id_name = acl_id
        context = {
            'head' : head,
            'acl_id' : acl_id_name,
        }
        #return render(request, 'netauto/acl_rules_table.html', context)
        return render(request, 'netauto/delete_acl_confirm.html', context)
    else:
        return redirect('delete_acl_rule_0')


# Manage ACL - Add ACL rule
@login_required
def add_acl_rule(request, router_id, acl_id):

    func_label = 'Add ACL rule'

    if request.method == "POST":
        if 'add' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            #selected_rule = request.POST.getlist('acl_rule')

            seqid = request.POST['acl_seq']
            source_ip = request.POST['source_ip']
            destination_ip = request.POST['dst_ip']
            acl_action = request.POST['acl_action']

            #print (request.POST)

            #for x in selected_rule:    
            try:
                dev = get_object_or_404(Device, pk=selected_device_id)

                # get token
                get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                # modify this: 
                # post_add_rules = api.acl(dev.ip_address, get_token).add_existing(selected_acl_id, acl_sequence, 'ip', source_ip, destination_ip, acl_action)
                post_add_rules = api.acl(dev.ip_address, get_token).add_existing(selected_acl_id, seqid, 'all', source_ip, destination_ip, acl_action)
                print(post_add_rules)

                # Evaluate the output.
                #if post_add_rules:
                log = Log(target=dev.ip_address, action=func_label, status="Successful", time= datetime.now(), user=request.user.username, messages='No Error')
                log.save()
                # else:
                #     log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                #     log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages="Exception caught: Failed establishing connection to device or requirements not match")
                log.save()
            return redirect('home')
        else:
            if len(request.META['HTTP_REFERER']) < 1:
                return redirect('manage_acl_0')
            else:
                return redirect(request.META['HTTP_REFERER'])

    # Show the page
    elif request.method == "GET":
        head = 'List of registered ACL rule'
        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        selected_acl_id = acl_id

        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get(selected_acl_id)
                json_data = json.loads(get_acl)
                #acl_id_list = []
                acl_rule_list = []
                #acl_rule_list = json_data['rules']
                if 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                elif 'rules' in json_data:
                    for x in range(len(json_data['rules'])):
                        acl_rule_list.append(json_data['rules'][x])
                    return ('bisa', acl_rule_list)
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_payload = get_acl_data(token)
            if get_payload[0] == "bisa":
                pass
            else:
                return redirect('manage_acl_1', selected_device_id)
        except Exception as e:
            pass
            #return redirect('manage_acl_0')
        token = get_token()
        get_the_data = get_acl_data(token)
        #acl_int_payload = get_acl_interfaces(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
        }
        #return render(request, 'netauto/acl_rules_table.html', context)
        return render(request, 'netauto/acl_rule_add.html', context)
    else:
        return redirect('delete_acl_rule_0')

# Manage ACL - Interface integration to ACL
def add_acl_interface(request, router_id, acl_id):
    func_label = 'Add ACL interface'

    if request.method == "POST":
        if 'add' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            # selected_interface = request.POST.getlist['acl_interface_list']

            acl_interface = request.POST['acl_interface']
            acl_direction = request.POST['acl_direction']

            #print (request.POST)
            # TODO: define add/remove action

                
            try:
                dev = get_object_or_404(Device, pk=selected_device_id)

                # get token
                get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                #get_token = "meong"
                # modify this: 
                # post_add_rules = api.acl(dev.ip_address, get_token).add_existing(selected_acl_id, acl_sequence, 'ip', source_ip, destination_ip, acl_action)
                # post_add_rules = api.acl(dev.ip_address, token).add_existing(selected_acl_id, seqid, 'all', source_ip, destination_ip, acl_action)

                post_add_int = api.acl(dev.ip_address, get_token).apply_acl_interface(selected_acl_id, acl_interface, acl_direction=acl_direction)

                # Evaluate the output.
                #if 'error-code' not in json.loads(post_add_int):
                try:
                    meong = json.loads(post_add_int)
                    if 'error-code' in meong:
                        log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                        log.save()
                        print(get_token)
                        print(post_add_int)
                except ValueError:
                    print(get_token)
                    print(post_add_int)
                    if post_add_int == 'success':
                        log = Log(target=dev.ip_address, action=func_label, status="Successful", time= datetime.now(), user=request.user.username, messages='Success')
                        log.save()
                    else:
                        log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                        log.save()
                    #print("x")
                
                #else:
                #    log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                #    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action=func_label, status="Error", time= datetime.now(), user=request.user.username, messages="Exception caught: Failed establishing connection to device or requirements not match")
                log.save()

            return redirect('home')
        elif 'delete' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            selected_interface = request.POST.getlist('acl_interface_list')

            #print (request.POST)
            for x in selected_interface:
                try:
                    dev = get_object_or_404(Device, pk=selected_device_id)

                    # get token
                    get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                    # modify this: 
                    post_del_int = api.acl(dev.ip_address, get_token).delete_acl_interface(selected_acl_id, x, acl_direction='both')

                    #print(selected_acl_id)
                    #print(x)
                    #print(post_del_int)
                                        
                    # Evaluate the output.
                    try:
                        meong = json.loads(post_del_int)
                        if 'error-code' in meong:
                            log = Log(target=dev.ip_address, action="Delete ACL Interface", status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                            log.save()
                    except ValueError:
                        if post_del_int == 'success':
                            log = Log(target=dev.ip_address, action="Delete ACL Interface", status="Successful", time= datetime.now(), user=request.user.username, messages='Success')
                            log.save()
                        else:
                            log = Log(target=dev.ip_address, action="Delete ACL Interface", status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                            log.save()
                except Exception as e:
                    log = Log(target=dev.ip_address, action="Delete ACL Interface", status="Error", time= datetime.now(), user=request.user.username, messages="Exception caught: Failed establishing connection to device or requirements not match")
                    log.save()
                return redirect('home')
        else:
            if len(request.META['HTTP_REFERER']) < 1:
                return redirect('manage_acl_0')
            else:
                return redirect(request.META['HTTP_REFERER'])

    # Show the page
    elif request.method == "GET":
        head = 'List of registered ACL interfaces'

        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        selected_acl_id = acl_id

        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_interfaces(token):
                acl_int = api.acl(dev.ip_address, token).get_interfaces(selected_acl_id)
                json_data = json.loads(acl_int.replace("-id\":", "_id\":"))
                list_int = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        list_int.append(json_data['items'][x])
                    return ('bisa', list_int)
                elif 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_payload = get_acl_interfaces(token)
            if get_payload[0] == "bisa":
                pass
            else:
                pass
                # return redirect('manage_acl_1', selected_device_id)
        except Exception as e:
            pass

        context = {
            'head' : head,
            'int_list' : get_payload[1],
        }

        return render(request, 'netauto/acl_interface_config.html', context)
    else:
        return redirect('delete_acl_rule_0')

@login_required
def attacklog(request):
    logs = AttackLog.objects.all().order_by('-id')
    context = {
        'logs': logs,
        'superadmin' : check_superadmin(request),
    }
    return render(request, 'netauto/log_attack.html', context)

# --------------------------------------------
# - Detector
# --------------------------------------------

@login_required
def detectors(request: WSGIRequest):
    all_detectors = Detector.objects.all()

    context = {
        'all_detectors': all_detectors,
        'superadmin': check_superadmin(request),
    }
    return render(request, 'netauto/detectors.html', context)


@login_required
def log(request):
    logs = Log.objects.all().order_by('-id')
    context = {
        'logs': logs,
        'superadmin': check_superadmin(request),
    }
    return render(request, 'netauto/log.html', context)


def handler403(request):
    return render(request, 'netauto/403.html')


def handler404(request, exception):
    return render(request, 'netauto/404.html')


def handler500(request):
    print(request)
    return render(request, 'netauto/500.html')
