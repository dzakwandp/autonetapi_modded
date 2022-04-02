import requests
import time

def report(source_ip, dst_ip, dst_port, conn_protocol, detection_time, report_url="http://localhost:8000/api/attacklog/"):
    #time_now = int(time.time())
    #sleep (0.5)
    try:
        return requests.post(url=report_url, timeout=1.5, json={
            'source_ip': source_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'conn_protocol': conn_protocol,
            'detection_time': detection_time})
    except requests.exceptions.Timeout:
        pass

source_ip = '10.225.50.11'
dst_ip = '10.50.10.11'
dst_port = '2048'
protocol = 'icmp'

print("Source IP: ", source_ip)
print("Destination IP: ", dst_ip)
print("Destination port: ", dst_port)
print("Protocol: ", protocol)

time_now = int(time.time())
report(source_ip, dst_ip, dst_port, protocol, time_now, report_url="http://localhost:8000/api/attacklog/")
