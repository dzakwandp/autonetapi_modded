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

def do_report():
    time_now = int(time.time())
    report('10.225.50.11', '10.50.10.11', '80', 'tcp', time_now, report_url="http://localhost:8000/api/attacklog/")

#schedule.every(1).seconds.do(attack_detection)

while True:
    try:
        do_report()
        time.sleep(40)
    except KeyboardInterrupt:
        sys.exit(0)
