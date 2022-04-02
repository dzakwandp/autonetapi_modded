import requests
from datetime import datetime


def report(source_ip, dst_ip, dst_port, conn_protocol, detection_time, report_url="http://localhost:8000/api/attacklog/"):
    #sleep (0.5)
    try:
        return requests.post(url=report_url, timeout=0.001, json={
            'source_ip': source_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'conn_protocol': conn_protocol.lower(),
            'detection_time': detection_time
        })
    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        print(e)
        #print("[WARNING] Timeout exceeded.")

def detection_log(time, action, status, messages, user, report_url="http://localhost:8000/api/log/"):
    #sleep (0.5)
    try:
        return requests.post(url=report_url, timeout=0.001, json={
            'action': action,
            'status': status,
            'messages': messages,
            'time': time,
            'user': "Anonymous"
        })
    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        print(e)
        #print("[WARNING] Timeout exceeded.")
