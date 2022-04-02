import requests


def report_api(source_ip, dst_ip, dst_port, conn_protocol, detection_time, report_url="http://localhost:8000/api/attacklog/"):
    #sleep (0.5)
    try:
        return requests.post(url=report_url, timeout=0.001, json={
            'source_ip': source_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'conn_protocol': conn_protocol,
            'detection_time': detection_time
        })
    except requests.exceptions.Timeout:
        pass
