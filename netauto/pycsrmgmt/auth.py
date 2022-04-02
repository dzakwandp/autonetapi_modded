import requests
import json

class device():
    def __init__(self, router_ip, username, password):
        self.router_ip = router_ip
        self.username = username
        self.password = password

    def token(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/auth/token-services"
        api_auth = (self.username, self.password)
        api_headers = {'Content-Type':'application/json'}
        try:
            get_token = requests.post(url=api_url, auth=api_auth, headers=api_headers, verify=False)
            if get_token.status_code == 200:
                token_data = json.loads(get_token.text)['token-id']
                return token_data
        except get_token.status_code != 200:
            if get_token.status_code == 401:
                message = "401-error"
                #return message
            elif get_token.status_code != 200:
                message = "connection-error"
                #return message

