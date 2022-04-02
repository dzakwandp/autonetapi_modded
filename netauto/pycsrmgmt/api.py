import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class device(object):
    def __init__(self, router_ip, username, password):
        self.router_ip = router_ip
        self.username = username
        self.password = password

# Get authentication token
# Returns token
    def token(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/auth/token-services"
        api_auth = (self.username, self.password)
        api_headers = {'Content-Type':'application/json'}
        try:
            get_token = requests.post(url=api_url, auth=api_auth, headers=api_headers, verify=False, timeout=10)
            if get_token.status_code == 200:
                token_data = json.loads(get_token.text)['token-id']
                return token_data
        except get_token.status_code != 200:
            if get_token.status_code == 401:
                message = "401-error"
                return message
            elif get_token.status_code != 200:
                message = "connection-error"
                return message


class acl(device):
    def __init__(self, router_ip, router_token):
        #device.__init__(self, router_ip)
        self.router_ip = router_ip
        self.router_token = router_token
        # self.router_port = router_port

    # Get ACL data by id
    def get(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_get = acl_get.text
        return output_acl_get

    # Get all ACL data
    def get_all(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl" 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_get_all = acl_get.text
        return output_acl_get_all

    # Get interfaces associated with ACL ID
    def get_interfaces(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id + "/interfaces" 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_get_all = acl_get.text
        return output_acl_get_all

    # Apply an ACL into an interface
    def apply_acl_interface(self, acl_id, acl_interface, acl_direction='inside'):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id + "/interfaces" 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        #acl_get = print(api_url, api_headers)
        payload = {
            "if-id": acl_interface,
            "direction": acl_direction
        }
        acl_apply = requests.post(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_acl_apply = acl_apply.text
        if acl_apply.status_code == 201:
            message = 'success'
            return message
        elif acl_apply.status_code !=201:
            return output_acl_apply

    # Remove an ACL associated with an interface 
    def delete_acl_interface(self, acl_id, acl_interface, acl_direction='both'):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id + "/interfaces/" + acl_interface + "_" + acl_direction 
        api_headers = { 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        #acl_get = print(api_url, api_headers)
        print(api_url)
        acl_apply = requests.delete(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_apply = acl_apply.text
        if acl_apply.status_code == 204:
            message = 'success'
            return message
        elif acl_apply.status_code != 204:
            return output_acl_apply

    # Get ACL statistics by ID/name
    def get_statistic(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/statistics/" + acl_id 
        api_headers = { 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_get_stat = acl_get.text
        return output_acl_get_stat

    # Get all ACL statistics
    def get_statistic_all(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/statistics" 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_get_stat_all = acl_get.text
        return output_acl_get_stat_all

    # Create an empty ACL
    def create(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        payload = {
            "kind": "object#acl",
            "rules": []
            }
        acl_config = requests.post(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        if acl_config.status_code == 200 :
            output_acl_config = acl_config.text
            return output_acl_config
        else:
            message = 'error'
            return message

    # Configure a new ACL with a rule
    def configure(self, acl_sequence, acl_protocol, acl_src_ip, acl_dst_ip, acl_action, srcport='', srcop='eq', srcport_end='', dstport='eq', dstop='',  dstport_end=''):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        new_rule = {
                        "sequence" : acl_sequence,
                        "protocol": acl_protocol,
                        "source": acl_src_ip,
                        "destination": acl_dst_ip,
                        "action": acl_action,
        }

        srcport_options = {
            "src-port-start" : srcport,
            "src-port-op" : srcop,
        }

        srcport_end_options = {
            "src-port-end" : srcport_end,
        }

        dstport_options = {
            "dest-port-start" : dstport,
            "dest-port-op" : dstop
        }

        dstport_end_options = {
            "dest-port-end" : dstport_end,
        }

        option_payload = {}
        
        port_payload = { "l4-options" : option_payload }

        if acl_protocol == "tcp" or acl_protocol == "udp":
            if len(srcport) >= 1:
                if srcop == "eq" or srcop == "gt" or srcop == "lt":
                    option_payload.update(srcport_options)
                    new_rule.update(port_payload)
                elif srcop == "range":
                    if len(srcport_end) < 1:
                        srcop = "eq"
                        option_payload.update(srcport_options)
                        new_rule.update(port_payload)
                    elif len(srcport_end) >= 1:
                        option_payload.update(srcport_options)
                        option_payload.update(srcport_end_options)
                        new_rule.update(port_payload)

            elif len(srcport) < 1:
                pass

            if len(dstport) >= 1:
                if dstop == "eq" or dstop == "gt" or dstop == "lt":
                    option_payload.update(dstport_options)
                    new_rule.update(port_payload)
                elif dstop == "range":
                    if len(dstport_end) < 1 :
                        dstop = "eq"
                        option_payload.update(dstport_options)
                        new_rule.update(port_payload)
                    elif len(dstport_end) >= 1 :
                        option_payload.update(dstport_options)
                        option_payload.update(dstport_end_options)
                        new_rule.update(port_payload)
            elif len(dstport) < 1 :
                pass

        else:
            pass

        payload = {
            "kind": "object#acl",
            "rules": [
                new_rule
                ]
            }
        acl_config = requests.post(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        if acl_config.status_code == 200 :
            output_acl_config = acl_config.text
            return output_acl_config
        else:
            message = 'error'
            return message

    # work in progress, needs to add append function
    # Add a rule into an existing ACL 
    def add_existing(self, acl_id, acl_sequence, acl_protocol, acl_src_ip, acl_dst_ip, acl_action, srcport='', srcop='eq', srcport_end='', dstport='', dstop='eq',  dstport_end=''):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        existing_rules = json.loads(acl_get.text)['rules']
        #existing_rules.append(payload)
        new_rule = {
                        "sequence" : acl_sequence,
                        "protocol": acl_protocol,
                        "source": acl_src_ip,
                        "destination": acl_dst_ip,
                        "action": acl_action,
        }

        srcport_options = {
            "src-port-start" : srcport,
            "src-port-op" : srcop,
        }

        srcport_end_options = {
            "src-port-end" : srcport_end,
        }

        dstport_options = {
            "dest-port-start" : dstport,
            "dest-port-op" : dstop
        }

        dstport_end_options = {
            "dest-port-end" : dstport_end,
        }

        option_payload = {}
        
        port_payload = { "l4-options" : option_payload }

        if acl_protocol == "tcp" or acl_protocol == "udp":
            if len(srcport) >= 1:
                if srcop == "eq" or srcop == "gt" or srcop == "lt":
                    option_payload.update(srcport_options)
                    new_rule.update(port_payload)
                elif srcop == "range":
                    if len(srcport_end) < 1:
                        srcop = "eq"
                        option_payload.update(srcport_options)
                        new_rule.update(port_payload)
                    elif len(srcport_end) >= 1:
                        option_payload.update(srcport_options)
                        option_payload.update(srcport_end_options)
                        new_rule.update(port_payload)

            elif len(srcport) < 1:
                pass

            if len(dstport) >= 1:
                if dstop == "eq" or dstop == "gt" or dstop == "lt":
                    option_payload.update(dstport_options)
                    new_rule.update(port_payload)
                elif dstop == "range":
                    if len(dstport_end) < 1 :
                        dstop = "eq"
                        option_payload.update(dstport_options)
                        new_rule.update(port_payload)
                    elif len(dstport_end) >= 1 :
                        option_payload.update(dstport_options)
                        option_payload.update(dstport_end_options)
                        new_rule.update(port_payload)
            elif len(dstport) < 1 :
                pass

            existing_rules.append(new_rule)
        else:
            existing_rules.append(new_rule)

        payload = {
            "kind": "object#acl",
            "rules": existing_rules
            }

        #x=json.dumps(payload)
        # print (payload)
        #print(x)

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_acl_config = acl_config.text
        return output_acl_config

    # Remove existing rule from an ACL
    def remove_existing(self, acl_id, acl_sequence):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        # full_response = json.loads(acl_get.text)
        existing_rules = json.loads(acl_get.text)['rules']

        new_rule = [x for x in existing_rules if not (int(acl_sequence) == x.get('sequence'))]  
        print(new_rule)
        print(len(new_rule))

        print(len(existing_rules))

        payload = {
            "kind": "object#acl",
            "rules": new_rule
            }

        #x=json.dumps(payload)
        #print ('here is your payload')
        #print (x)
        #print(x)
        #print(payload)

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_acl_config = acl_config.text
        return output_acl_config

    # Remove existing rule related with source IP from an ACL associated with ID
    def remove_existing_srcip(self, acl_id, acl_src_ip):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        # full_response = json.loads(acl_get.text)
        existing_rules = json.loads(acl_get.text)['rules']

        new_rule = [x for x in existing_rules if not (acl_src_ip == x.get('source'))]  
        # print(new_rule)
        # print(len(new_rule))
        # print(len(existing_rules))

        payload = {
            "kind": "object#acl",
            "rules": new_rule
            }

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_acl_config = acl_config.text
        return output_acl_config

    def remove_existing_src_dst(self, acl_id, acl_src_ip, acl_dst_ip):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        # full_response = json.loads(acl_get.text)
        existing_rules = json.loads(acl_get.text)['rules']

        new_rule_a = [x for x in existing_rules if not (acl_src_ip == x.get('source'))]
        new_rule_b = [x for x in new_rule_a if not (acl_dst_ip == x.get('destination'))]
        # print(new_rule)
        # print(len(new_rule))
        # print(len(existing_rules))

        payload = {
            "kind": "object#acl",
            "rules": new_rule_b
            }

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_acl_config = acl_config.text
        return output_acl_config
   
   # Delete an ACL
    def delete(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        acl_del = requests.delete(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_acl_del = acl_del.text
        return output_acl_del

    # def assign_acl_interface(self, acl_id, acl_interface, acl_direction):
    #     api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id + "/interfaces"
    #     api_headers = { 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
    #     payload = {
    #         "if-id": acl_interface,
    #         "direction": acl)
    #     }
    #     acl_assign = requests.post(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
    #     print('x')


class interface(device):
    def __init__(self, router_ip, router_token):
        self.router_ip = router_ip
        self.router_token = router_token

    def get_all(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/interfaces"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        int_get = requests.get(url=api_url, headers=api_headers, verify=False, timeout=10)
        output_int_get_all = int_get.text
        return output_int_get_all

    def create(self, router_interface_type, router_interface, interface_ip_address, interface_netmask, interface_status='true', description='', interface_nat_direction=''):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/interfaces/" + router_interface
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        nat_payload = { "nat-direction": interface_nat_direction }
        payload = {
            "type" : router_interface_type,
            "if-name": router_interface,
            "description": description,
            "ip-address": interface_ip_address,
            "subnet-mask": interface_netmask,
            "enabled": interface_status
        }

        if interface_nat_direction >= 1:
            payload.update(nat_payload)

        int_create = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output = int_create.text
        if int_create.status_code == 201:
            message = 'success'
        else:
            message = output
        return message


    # configure interface
    # basic functions only
    def configure(self, router_interface, interface_ip_address, interface_netmask, interface_status='true', interface_type='ethernet'):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/interfaces/" + router_interface
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        payload = {
            "type" : interface_type,
            "if-name": router_interface,
            "ip-address": interface_ip_address,
            "subnet-mask": interface_netmask,
            "enabled": interface_status
        }
        int_conf = requests.post(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output = int_conf.text
        if int_conf.status_code == 201:
            message = 'success'
        else:
            message = output
        return message

    def link_status_change(self, router_interface, interface_status):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/interfaces/" + router_interface + "/state"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        payload = {
            "if-name": router_interface,
            "enabled": interface_status
        }
        int_set = requests.put(url=api_url, headers=api_headers, json=payload, verify=False, timeout=10)
        output_int_set = int_set.text
        if int_set.status_code == 201:
            message = 'success'
            return message
        else:
            return output_int_set

    # def link_status(self, router_interface, interface_status):
    #     print (router_interface, interface_status)
