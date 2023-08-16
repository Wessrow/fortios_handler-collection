#!/usr/bin/python

"""
Custom Ansible module - returns list of keys for a specific endpoint.
"""

import urllib3
from fortiosapi import FortiOSAPI
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: fortios_fw_state
short_description: GETs current state of FW.
description:
    - Lorum Ipsum
version_added: "0.0.5"
author:
    - Gustav Larsson
notes:
    - Lorum Ipsum

requirements:
    - ansible>=2.9
options:
    host:
        description:
            - Host to GET state from.
        type: str
        required: true
    token:
        description:
            - API token for device.
        type: str
        required: true
    differ_api_path:
        description:
            - API path to GET state from.
        type: str
        required: true
    differ_api_name:
        description:
            - API endpoint to GET state from.
        type: str
        required: true
    ssl_verify:
        description:
            - Switch whether to check SSL-cert or not.
        type: str
        required: true
"""

module = AnsibleModule(argument_spec={
    "host":{"type":"str", "required":True},                     # hostname
    "token":{"type":"str", "required":True, "no_log":True},     # token
    "differ_api_path":{"type":"str", "required":True},          # path to endpoint eg. /xxx/...
    "differ_api_name":{"type":"str", "required":True},          # name of endpoint eg. /.../xxx
    "ssl_verify":{"type":"bool", "required":True}},             # True/False
    supports_check_mode=True)  

if module.params["ssl_verify"] is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

fgt = FortiOSAPI()
fgt.tokenlogin(module.params["host"], module.params["token"], verify=module.params["ssl_verify"])

def main(differ_api_path, differ_api_name):
    """
    returns list of entries, keyed by name
    """

    return_list = []
    result = fgt.get(differ_api_path, differ_api_name)['results']

    if differ_api_path == "router" and differ_api_name == "static":                 # /router/static/ is keyed by seq-num, not name
        search_key = "seq-num"
    elif differ_api_path == "firewall" and differ_api_name == "policy":             # /firewall/policy/ is keyed by policyid, not name
        search_key = "policyid"
    elif differ_api_path == "firewall" and differ_api_name == "central-snat-map":   # /firewall/central-snat-map/ is keyed by policyid, not name
        search_key = "policyid"
    elif differ_api_path == "system.snmp" and differ_api_name == "community":       # /firewall/central-snat-map/ is keyed by policyid, not name
        search_key = "id"
    else:
        search_key = "name"

    for entry in result:
        if differ_api_path == "system" and differ_api_name == "interface":
            if entry["type"] == "tunnel":         # /system/interface/ dynamic tunnels are skipped
                continue
        return_list.append(entry[search_key])

    module.exit_json(return_list=return_list)

if __name__ == "__main__":
    main(module.params["differ_api_path"], module.params["differ_api_name"])
