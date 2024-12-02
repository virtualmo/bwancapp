#!/usr/bin/python3

BWANCAPP_DESCRIPTION = """
    BWANCAPP is a script by Mohanad Elamin

    BWANCAPP Help configure, query Netskope Borderless SDWAN tenant custom apps in bulk via GraphQL API calls
    Requirements:
        python >= 3.11 (it should work with any version > 3 but I've only tested
                        it with 3.11)

        third-party libraries:
            requests >= 2.31.0   (http://docs.python-requests.org/en/latest/)
            tabulate
        You should be able to install the third-party libraries via pip (or pip3
        depending on the setup):

            pip3 install requests
            pip3 install tabulate
"""

BWANCAPP_VERSION = "2024-01-30_00"
CONFIG_FILENAME = "~/.bwanCapp.conf"
#
# Any of these can be customized in the configuration file, for example:
#
#    $ cat ~/.bwanCapp.conf
#    [bwan_config]
#    # auth details
#    tenant_url=
#    api_token=


import os
import os.path
import sys
import json
import tabulate
import argparse
import csv

from configparser import ConfigParser
from logging import basicConfig as logging_basicConfig, \
    addLevelName as logging_addLevelName, \
    getLogger as logging_getLogger, \
    log as logging_log, \
    DEBUG   as logging_level_DEBUG, \
    INFO    as logging_level_INFO,  \
    WARN    as logging_level_WARN,  \
    ERROR   as logging_level_ERROR, \
    debug   as debug,   \
    info    as info,    \
    warning    as warn,    \
    error   as error

from re import search as re_search, sub as re_sub
from signal import signal as signal_set_handler, SIGINT as signal_SIGINT

from requests import Session as RQ_Session, \
    ConnectionError as RQ_ConnectionError, \
    Timeout as RQ_Timeout, \
    RequestException as RQ_Exception

#
# 256 color terminal color test:
#
# print("FG | BG")
# for i in range(256):
#    # foreground color | background color
#    print("\033[48;5;0m\033[38;5;{0}m #{0} \033[0m | "
#            "\033[48;5;{0}m\033[38;5;15m #{0} \033[0m".format(i))
#
LOGGING_LEVELS = {
    'ERROR' : {
        'level' : logging_level_ERROR,
        'name'  : 'ERROR',
        'xterm' : '31m',
        '256color': '38;5;196m',
    },
    'NORMAL' : {
        'level' : 35,
        'name'  : 'CAD',
        'xterm' : '37m',
        '256color': '38;5;255m',
    },
    'WARNING' : {
        'level' : logging_level_WARN,
        'name'  : 'WARNING',
        'xterm' : '33m',
        '256color': '38;5;227m',
    },
    'INFO' : {
        'level' : logging_level_INFO,
        'name'  : 'INFO',
        'xterm' : '36m',
        '256color': '38;5;45m',
    },
    'DEBUG' : {
        'level' : logging_level_DEBUG,
        'name'  : 'DEBUG',
        'xterm' : '35m',
        '256color': '38;5;135m',
    },
}

#
# We allow the log level to be specified on the command-line or in the
# config by name (string/keyword), but we need to convert these to the
# numeric value:
#
LOGGING_LEVELS_MAP = {
    'NORMAL'    : LOGGING_LEVELS['NORMAL']['level'],
    'ERROR'     : logging_level_ERROR,
    'WARN'      : logging_level_WARN,
    'INFO'      : logging_level_INFO,
    'DEBUG'     : logging_level_DEBUG,
    'normal'    : LOGGING_LEVELS['NORMAL']['level'],
    'error'     : logging_level_ERROR,
    'warn'      : logging_level_WARN,
    'info'      : logging_level_INFO,
    'debug'     : logging_level_DEBUG
}

def custom_signal_handler(signal, frame):
    """Very terse custom signal handler

    This is used to avoid generating a long traceback/backtrace
    """

    warn("Signal {} received, exiting".format(str(signal)))
    sys.exit(1)

def graphql_request(session, url, headers, data):
   return session.post(url=url + "/graphql", headers=headers, data=data)


def get_custom_apps(session, headers, tenant_url):
   info("Getting custom apps")
   query = json.dumps({
    "operationName": "getCustomApps",
    "variables": {},
    "query": "query getCustomApps {\n  getCustomApps {\n    id\n    capp_name\n    capp_description\n    capp_enabled\n    capp_native\n    capp_type\n    capp_type_id\n    capp_icon_url\n    capp_sites {\n      capp_site_id\n      capp_site_overlay_ip\n      __typename\n    }\n    capp_definitions {\n      capp_def_web_access\n      capp_def_protocol\n      capp_def_host\n      capp_def_port_range\n      __typename\n    }\n    nddb_created\n    nddb_modified\n    createdBy {\n      id\n      auc_name\n      __typename\n    }\n    modifiedBy {\n      id\n      auc_name\n      __typename\n    }\n    __typename\n  }\n}"
   })
   response = graphql_request(session, tenant_url, headers, query)
   response_data = response.json()
   response_dict = response_data["data"]["getCustomApps"]
   table_header = ["id","capp_name"]
   table_data = [[row[col] for col in table_header] for row in response_dict]
   print(tabulate.tabulate(table_data, headers=table_header, tablefmt="grid"))
   print("\nTotal number of Custom Apps is {}\n".format(len(response_dict)))
   id_list = [ id['id'] for id in response_dict ]
   return(id_list)

def del_custom_app(session, headers, tenant_url, app_id):
   info("deleting custom app with ID {}".format(app_id))
   query = json.dumps({
    "variables": {
        "id": str(app_id)
    },
    "query": "mutation ($id: ID!) {\n  deleteCustomApp(id: $id) {\n    id\n    capp_name\n    capp_description\n    capp_enabled\n    capp_native\n    capp_type\n    capp_type_id\n    capp_icon_url\n    capp_sites {\n      capp_site_id\n      capp_site_overlay_ip\n      __typename\n    }\n    capp_definitions {\n      capp_def_web_access\n      capp_def_protocol\n      capp_def_host\n      capp_def_port_range\n      __typename\n    }\n    nddb_created\n    nddb_modified\n    createdBy {\n      id\n      auc_name\n      __typename\n    }\n    modifiedBy {\n      id\n      auc_name\n      __typename\n    }\n    __typename\n  }\n}"   
   })
   response = graphql_request(session, tenant_url, headers, query)
   response_data = response.json()
  #  print(response_data)

def capp_def_str(ip_addr, port_range, protocol):
  capp_def_str = "{ \"capp_def_web_access\": false, \"capp_def_host\": \"" + ip_addr + "\", \"capp_def_port_range\": \"" + port_range + "\", \"capp_def_protocol\": \"" + protocol + "\" },"
  return capp_def_str

def add_custom_apps(session,headers, tenant_url, data_file, capp_name_prefix):
  ipv4_merged_list = []
  global json_dump_def_list
  global c
  
  ip_data_dict = {}
  
  with open(data_file, "r") as f:
    reader = csv.reader(f)
    next(reader)
    for name,address,protocl,port in reader:
        ip_data_dict.setdefault(name, []).append([address,protocl,port])
  
  json_dump_def_list = []
  c = 0
  capp_c = 0
  for key, value in ip_data_dict.items():
    for entry in value:
      ip_addr=entry[0]
      if entry[2] == "*":
        port_range = "0-65535"
      else:
        port_range = entry[2]
        
      if entry[1].upper() == "TCP":
        protocol = "TCP"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
      elif entry[1].upper() == "UDP":
        protocol = "UDP"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
      elif entry[1].upper() == "ICMP":
        protocol = "ICMP"
        port_range = "null"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
      elif entry[1].upper() == "ANY":
        protocol = "TCP"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
        protocol = "UDP"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
        protocol = "ICMP"
        port_range = "null"
        json_dump_def_list.append(capp_def_str(ip_addr,port_range,protocol))
      else:
        error("Unknown protocl or port. Allowed Protocol: TCP, UDP, ICMP or Any allowed. Allowed Port: single port or *")
        exit()
    capp_name = capp_name_prefix + "-" + key
    capp_desc = capp_name_prefix + "-" + key
    query = json.dumps({
      "variables": {
        "data": {
            "capp_name": capp_name,
            "capp_type": "Standard",
            "capp_type_id": 24,
            "capp_description": capp_desc,
            # "capp_icon_url": null,
            "capp_definitions": [
                ''.join(json_dump_def_list)[:-1]
            ],
            # "capp_sites": null,
            # "capp_enabled": null
        }
    },
    "query": "mutation ($data: AddCustomAppInput!) {\n  createCustomApp(newCustomAppData: $data) {\n    id\n    capp_name\n    capp_description\n    capp_enabled\n    capp_native\n    capp_type\n    capp_type_id\n    capp_icon_url\n    capp_sites {\n      capp_site_id\n      capp_site_overlay_ip\n      __typename\n    }\n    capp_definitions {\n      capp_def_web_access\n      capp_def_protocol\n      capp_def_host\n      capp_def_port_range\n      __typename\n    }\n    nddb_created\n    nddb_modified\n    createdBy {\n      id\n      auc_name\n      __typename\n    }\n    modifiedBy {\n      id\n      auc_name\n      __typename\n    }\n    __typename\n  }\n}"
    }) 
    parsed_query = query.replace("[\"","[").replace("\"]","]").replace("\\\"","\"")
    # print(parsed_query)
    info("Creating custom app: {}".format(capp_name))
    response = graphql_request(session, tenant_url, headers, parsed_query)
    response_data = response.json()
    json_dump_def_list = []


def main():
    session = RQ_Session()

    #
    # Set logging to INFO by default (log everything except DEBUG).
    #
    # Also try to add colors to the logging output if the logging output goes
    # to a capable device (not a file and a terminal supporting colors).
    #
    # Actually adding the ANSI escape codes in the logging level name is pretty
    # much an ugly hack but it is the easiest way (less changes).
    #
    # An elegant way of doing this is described here:
    #  http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
    #
    fmt_str = '%(asctime)s %(levelname)s: %(message)s'

    logging_basicConfig(format=fmt_str, level=logging_level_INFO,
                        stream=sys.stdout)
    logger = logging_getLogger()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('-u','--tenant_url', help='BWAN Tenant URL')
    argparser.add_argument('-t','--api_token', help='BWAN Tenant API Token')
    argparser.add_argument('-g','--get_custom_apps', help='Get BWAN Custom App', action='store_true')
    argparser.add_argument('-d','--del_custom_app', help='Delete Custom App with ID, 0 for All', metavar='CUSTOM_APP_ID')
    argparser.add_argument('-a','--add_custom_app', help='Add BWAN Custom App from File', metavar='FILENAME')
    argparser.add_argument('-p','--custom_app_prefix', help='Custom App name prefix. Default: capp', metavar='PREFIX')

    args = argparser.parse_args(args=None if sys.argv[1:] else ['--help'])


    cfgparser = ConfigParser()
    
    try:
        if not cfgparser.read(os.path.expanduser(CONFIG_FILENAME)):
          warn("Config file doesn't exit, will look into CLI arguments")
          if (args.tenant_url is not None):
              tenant_url = args.tenant_url
          else:
              error("add the tenant_url to arguments or to the config file.")
              sys.exit(1)
              
          if (args.api_token is not None):
              bwan_api_token = args.api_token
          else:
              error("add the api_token to arguments or to the config file.")
              sys.exit(1)      
        else:
          config = cfgparser['bwan_config']
          if ('bwan_config' not in cfgparser):
              error("Configuration file {} doesn't contain 'bwan_config' section"
                    "".format(os.path.expanduser(CONFIG_FILENAME)))
              sys.exit(1)
          elif (('tenant_url' not in cfgparser['bwan_config']) or
                  ('api_token' not in cfgparser['bwan_config'])):
              error("Config file doesn't contain (all) required authentication info")
              sys.exit(1)
    except:
        error("Can't parse configuration file {}"
              "".format(os.path.expanduser(CONFIG_FILENAME)))
        sys.exit(1)

    info("Working with tenant: {}".format(tenant_url))
    headers = {
      "authorization": "Bearer {\"auc_token\":\"" + bwan_api_token + "\"}",
      "content-type": "application/json"
    }

    if args.get_custom_apps:
       get_custom_apps(session, headers, tenant_url)

    # if args.add_custom_app:
    #     add_custom_app(session, headers, tenant_url, ip_list_file=args.add_custom_app)
    
    if args.del_custom_app:
       if args.del_custom_app == "0":
          id_list = get_custom_apps(session, headers, tenant_url)
          if len(id_list) == 0:
            info("No custom app found. Nothing to delete.")
            exit(0)
          info("The script will delete {} custom app".format(len(id_list)))
          while True:
            answer = input("Do you want to Continue? (Yes/Y or No/N) ")
            if answer.lower() in ["y","yes"]:
              for app_id in id_list:
                del_custom_app(session, headers, tenant_url, app_id)
              break
            elif answer.lower() in ["n","no"]:
              info("No custom app deleted. Exiting...")
              exit(0)
            else:
              error("Please select Yes/y or No/n")
          
       else:
          del_custom_app(session, headers, tenant_url, args.del_custom_app)

    if args.add_custom_app:
      capp_name_prefix = args.custom_app_prefix if args.custom_app_prefix else "capp"
      add_custom_apps(session, headers, tenant_url, args.add_custom_app, capp_name_prefix)       

if (__name__ == '__main__'):
    main()