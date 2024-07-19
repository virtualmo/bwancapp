# bwanCapp

bwanCapp.py is a tool that help configure, query, and delete Netskope Borderless SDWAN tenant custom apps in bulk via GraphQL API calls


## Prerequisites

1. Python3
2. The following python modules (see requirements.txt)
	- requests



## Installation

```
$ git clone https://github.com/virtualmo/bwancapp.git
$ cd bwancapp
$ pip3 install -r requirements.txt
```


## Running

### Generate API Token

1. Log in to the SASE Orchestrator as a System Admin and navigate to Administration > Tokens.
2. Click the + icon to create a new token.
3. Provide a Name and Permissions details. The Permissions must be supplied in JSON format.
4. Click Create to generate the token.
5. The popup window will show the token detail. Copy the token and save it for future use.


### Script help
```
$ python3 bwanCapp.py -h
usage: bwanCapp.py [-h] [-u TENANT_URL] [-t API_TOKEN] [-g] [-d CUSTOM_APP_ID] [-a FILENAME] [-p PREFIX]

options:
  -h, --help            show this help message and exit
  -u TENANT_URL, --tenant_url TENANT_URL
                        BWAN Tenant URL
  -t API_TOKEN, --api_token API_TOKEN
                        BWAN Tenant API Token
  -g, --get_custom_apps
                        Get BWAN Custom App
  -d CUSTOM_APP_ID, --del_custom_app CUSTOM_APP_ID
                        Delete Custom App with ID, 0 for All
  -a FILENAME, --add_custom_app FILENAME
                        Add BWAN Custom App from File
  -p PREFIX, --custom_app_prefix PREFIX
                        Custom App name prefix. Default: capp
```

### Create Custom App From file
1. Create csv file with the IP address and custom app name as per the following format (IP address with the same name will be added to the same custom app. And if more than 100 IP share the same app name it will be split into -1 -2 , etc):
```
name,address
app1,192.168.1.1
app1,192.168.1.2
app1,192.168.1.3
app2,192.168.2.0/24
app3,www.example.com
```
2. Run the script:
```
$ python3 bwanCapp.py -u https://<TENANT_URL>/ -t <TOKEN> -a ip_file.csv
2024-07-19 11:52:08,672 WARNING: Config file doesn't exit, will look into CLI arguments
2024-07-19 11:52:08,672 INFO: Working with tenant: <TENANT_URL>
2024-07-19 11:52:08,672 INFO: Creating custom app: capp-app1
2024-07-19 11:52:09,180 INFO: Creating custom app: capp-app2
2024-07-19 11:52:09,369 INFO: Creating custom app: capp-app3
```

3. Confirm the Custom App is created in the orchestrator und Configure > Custom Apps


## Disclaimer

This software is supplied "AS IS" without any warranties and support.