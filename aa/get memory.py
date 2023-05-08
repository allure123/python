
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
import sys
import time
import json
from urllib import request

ID = 'tester'
SECRET = 'cassiate@#@1231'
basehost = '112.126.95.79/api'
apmacs= ['CC:1B:E0:E3:1C:14', 'CC:1B:E0:E3:0D:8C']
# apmacs= ['CC:1B:E0:E3:0D:8C']
# basehost='192.168.1.159'


def get_token():
    url = 'http://' + basehost + '/oauth2/token'
    data = {'grant_type': 'client_credentials'}
    IDSEC = ID + ':' + SECRET
    author = request.base64.b64encode((IDSEC).encode('utf-8'))
    authorize = author.decode('utf-8')
    headers = {'Authorization': 'Basic ' + authorize}
    r = requests.post(url, headers=headers, data=data, verify=False)
    try:
        access_token = json.loads(r.content.decode('utf-8'))['access_token']
        return access_token
    except:
        print("Get access_token failed: " + r.content.decode('utf-8') + '(' + str(r.status_code) + ')')
        sys.exit()


def get_mem(apmac):
    url = 'http://' + basehost + '/cassia/memory?mac=' + apmac + ''
    access_token = get_token()
    headers = {'Authorization': 'Bearer ' + access_token}
    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    r = requests.get(url, headers=headers)
    print(tag + " ------ " + apmac + "------" + r.content.decode('utf-8'))


if __name__=='__main__':
    while True:
        for apmac in apmacs:
            get_mem(apmac)
        time.sleep(60)
