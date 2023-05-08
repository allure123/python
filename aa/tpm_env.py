#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

# This test tool is used to test: scan, connect, get connected device, discovery(6), write by handle, 
# read by handle, disconnect, notify, get connect status, set info, get info, start/stop adv 18 apis.

# import requests
try:
    import requests
except Exception:
    import os
    os.system('sudo /home/cassia/py3env/bin/pip install requests')
    import requests
from urllib import request
import json
from requests.auth import HTTPBasicAuth
import time
import sys
import threading
import os
                        
basehost='172.16.60.109'
access_token=''
apmac=''
mutex = threading.Lock()


def set_env(offset,data):
    data={"offset": offset, "data": data}
    url_test='http://'+basehost+'/cassia/tpm/env'+''
    login_data={'username':'admin','password':'`1q`1q`1q'}
    session=requests.Session()
    url_login='http://'+basehost+'/cassia/login'+''
    session.post(url_login,data=login_data)
    response=session.post(url_test,json=data)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        print('Set env successfully!')
    else:
        print('Set env failed: '+str(response.status_code))
        print(response.content.decode('utf-8'))

def get_env(offset):
    url_test='http://'+basehost+'/cassia/tpm/env?offset='+str(offset)+''
    login_data={'username':'admin','password':'`1q`1q`1q'}
    session=requests.Session()
    url_login = 'http://' + basehost + '/cassia/login' + ''
    session.post(url_login,data=login_data)
    response=session.get(url_test)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        print('Get env result: '+result)
        return result
    else:
        print('Get env failed: '+str(response.status_code))
        print(response.content.decode('utf-8'))


if __name__=='__main__':
    # set_env(500, "b2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")
    set_env(0,"123")
    # get_env(500)
