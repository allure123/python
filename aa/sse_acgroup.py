
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
from urllib import request
import json
import time
import sys
                        
basehost = "http://112.126.95.79/api"
# basehost = "http://112.74.173.177/api"
# apmac = '44:17:93:4A:C7:10'
apmac = 'CC:1B:E0:E3:15:78'
ID = 'tester'
SECRET = '10b83f9a2e823c47!'

def get_token():
    url = basehost+'/oauth2/token'
    data={'grant_type': 'client_credentials'}
    IDSEC=ID+':'+SECRET
    author=request.base64.b64encode((IDSEC).encode('utf-8'))
    authorize=author.decode('utf-8')
    headers={'Authorization':'Basic '+authorize}
    r = requests.post(url,headers=headers,data=data, verify=False)
    try:
        access_token = json.loads(r.content.decode('utf-8'))['access_token']
        return access_token
    except:
        print("Get access_token failed: "+r.content.decode('utf-8')+'('+str(r.status_code)+')')
        sys.exit()


def sse_acgroup_notify(basehost, access_token, group_name):
    url = basehost+'/v2/gatt/nodes?event=1&group=' + group_name+''
    print(url)
    # time_start = time.time()
    # i=1
    # while True:
    # access_token = get_token()
    headers = {'Authorization': 'Bearer ' + access_token}
    r = requests.get(url, headers=headers, stream=True)
    message_num = 0
    for line in r.iter_lines():
        # time_now = time.time()
        # if time_now > time_start + i * 7000:
        #     i = i + 1
        #     break
        line = str(line, encoding="utf-8")
        if line.startswith('data'):
            message_num += 1
            message = line[6:]
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(str(message_num)+": "+tag+": "+message)


def sse_acgroup_scan(basehost, access_token, group_name):
    url = basehost+'/v2/gap/nodes?event=1&group=' + group_name+''
    # time_start = time.time()
    # i=1
    # while True:
    # access_token = get_token()
    headers = {'Authorization': 'Bearer ' + access_token}
    r = requests.get(url, headers=headers, stream=True)
    message_num = 0
    for line in r.iter_lines():
        # time_now = time.time()
        # if time_now > time_start + i * 7000:
        #     i = i + 1
        #     break
        line = str(line, encoding="utf-8")
        if line.startswith('data'):
            message_num += 1
            message = line[6:]
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(str(message_num)+": "+tag+": "+message)


def sse_acgroup_consta(basehost, access_token, group_name):
    url = basehost+'/v2/management/nodes/connection-state?group=' + group_name+''
    # time_start = time.time()
    # i=1
    # while True:
    # access_token = get_token()
    headers = {'Authorization': 'Bearer ' + access_token}
    r = requests.get(url, headers=headers, stream=True)
    message_num = 0
    for line in r.iter_lines():
        # time_now = time.time()
        # if time_now > time_start + i * 7000:
        #     i = i + 1
        #     break
        line = str(line, encoding="utf-8")
        if line.startswith('data'):
            message_num += 1
            message = line[6:]
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(str(message_num)+": "+tag+": "+message)


if __name__=='__main__':
    access_token = get_token()
    group = "M_Office"
    print(access_token)
    # scan_performance(basehost, access_token, active=0)
    # aps_mac = get_apmac(basehost,access_token)
    # print(aps_mac)
    # aps_mac = ["CC:1B:E0:E1:00:01"]
    # sse_scan_close(basehost, access_token, aps_mac)
    # sse_scan_open(basehost, access_token, aps_mac)
    # sse_scan_open(basehost, access_token, aps_mac, active=1, filter_value={"offset": "7", "data": "0702F5"})
    # sse_notify_open(basehost, access_token, aps_mac)
    # sse_notify_close(basehost, access_token, aps_mac)
    # sse_constat_open(basehost, access_token, aps_mac)
    # sse_constat_close(basehost, access_token, aps_mac)
    # sse_constat_open(basehost, access_token, aps_mac)
    # sse_constat_close(basehost, access_token, aps_mac)
    sse_acgroup_notify(basehost, access_token, group)
