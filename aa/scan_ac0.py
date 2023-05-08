
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
from urllib import request
import json
import time
import sys
                        
basehost = "http://112.126.95.79/api"
apmac = 'CC:1B:E0:E3:1C:14'
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


def scan_circle(basehost, access_token, time_scan=720000, active=0, chip=0, **filter_m):
    filter_name=filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi=str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac=filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid=str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates=str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    url = basehost+'/gap/nodes?event=1&mac='+apmac+'&chip='+str(chip)+'&active='\
         +str(active)+'&filter_name='+filter_name+'&filter_rssi='+filter_rssi+'&filter_mac='\
         +filter_mac+'&filter_uuid='+filter_uuid+'&filter_duplicates='+filter_duplicates+''
    headers = {'Authorization':'Bearer ' + access_token}
    try:
        r=requests.get(url,headers=headers,stream=True)
    except Exception:
        time.sleep(3)
        try:
            r=requests.get(url,headers=headers,stream=True)
        except Exception:
            time.sleep(3)
            r=requests.get(url,headers=headers,stream=True)
    time_start=time.time()
    i=1
    j=0
    index=0
    par=[(0,0),(0,1)]
    while True:
        try:
            if j==1:                
                if index==1:
                    index=0
                else:
                    index+=1
            j=0
            access_token=get_token()
            chip,active=par[index]
            time_now=time.time()
            if time_now>time_start+time_scan:
                break 
            url = basehost+'/gap/nodes?event=1&mac='+apmac+'&chip='+str(chip)+'&active='\
                 +str(active)+'&filter_name='+filter_name+'&filter_rssi='+filter_rssi+'&filter_mac='\
                 +filter_mac+'&filter_uuid='+filter_uuid+'&filter_duplicates='+filter_duplicates+''
            headers={'Authorization':'Bearer ' + access_token}
            try:
                r=requests.get(url,headers=headers,stream=True)
            except Exception:
                time.sleep(3)
                try:
                    r=requests.get(url,headers=headers,stream=True)
                except Exception:
                    time.sleep(3)
                    r=requests.get(url,headers=headers,stream=True)
            for line in r.iter_lines():
                time_now=time.time()
                if time_now>time_start+i*300:
                    i=i+1
                    j=1
                    break                
                line=str(line, encoding = "utf-8")
                if line.startswith('data'):
                    try:
                        line=eval(line[6:])
                    except SyntaxError:
                        break
                    except NameError:
                        break
                    tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag)
                    print('Scan '+str(par[index])+'  :'+str(line))
        except KeyboardInterrupt:
            print('\nExit scan 0')
            return


def scan_performance(basehost, access_token, time_scan=720000, active=0, chip=0, **filter_m):
    package_num = 0
    time_start = time.time()
    filter_name=filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi=str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac=filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid=str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates=str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    url = basehost+'/gap/nodes?event=1&mac='+apmac+'&chip='+str(chip)+'&active='\
         +str(active)+'&filter_name='+filter_name+'&filter_rssi='+filter_rssi+'&filter_mac='\
         +filter_mac+'&filter_uuid='+filter_uuid+'&filter_duplicates='+filter_duplicates+''
    headers = {'Authorization':'Bearer ' + access_token}
    message_num = 0
    time_rate0 = time.time()
    try:
        r = requests.get(url, headers=headers, stream=True)
    except Exception:
        time_tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open('warning.log', 'a') as f:
            f.write(time_tag+': requests error occurred on scan!\n')
        sys.exit()
    for line in r.iter_lines():
        time_now = time.time()
        if time_now > time_start + time_scan:
            r.close()
            break
        line = line.decode(encoding="utf-8", errors="replace")
        if line.startswith('data'):
            time_rate1 = time.time()
            time_period = time_rate1 - time_rate0
            message_num += 1
            line = eval(line[6:])
            time_tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            if time_period >= 10:
                time_rate0 = time_rate1
                print(time_tag + '---' + str(message_num))
                message_num = 0
            # print(time_tag + ' Scan ' + str(package_num) + '  :' + str(line))


def get_apmac(basehost,access_token):
    aps_mac=[]
    url = basehost+'/cassia/hubs'+''
    headers = {'Authorization': 'Bearer ' + access_token}
    response = requests.request('GET', url, headers=headers)
    if response.status_code == 200:
        aps_info = json.loads(response.content.decode('utf-8'))
        for ap in aps_info:
            aps_mac.append(ap['mac'])
    return aps_mac


def sse_ac(basehost,access_token):
    url = basehost+'/aps/events'
    time_start = time.time()
    i=1
    # while True:
    access_token = get_token()
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


def sse_scan_open(basehost, access_token, aps_mac, **para):
    url = basehost + '/aps/scan/open'
    headers = {'Authorization': 'Bearer ' + access_token}
    active = para['active'] if ('active' in para) else ''
    filter_name = para['filter_name'] if ('filter_name' in para) else ''
    filter_rssi = str(para['filter_rssi']) if ('filter_rssi' in para) else '-100'
    filter_mac = para['filter_mac'] if ('filter_mac' in para) else ''
    filter_uuid = str(para['filter_uuid']) if ('filter_uuid' in para) else ''
    filter_duplicates = str(para['filter_duplicates']) if ('filter_duplicates' in para) else ''
    filter_value = json.dumps(para['filter_value']) if ('filter_value' in para) else ''
    data = {"aps": aps_mac, "chip": 0, "active": active, "filter_name": filter_name, "filter_rssi": filter_rssi,
            "filter_mac": filter_mac, "filter_uuid": filter_uuid, "filter_duplicates": filter_duplicates,
            "filter_value": filter_value}
    requests.request('POST', url, headers=headers, json=data)


def sse_scan_close(basehost,access_token,aps_mac):
    url = basehost + '/aps/scan/close'
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {"aps":aps_mac}
    requests.request('POST', url, headers=headers, json=data)


def sse_notify_open(basehost,access_token,aps_mac):
    url = basehost + '/aps/notify/open'
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {"aps":aps_mac}
    requests.request('POST', url, headers=headers, json=data)


def sse_notify_close(basehost,access_token,aps_mac):
    url = basehost + '/aps/notify/close'
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {"aps":aps_mac}
    requests.request('POST', url, headers=headers, json=data)


def sse_constat_open(basehost,access_token,aps_mac):
    url = basehost + '/aps/connection-state/open'
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {"aps":aps_mac}
    requests.request('POST', url, headers=headers, json=data)


def sse_constat_close(basehost,access_token,aps_mac):
    url = basehost + '/aps/connection-state/close'
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {"aps":aps_mac}
    requests.request('POST', url, headers=headers, json=data)


if __name__=='__main__':
    access_token = get_token()
    print(access_token)
    # print("**************** %s **************"% basehost)
    scan_performance(basehost, access_token, active=1, chip="all")
    # scan_performance(basehost, access_token)
    # scan_performance(basehost, access_token)
    # aps_mac = get_apmac(basehost,access_token)
    # print(aps_mac)
    # aps_mac = ["CC:1B:E0:E1:15:9C"]
    # sse_scan_close(basehost, access_token, aps_mac)
    # sse_scan_open(basehost, access_token, aps_mac)
    # sse_scan_open(basehost, access_token, aps_mac, active=1, filter_value={"offset": "7", "data": "0702F5"})
    # sse_notify_open(basehost, access_token, aps_mac)
    # sse_notify_close(basehost, access_token, aps_mac)
    # sse_constat_open(basehost, access_token, aps_mac)
    # sse_constat_close(basehost, access_token, aps_mac)
    # sse_ac(basehost, access_token)
