
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
import base64
import json
import time
import sys
import os
import csv
import pandas as pd
                        
# basehost='192.168.1.114'
basehost='112.126.95.79/api'
# apmac = 'CC:1B:E0:E1:2B:B0'
apmac = 'CC:1B:E0:E3:0D:8C'
# ID = "admin"
# SECRET = "`1q`1q`1q"
ID = 'tester'
SECRET = '10b83f9a2e823c47!'
logfile = 'log_notify.csv'


def get_token():
    url = 'http://'+basehost+'/oauth2/token'
    data={'grant_type': 'client_credentials'}
    IDSEC=ID+':'+SECRET
    author = base64.b64encode((IDSEC).encode('utf-8'))
    authorize=author.decode('utf-8')
    headers={'Authorization':'Basic '+authorize}
    r = requests.post(url, headers=headers, data=data)
    try:
        token = json.loads(r.content.decode('utf-8'))
        access_token = token['access_token']
        return access_token
    except:
        print("Get access_token failed: "+r.content.decode('utf-8')+'('+str(r.status_code)+')')
        sys.exit()


def notify(basehost, access_token):
    message_num = 0
    message = ''
    len_total = 0
    rate_notify = 0.0
    while True:
        try:
            devices_rate = {}
            url='http://'+basehost+'/gatt/nodes?event=1&mac='+apmac+''
            headers={'Authorization':'Bearer ' + access_token}
            time_rate0 = time.time()
            r = requests.get(url, headers=headers, stream=True)
            header_list = []
            header_list_i = 0
            for line in r.iter_lines():
                line = line.decode(encoding="utf-8", errors="replace")
                if line.startswith('data'):
                    message_num += 1
                    time_rate1 = time.time()
                    time_period = time_rate1 - time_rate0
                    message = eval(line[6:])
                    device_mac = message["id"]
                    len_value = len(message["value"])/2
                    if device_mac in devices_rate:
                        devices_rate[device_mac][0] += len_value
                    else:
                        devices_rate[device_mac] = [0, 0]
                    len_total += len_value
                    if time_period >= 2:
                        for device_mac in devices_rate:
                            devices_rate[device_mac][1] = devices_rate[device_mac][0]/time_period
                            devices_rate[device_mac][0] = 0
                        if header_list_i == 0:
                            header_list = list(devices_rate.keys())
                            header_list_i = 1
                            print(header_list)
                            data_list = []
                            data_list.append({key: value[1] for key, value in devices_rate.items()})
                            with open(logfile, mode='w', encoding='utf-8', newline='') as f:
                                writer = csv.DictWriter(f, header_list)
                                writer.writeheader()
                                writer.writerows(data_list)
                        else:
                            data_list = []
                            data_list.append({key: value[1] for key, value in devices_rate.items()})
                            with open(logfile, mode='a', encoding='utf-8', newline='') as f:
                                writer = csv.DictWriter(f, header_list)
                                writer.writerows(data_list)
                            # df = pd.DataFrame(data_list, columns=header_list)
                            # df.to_csv(logfile, mode='a', index=False, header=False)
                        rate_notify = len_total/time_period
                        time_rate0 = time_rate1
                        len_total = 0
                        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        print(tag+' --- '+str(len(devices_rate))+' devices Total Rate: '+str(rate_notify))
                        for device in devices_rate:
                            print(device + ": " + str(devices_rate[device][1]))
                    # tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    # print(tag+'---'+str(message_num)+'---'+str(message)+'---Rate: '+str(rate_notify))
                    # with open('script_scan00.log','a') as f:
                    #     f.write(tag+'---'+str(message_num)+'---'+str(line)+'\n')
        except Exception as e:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': Connection broken: ' + str(e))
            continue
               

if __name__=='__main__':
    access_token = get_token()
    # print(access_token)
    notify(basehost, access_token)
