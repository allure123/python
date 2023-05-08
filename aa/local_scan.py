
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import os
import requests
import base64
import json
import time
import sys

basehost='192.168.1.159'


def get_mem():
    url = 'http://' + basehost + '/cassia/memory'
    r = requests.get(url)
    print(r.content.decode('utf-8'))


def scan(time_scan=720000, active=0, chip=0, **filter_m):
    filter_name=filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi=str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac=filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid=str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates=str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    url = 'http://'+basehost+'/gap/nodes?event=1&chip=' + str(chip) + '&active=' \
          + str(active) + '&filter_name=' + filter_name + '&filter_rssi=' + filter_rssi + '&filter_mac=' \
          + filter_mac + '&filter_uuid=' + filter_uuid + '&filter_duplicates=' + filter_duplicates + ''
    sse_num = 0
    while True:
        time_rate0 = time.time()
        message_num = 0
        time_start = time.time()
        try:
            r = requests.get(url, stream=True)
            try:
                for line in r.iter_lines():
                    time_now = time.time()
                    if time_now > time_start+time_scan:
                        r.close()
                        sys.exit()
                    line = line.decode(encoding="utf-8", errors="replace")
                    if line.startswith('data'):
                        time_rate1 = time.time()
                        time_period = time_rate1 - time_rate0
                        message_num += 1
                        tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        if time_period >= 5:
                            get_mem()
                            time_rate0 = time_rate1
                            print(tag+'---'+str(int(message_num/5)))
                            message_num = 0
            except Exception as e:
                sse_num += 1
                print(e)
                print(str(sse_num)+"st SSE broken, Reopen!!!")
                continue
        except Exception as e:
            print(e)
            print('Open SSE failed!!!')
            time.sleep(10)
            continue
               

if __name__=='__main__':
    scan(active=1, chip=0)
    # while True:
    #     if os.path.exists('/root/config/QA_Scan/config.json'):
    #         with open('/root/config/QA_Scan/config.json', 'r', encoding='utf8')as fp:
    #             json_data = json.load(fp)
    #             active = json_data["active"]
    #             chip = json_data["chip"]
    #         if active != "" and chip != "":
    #             scan(active=str(active), chip=str(chip))
    #         else:
    #             print("Parameter 'active' or 'chip' is null!")
    #             time.sleep(30)
    #     else:
    #         time.sleep(30)
