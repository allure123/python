
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
import base64
import json
import time
import sys
                        
basehost='172.16.60.115'
ID = "admin"
SECRET = "`1q`1q`1q"
# SECRET = "U2FsdGVkX1/Ooq+LxtRA64QSYgblr88lwrmDbxQPPwk="

access_token=''
apmac=''

def get_token():
    url = 'http://'+basehost+'/oauth2/token'
    data={'grant_type': 'client_credentials'}
    IDSEC=ID+':'+SECRET
    author = base64.b64encode((IDSEC).encode('utf-8'))
    authorize=author.decode('utf-8')
    headers={'Authorization':'Basic '+authorize}
    r = requests.post(url, headers=headers, data=data, verify=False)
    try:
        token = json.loads(r.content.decode('utf-8'))
        access_token = token['access_token']
        return access_token
    except:
        print("Get access_token failed: "+r.content.decode('utf-8')+'('+str(r.status_code)+')')
        sys.exit()


def scan(basehost, access_token, time_scan=3610, active=0, chip=0, **filter_m):
    filter_name=filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi=str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac=filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid=str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates=str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    message_num = 0
    message_num0 = 0
    time_start = time.time()
    time0 = time_start
    data_num = 1
    try:
        url='http://'+basehost+'/gap/nodes?event=1&mac='+apmac+'&chip='+str(chip)+'&active='\
             +str(active)+'&filter_name='+filter_name+'&filter_rssi='+filter_rssi+'&filter_mac='\
             +filter_mac+'&filter_uuid='+filter_uuid+'&filter_duplicates='+filter_duplicates+''
        headers={'Authorization':'Bearer ' + access_token}
        r = requests.get(url, headers=headers, stream=True)
        if r.status_code == 200:
            for line in r.iter_lines():
                time_now=time.time()
                if time_now>time_start+time_scan:
                    r.close()
                    sys.exit(0)
                line = line.decode(encoding="utf-8", errors="replace")
                if line.startswith('data'):
                    message_num += 1
                    message=line[6:]
                    time_now = time.time()
                    if time_now > time0+60*data_num:
                        scan_num_ps = int((message_num - message_num0)/60)
                        message_num0 = message_num
                        data_num += 1
                        with open('scan_result_chip1.log','a') as f:
                            f.write(str(scan_num_ps)+'\n')
                    tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag+'---'+str(message_num)+'---'+str(message))
                    # with open('scan_result.log','a') as f:
                    #     f.write(tag+'---'+str(message_num)+'---'+str(line)+'\n')
        else:
            print(r.content.decode('utf-8') + '(' + str(r.status_code) + ')')
    except KeyboardInterrupt:
        print('\nExit scan 0')
        return
               

if __name__=='__main__':
    access_token = get_token()
    # print(access_token)
    time_scan = 86410
    scan(basehost, access_token, time_scan, active=1, chip=1)
    # scan(basehost, access_token, active=0, chip="all")
