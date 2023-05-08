
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
import base64
import json
import time
import sys
                        
basehost='192.168.1.159'
ID = "admin"
SECRET = "`1q`1q`1q"

access_token=''
apmac=''

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
            url='http://'+basehost+'/gatt/nodes?event=1'+''
            headers={'Authorization':'Bearer ' + access_token}
            time_rate0 = time.time()
            print("Open new sse!")
            r = requests.get(url, headers=headers, stream=True)
            for line in r.iter_lines():
                line = line.decode(encoding="utf-8", errors="replace")
                if line.startswith('data'):
                    time_rate1 = time.time()
                    time_period = time_rate1 - time_rate0
                    message_num += 1
                    try:
                        message = eval(line[6:])
                    except Exception as e:
                        print("Read message failed: " + e)
                        continue
                    len_value = len(message["value"])/2
                    len_total += len_value
                    if time_period >= 2:
                        rate_notify = len_total/time_period
                        time_rate0 = time_rate1
                        len_total = 0
                        # print(rate_notify)
                    tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag+'---'+str(message_num)+'---'+str(message)+'---Rate: '+str(rate_notify))
        except Exception as e:
            print('Connection broken: ' + str(e))
            continue
               

if __name__=='__main__':
    # access_token = get_token()
    # print(access_token)
    notify(basehost, access_token)
