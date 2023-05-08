
#!/usr/bin/python3.5
#-*- coding=utf-8 -*-

import requests
import base64
import json
import time
import sys
                        
basehost='172.16.60.84'
ID = 'admin'
SECRET = "U2FsdGVkX1/TGu7Gvs4hpiwjU410SNcchdb1TXy6LSI="
# SECRET = '`1q`1q`1q'


def get_token():
    url = 'http://'+basehost+'/oauth2/token'
    data={'grant_type': 'client_credentials'}
    IDSEC=ID+':'+SECRET
    author=base64.b64encode((IDSEC).encode('utf-8'))
    authorize=author.decode('utf-8')
    headers={'Authorization':'Basic '+authorize}
    r = requests.post(url, headers=headers, data=data)
    try:
        access_token = json.loads(r.content.decode('utf-8'))['access_token']
        return access_token
    except:
        print("Get access_token failed: "+r.content.decode('utf-8')+'('+str(r.status_code)+')')
        sys.exit()


def get_info():
    url_info = 'http://'+basehost+'/cassia/info'+''
    url_login='http://'+basehost+'/cassia/login'+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    session.post(url_login, data=login_data)
    response=session.get(url_info)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        res=json.loads(result)
        return res
    else:
        print('Get info failed: '+response.content.decode('utf-8')+'('+str(response.status_code)+')')


def get_pcr():
    url_info = 'http://'+basehost+'/cassia/info?fields=tpm'+''
    url_login='http://'+basehost+'/cassia/login'+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    session.post(url_login, data=login_data)
    response=session.get(url_info)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        res=json.loads(result)
        return res
    else:
        print('Get info failed: '+response.content.decode('utf-8')+'('+str(response.status_code)+')')


def set_text(text):
    data = {"login_text": text}
    url_text = 'http://'+basehost+'/cassia/custom'+''
    url_login='http://'+basehost+'/cassia/login'+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    session.post(url_login, data=login_data)
    response=session.post(url_text, json=data)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        print('Set text: '+result)
    else:
        print('Set text failed: '+response.content.decode('utf-8')+'('+str(response.status_code)+')')


def set_iptables(param):
    url_iptables = 'http://'+basehost+'/cassia/iptables?param='+param+''
    url_login='http://'+basehost+'/cassia/login'+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    session.post(url_login, data=login_data)
    response=session.get(url_iptables)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        print('Set iptables: \n'+result)
    else:
        print('Set iptables failed: '+response.content.decode('utf-8')+'('+str(response.status_code)+')')


def set_env(offset, data):
    data={"offset": offset, "data": data}
    url_test='http://'+basehost+'/cassia/tpm/env'+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    url_login='http://'+basehost+'/cassia/login'+''
    session.post(url_login,data=login_data)
    response=session.post(url_test,json=data)
    if response.status_code==200:
        # result=response.content.decode('utf-8')
        print('Set env successfully!')
    else:
        print('Set env failed: '+str(response.status_code))
        print(response.content.decode('utf-8'))


def get_env(offset):
    url_test='http://'+basehost+'/cassia/tpm/env?offset='+str(offset)+''
    login_data={'username': ID, 'password': SECRET}
    session=requests.Session()
    url_login = 'http://' + basehost + '/cassia/login' + ''
    session.post(url_login,data=login_data)
    response=session.get(url_test)
    if response.status_code==200:
        result=response.content.decode('utf-8')
        print('Get env successfully!')
        return result
    else:
        print('Get env failed: '+str(response.status_code))
        print(response.content.decode('utf-8'))


def scan(access_token, time_scan=720000,active=0, chip=0, **filter_m):
    filter_name=filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi=str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac=filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid=str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates=str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    message_num = 0
    time_start = time.time()
    try:
        url = 'http://'+basehost+'/gap/nodes?event=1&chip='+str(chip)+'&active='+str(active)+'&filter_name='\
              +filter_name+'&filter_rssi='+filter_rssi+'&filter_mac='+filter_mac+'&filter_duplicates='\
              +filter_duplicates+'&filter_uuid='+filter_uuid+''
        # print(url)
        headers={'Authorization': 'Bearer ' + access_token}
        r = requests.get(url, headers=headers, stream=True)
        for line in r.iter_lines():
            time_now=time.time()
            if time_now>time_start+time_scan:
                r.close()
            line = line.decode(encoding="utf-8", errors="replace")
            if line.startswith('data'):
                message_num+=1
                message=line[6:]
                tag=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                print(tag+'---'+str(message_num)+'---'+str(message))
                # with open('script_scan00.log','a') as f:
                #     f.write(tag+'---'+str(message_num)+'---'+str(line)+'\n')
    except KeyboardInterrupt:
        print('\nExit scan 0')
        return
               

if __name__=='__main__':
    # access_token = get_token()
    # print(access_token)
    # scan(access_token, active=0, chip="all", filter_uuid="180d")
    # print(get_info())
    # print(get_pcr())
    # set_text("App: 1.1.1")
    # set_iptables("-D INPUT 1")
    set_iptables("-I INPUT -s 8.8.8.8 -j DROP")
    set_iptables("-I INPUT -s 114.114.114.114 -j DROP")
    set_iptables("-I FORWARD -s 8.8.8.8 -j REJECT")
    set_iptables("-I FORWARD -s 114.114.114.114 -j REJECT")
    # set_iptables("-i wlan0 -I INPUT -p tcp -m multiport --sports 8885 -j ACCEPT")
    # set_iptables("-nvL --line-number -t filter")
    # offset0, string_set0 = 0, "3211111111111111111111111111111111111111111111111111112"
    # set_env(offset0, string_set0)
    # string_get = get_env(offset0)
    # print(string_get)
