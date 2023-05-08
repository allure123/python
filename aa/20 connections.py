#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

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

basehost = '112.126.95.79/api'
access_token = ''
apmac = 'CC:1B:E0:E3:0D:8C'
# apmac = 'CC:1B:E0:E1:2B:B0'
ID = 'tester'
SECRET = '10b83f9a2e823c47!'
mutex = threading.Lock()


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


# requests.request has a problem, so change to use urllib3.PoolManage
def get_constatus(basehost):
    url = 'http://' + basehost + '/management/nodes/connection-state?mac=' + apmac + ''
    # i=1
    # time_start=time.time()
    while True:
        access_token = get_token()
        headers = {'Authorization': 'Bearer ' + access_token}
        try:
            r = requests.get(url, headers=headers, stream=True)
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': requests error occured on get_constatus!\n')
            break
        try:
            for line in r.iter_lines():
                # time_now = time.time()
                # if time_now > time_start + 30 * 60 * i and time_now < time_start + 30 * 60 * (i + 1):
                #     i += 1
                #     break
                line = str(line, encoding="utf-8")
                if line.startswith('data'):
                    try:
                        line = eval(line[6:])
                    except Exception as e:
                        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        with open('warning.log', 'a') as f:
                            f.write(tag + ': Get_con_status error occured!\n' + e + '\n')
                        break
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    mutex.acquire()
                    print(tag + ': ' + threading.current_thread().name + str(line))
                    mutex.release()
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': SSE error occured on get_constatus!\n')
            continue


def notify(basehost):
    url = 'http://' + basehost + '/gatt/nodes/?event=1&mac=' + apmac + ''
    # i=1
    # time_start = time.time()
    while True:
        access_token = get_token()
        headers = {'Authorization': 'Bearer ' + access_token}
        try:
            r = requests.get(url, headers=headers, stream=True)
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': requests error occured on notify!\n')
            break
        try:
            for line in r.iter_lines():
                # time_now=time.time()
                # if time_now>time_start+30*60*i and time_now<time_start+30*60*(i+1):
                #     i+=1
                #     break
                line = str(line, encoding="utf-8")
                if line.startswith('data'):
                    try:
                        line = eval(line[6:])
                    except Exception as e:
                        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        with open('warning.log', 'a') as f:
                            f.write(tag + ': Notify error occured!\n' + e + '\n')
                        break
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    mutex.acquire()
                    print(tag + ': ' + threading.current_thread().name + str(line))
                    mutex.release()
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': SSE error occured on notify!\n')
            continue


def connect(basehost, access_token, device_mac, device_type="public", chip='0', auto=0):
    index = 0
    while index < len(device_mac):
        url = 'http://' + basehost + '/gap/nodes/' + device_mac[index] + '/connection?chip=' + str(
            chip) + '&mac=' + apmac + ''
        headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
        data = {'timeout': '5000', "type": device_type, 'auto': auto, 'discovergatt': '0'}
        try:
            response = requests.request('POST', url, headers=headers, json=data)
        except Exception:
            time.sleep(3)
            try:
                response = requests.request('POST', url, headers=headers, json=data)
            except Exception:
                time.sleep(3)
                response = requests.request('POST', url, headers=headers, json=data)
        status_code = response.status_code
        '''
        if status_code!=200:
            response=requests.request('POST',url,headers=headers,json=data_p)
            status_code=response.status_code
        '''
        result = response.content.decode('utf-8')
        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(tag + ': ' + 'Connect ' + device_mac[index] + ' status_code:' + str(status_code) + ' :' + result)
        index += 1
        return status_code


def get_condev(basehost, access_token):
    dev_list = []
    url = 'http://' + basehost + '/gap/nodes?connection_state=connected&mac=' + apmac + ''
    headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
    response = requests.request('GET', url, headers=headers)
    if response.status_code == 200:
        nodes = json.loads(response.content.decode('utf-8'))['nodes']
        if len(nodes):
            for i in range(0, len(nodes)):
                dev_list.append(nodes[i]['id'])
    elif response.status_code == 504:  # Gateway Timeout 504
        print('Get connected device failed: ' + response.content.decode('utf-8') + ' (504)')
        time.sleep(3)
        response = requests.request('GET', url, headers=headers)
        if response.status_code == 200:
            nodes = json.loads(response.content.decode('utf-8'))['nodes']
            if len(nodes):
                for i in range(0, len(nodes)):
                    dev_list.append(nodes[i]['id'])
        else:
            print('Get connected device failed: ' + response.content.decode('utf-8') + '(' + str(
                response.status_code) + ')')
    else:
        print(
            'Get connected device failed: ' + response.content.decode('utf-8') + '(' + str(response.status_code) + ')')
    return dev_list


def disconnect(basehost, access_token, device_mac):
    index = 0
    while index < len(device_mac):
        device_list = get_condev(basehost, access_token)
        if device_mac[index] in device_list:
            # print('Disconnecting '+device_mac[index])
            url = 'http://' + basehost + '/gap/nodes/' + device_mac[index] + '/connection?mac=' + apmac + ''
            headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
            data = {'timeout': '5000'}
            try:
                response = requests.request('DELETE', url, headers=headers, json=data)
            except Exception:
                time.sleep(3)
                try:
                    response = requests.request('DELETE', url, headers=headers, json=data)
                except Exception:
                    time.sleep(3)
                    response = requests.request('DELETE', url, headers=headers, json=data)
            status_code = response.status_code
            result = response.content.decode('utf-8')
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(tag + ': ' + 'Disconnect ' + device_mac[index] + ' status_code:' + str(status_code) + ' :' + result)
        index += 1


def discover(basehost, access_token, device_mac):
    total_result = 0
    services_list = []
    characteristics_list = []
    descriptors_list = []
    # NO.1 Discover all test
    if len(device_mac):
        url_all = 'http://' + basehost + '/gatt/nodes/' + device_mac[
            0] + '/services/characteristics/descriptors/?mac=' + apmac + ''
        headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
        response = requests.request('GET', url=url_all, headers=headers)
        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        # print(url_all)
        if response.status_code == 200:
            print(tag + ': ' + 'Discover all test :Passed')

            result_all = json.loads(response.content.decode('utf-8'))
            if len(result_all):
                # print("Discover all test begin..............................................................................")
                for i in range(0, len(result_all)):
                    services_list.append(result_all[i]['uuid'])
                    #     print('serv:'+result_all[i]['uuid'])
                    if 'characteristics' in result_all[i]:
                        for j in range(0, len(result_all[i]['characteristics'])):
                            characteristics_list.append(result_all[i]['characteristics'][j]['uuid'])
                            #             print('        char:'+result_all[i]['characteristics'][j]['uuid'])
                            if 'descriptors' in result_all[i]['characteristics'][j]:
                                for k in range(0, len(result_all[i]['characteristics'][j]['descriptors'])):
                                    descriptors_list.append(
                                        result_all[i]['characteristics'][j]['descriptors'][k]['uuid'])
                # print(services_list)
                # print(characteristics_list)
                # print(descriptors_list)
                #                     print('                desc:'+result_all[i]['characteristics'][j]['descriptors'][k]['uuid'])
                # print("Discover all test finish.............................................................................")

                # NO.2 Discover service test
                # print("\nDiscover service test begin........................................................................")
                url_service = 'http://' + basehost + '/gatt/nodes/' + device_mac[
                    0] + '/services/?mac=' + apmac + '&all=1'
                # print(url_service)
                response = requests.request('GET', url=url_service, headers=headers)
                if response.status_code == 200:
                    result = json.loads(response.content.decode('utf-8'))
                else:
                    result = []
                s = []
                for i in range(0, len(result)):
                    s.append(result[i]['uuid'])
                if s == services_list:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover service test :Passed")
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover service test :Failed")
                # print("Discover service test finish.........................................................................")

                # NO.3 Discover service with uuid test
                # print("\nDiscover service with uuid test begin..............................................................")
                services_uuid_result = 1
                for services_uuid in services_list:
                    url_service_uuid = 'http://' + basehost + '/gatt/nodes/' + device_mac[
                        0] + '/services/?mac=' + apmac + '&all=1&uuid=' + services_uuid + ''
                    # print(url_service_uuid)
                    response = requests.request('GET', url=url_service_uuid, headers=headers)
                    if response.status_code != 200:
                        services_uuid_result = 0
                if services_uuid_result:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover service with uuid test :Passed")
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover service with uuid test :Failed")
                # print("Discover service with uuid test finish...............................................................")

                # NO.4 Discover characteristics test
                # print("\nDiscover characteristics test begin................................................................")
                c = []
                for services_uuid in services_list:
                    url_characteristics = 'http://' + basehost + '/gatt/nodes/' + device_mac[
                        0] + '/services/' + services_uuid + '/characteristics?mac=' + apmac + '&all=1'
                    # print(url_characteristics)
                    response = requests.request('GET', url=url_characteristics, headers=headers)
                    if response.status_code == 200:
                        result = json.loads(response.content.decode('utf-8'))
                    else:
                        result = []
                    if len(result):
                        for i in range(0, len(result)):
                            c.append(result[i]['uuid'])
                if c == characteristics_list:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover characteristics test :Passed")
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover characteristics test :Failed")
                # print("Discover characteristics test finish.................................................................")

                # NO.5 Discover characteristics with uuid test
                # print("\nDiscover characteristics with uuid test begin......................................................")
                characteristics_uuid_result = 1
                for characteristics_uuid in characteristics_list:
                    url_characteristics_uuid = 'http://' + basehost + '/gatt/nodes/' + device_mac[
                        0] + '/characteristics?mac=' + apmac + '&uuid=' + characteristics_uuid
                    # print(url_characteristics_uuid)
                    response = requests.request('GET', url=url_characteristics_uuid, headers=headers)
                    if response.status_code != 200:
                        characteristics_uuid_result = 0
                if characteristics_uuid_result:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover characteristics with uuid test :Passed")
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover characteristics with uuid test :Failed")
                    # print("Discover characteristics with uuid test finish.......................................................")

                # NO.6 Discover descriptors test
                # print("\nDiscover descriptors test begin....................................................................")
                d = []
                for characteristics_uuid in characteristics_list:
                    url_descriptors = 'http://' + basehost + '/gatt/nodes/' + device_mac[
                        0] + '/characteristics/' + characteristics_uuid + '/descriptors?mac=' + apmac + ''
                    # print(url_descriptors)
                    response = requests.request('GET', url=url_descriptors, headers=headers)
                    if response.status_code == 200:
                        result = json.loads(response.content.decode('utf-8'))
                    else:
                        result = []
                    if len(result):
                        for i in range(0, len(result)):
                            d.append(result[i]['uuid'])
                        # print(characteristics_uuid)
                        # print(d)
                        # d=[]
                if d == descriptors_list:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover descriptors test :Passed")
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + "Discover descriptors test :Failed")
                # print("Discover descriptors test finish.....................................................................")

            else:

                print('No service!!!')
        else:
            print(tag + ': ' + 'Discover test :Failed')

    else:
        print('No connected device!!!')


def readby_handle(basehost, access_token, device_mac, **handlee):
    # dev_mac,services_handle,characteristics_handle,descriptors_handle=get_handle(basehost,access_token)
    handle_list = handlee['handle'] if ('handle' in handlee) else []

    for mac in device_mac:
        device_list = get_condev(basehost, access_token)
        if mac in device_list:
            for handle in handle_list:
                url = 'http://' + basehost + '/gatt/nodes/' + mac + '/handle/' + str(
                    handle) + '/value/?mac=' + apmac + ''
                headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
                try:
                    response = requests.request('GET', url=url, headers=headers)
                except:
                    time.sleep(3)
                    try:
                        response = requests.request('GET', url=url, headers=headers)
                    except Exception:
                        time.sleep(3)
                        response = requests.request('GET', url=url, headers=headers)
                if response.status_code == 200:
                    result = json.loads(response.content.decode('utf-8'))
                    result = response.content.decode('utf-8')
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + 'Handle' + str(handle) + ' read  result: ' + result)
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + 'Handle' + str(handle) + ' read  failed: ' + response.content.decode(
                        'utf-8') + '(' + str(response.status_code) + ')')


def writeby_handle(basehost, access_token, device_mac, **handlee):
    handle_list = handlee['handle'] if ('handle' in handlee) else []
    if 'value' in handlee:
        value = handlee['value']
    else:
        value = '1111'

    for mac in device_mac:
        device_list = get_condev(basehost, access_token)
        if mac in device_list:
            for handle in handle_list:
                url = 'http://' + basehost + '/gatt/nodes/' + mac + '/handle/' + str(
                    handle) + '/value/' + value + '/?mac=' + apmac + ''
                headers = {'Authorization': 'Bearer ' + access_token, 'content-type': 'application/json'}
                try:
                    response = requests.request('GET', url=url, headers=headers)
                except:
                    time.sleep(3)
                    try:
                        response = requests.request('GET', url=url, headers=headers)
                    except Exception:
                        time.sleep(3)
                        response = requests.request('GET', url=url, headers=headers)
                if response.status_code == 200:
                    result = response.content.decode('utf-8')
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + 'Handle' + str(handle) + ' write result: ' + result)
                else:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + 'Handle' + str(handle) + ' write failed: ' + str(response.status_code))


def scdwrd(basehost, active=0, chip=0, **filter_m):
    filter_name = filter_m['filter_name'] if ('filter_name' in filter_m) else ''
    filter_rssi = str(filter_m['filter_rssi']) if ('filter_rssi' in filter_m) else '-100'
    filter_mac = filter_m['filter_mac'] if ('filter_mac' in filter_m) else ''
    filter_uuid = str(filter_m['filter_uuid']) if ('filter_uuid' in filter_m) else ''
    filter_duplicates = str(filter_m['filter_duplicates']) if ('filter_duplicates' in filter_m) else ''
    url = 'http://' + basehost + '/gap/nodes?event=1&mac=' + apmac + '&chip=' + str(chip) + '&active=' \
          + str(active) + '&filter_name=' + filter_name + '&filter_rssi=' + filter_rssi + '&filter_mac=' \
          + filter_mac + '&filter_uuid=' + filter_uuid + '&filter_duplicates=' + filter_duplicates + ''
    time_start = time.time()
    i = 1
    while True:
        access_token = get_token()
        headers = {'Authorization': 'Bearer ' + access_token}
        try:
            r = requests.get(url, headers=headers, stream=True)
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': requests error occured on scan!\n')
            time.sleep(3)
            r = requests.get(url, headers=headers, stream=True)
        try:
            for line in r.iter_lines():
                time_now = time.time()
                if time_now > time_start + 30 * 60 * i and time_now < time_start + 30 * 60 * (i + 1):
                    i += 1
                    break
                line = str(line, encoding="utf-8")
                if line.startswith('data'):
                    time.sleep(0.1)
                    mutex.acquire()
                    try:
                        line = eval(line[6:])
                    except Exception as e:
                        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        with open('warning.log', 'a') as f:
                            f.write(tag + ': Scan error occured!\n' + str(e) + '\n')
                        break
                    mac = []
                    device_list = []
                    mac_scaned = line['bdaddrs'][0]['bdaddr']
                    mac.append(mac_scaned)
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print('-------------------------------------------------------------------------')
                    print(tag + ': ' + 'Scan device: ' + mac_scaned)
                    result = connect(basehost, access_token, device_mac=mac, device_type="public")
                    if result == 200:
                        # print(device_list)
                        time.sleep(0.25)
                        device_list += get_condev(basehost, access_token)
                        print(device_list)
                        if mac_scaned in device_list:
                            discover(basehost, access_token, device_mac=mac)
                            writeby_handle(basehost, access_token, device_mac=mac, value='0100', handle=[24])
                            # disconnect(basehost, access_token, device_mac=mac)
                        else:
                            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                            print(tag + ': ' + 'Can\'t Hold connection')
                    r.close()
                    mutex.release()
                    break
        except Exception:
            tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open('warning.log', 'a') as f:
                f.write(tag + ': SSE error occured on scdwrd!\n')
            continue


def scan(basehost, access_token, chip, filter_mac, time_scan):
    url = 'http://' + basehost + '/gap/nodes?event=1&mac=' + apmac + '&chip=' + chip + '&filter_mac=' + filter_mac + ''
    headers = {'Authorization': 'Bearer ' + access_token}
    message_num = 0
    message = ''
    try:
        r = requests.get(url, headers=headers, stream=True)
    except Exception:
        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open('warning.log', 'a') as f:
            f.write(tag + ': requests error occured on adv scan!\n')
        time.sleep(3)
        r = requests.get(url, headers=headers, stream=True)
    time_start = time.time()
    try:
        for line in r.iter_lines():
            time_now = time.time()
            if time_now > time_start + time_scan:
                r.close()
                return (message, message_num)
            line = str(line, encoding="utf-8")
            if line.startswith('data'):
                message_num += 1
                message = line[6:]
    except Exception:
        tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open('warning.log', 'a') as f:
            f.write(tag + ': SSE error occured on scan!\n')
        return (message, message_num)


if __name__ == '__main__':
    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open('warning.log', 'a') as f:
        f.write(tag + ': Start test!\n')
    t0 = threading.Thread(target=scdwrd, name="scdwrd:", args=(basehost,), kwargs={'filter_mac': 'AA:AA:AA:88:88*,AA:AA:AA:11:22:3*'})
    t1 = threading.Thread(target=get_constatus, name="get_con_sta:", args=(basehost,))
    t2 = threading.Thread(target=notify, name="notify:", args=(basehost,))

    ###########get_info, set_info test################################

    t0.start()
    t1.start()
    # t2.start()

