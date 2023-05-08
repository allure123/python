import json
import requests
import time
import os

ap_Ip = 'http://192.168.1.114'
device_mac = 'DC:16:A2:6E:9C:14'
file_time = time.strftime("%Y%m%d%H%M%S", time.localtime())


def timeCost(time_c, time_s):
    secs = int(time.mktime(time_s))-int(time.mktime(time_c))
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    res_diff_time = "{:02}:{:02}:{:02}".format(h, m, s)
    return res_diff_time


def get_condev(ap_Ip):
    dev_list = []
    url = ap_Ip+'/gap/nodes?connection_state=connected'+''
    response=requests.request('GET', url)
    if response.status_code == 200:
        nodes = json.loads(response.content.decode('utf-8'))['nodes'] if ('nodes' in json.loads(response.content.decode('utf-8'))) else []
        if len(nodes):
            for i in range(0, len(nodes)):
                dev_list.append(nodes[i]['id'])
    else:
        print('Get connected device failed: '+response.content.decode('utf-8')+'('+str(response.status_code)+')')
    return dev_list


def connect(ap_Ip, device_mac, device_type="public", chip='0', auto=0):
    url = ap_Ip+'/gap/nodes/'+device_mac+'/connection?chip='+str(chip)+''
    data = {'timeout': '5000', "type": device_type, 'auto': auto, 'discovergatt': '0'}
    try:
        response = requests.request('POST', url, json=data)
    except Exception:
        time.sleep(3)
        try:
           response = requests.request('POST', url, json=data)
        except Exception:
            time.sleep(3)
            response = requests.request('POST', url, json=data)
    status_code = response.status_code
    result = response.content.decode('utf-8')
    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(tag+': '+'Connect '+device_mac+' status_code:'+str(status_code)+' :'+result)
    return status_code


if __name__ == '__main__':
    testresult_dir = "Testresult-" + file_time
    os.mkdir(testresult_dir)
    file_name = os.path.join(testresult_dir, "scan.csv")
    while True:
        connect_status = connect(ap_Ip, device_mac)
        if connect_status == 200:
            time_c = time.localtime()
            tag_c = time.strftime("%Y-%m-%d %H:%M:%S", time_c)
            with open(file_name, "a+", encoding='utf-8') as f:
                f.write(tag_c+': '+device_mac+' is connected successfully.' + "\n")
            while True:
                dev_list = get_condev(ap_Ip)
                if device_mac in dev_list:
                    tag = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print(tag + ': ' + device_mac + ' is still connected.')
                    time.sleep(10)
                else:
                    time_d = time.localtime()
                    tag_d = time.strftime("%Y-%m-%d %H:%M:%S", time_d)
                    con_duration = timeCost(time_c, time_d)
                    print(tag_d + ': ' + device_mac + ' is disconnected and the connect duration is ' + str(con_duration))
                    with open(file_name, "a+", encoding='utf-8') as f:
                        f.write(tag_d + ': ' + device_mac + ' is disconnected and the connect duration is ' + str(con_duration) + "\n")
                    break
        else:
            time.sleep(10)
