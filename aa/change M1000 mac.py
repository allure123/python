#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

# This test tool is used to test: scan, connect, get connected device, discovery(6), write by handle, 
# read by handle, disconnect, notify, get connect status, set info, get info, start/stop adv 18 apis.

import requests
from urllib import request
import json
import re
import sys
import xlwt
import xlrd
from xlutils.copy import copy
import os


basehost = '112.126.95.79/api'
access_token = ''
ID = 'tester'
SECRET = '10b83f9a2e823c47!'
filename = 'result.xls'


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


def set_btmac(ap_mac, ap_bt_mac):
    url = 'http://' + basehost+'/gap/btaddr?mac=' + ap_mac + ''
    headers = {'Authorization': 'Bearer ' + access_token}
    data = {'address': ap_bt_mac}
    response = requests.request('POST', url, headers=headers, json=data)
    if response.status_code == 200:
        print(ap_mac + " write success!")
    else:
        print(ap_mac + " write failed!")


def get_btmac(apmac):
    url = 'http://' + basehost+'/gap/btaddr?mac=' + apmac + ''
    headers = {'Authorization': 'Bearer ' + access_token}
    response = requests.request('Get', url, headers=headers)
    aps_info = json.loads(response.content.decode('utf-8'))
    ap_mac = aps_info['nodes'][0]['bdaddr']
    return ap_mac


def set_all(basehost,access_token):
    url = 'http://' + basehost+'/cassia/hubs'+''
    headers = {'Authorization': 'Bearer ' + access_token}
    response = requests.request('GET', url, headers=headers)
    ap_num = 0
    result = []
    if response.status_code == 200:
        aps_info = json.loads(response.content.decode('utf-8'))
        for ap in aps_info:
            if ap['model'] == "M1000":
                ap_mac = ap['mac']
                result.append([ap_mac])
                ap_mac_offset = mac_handle_offset(ap_mac)
                ap_bt_mac = get_btmac(ap_mac)
                if ap_bt_mac != ap_mac_offset:
                    result[ap_num].append(ap_bt_mac)
                    print(ap_mac + "---" + ap_bt_mac + "---Bluetooth MAC is wrong, correct it!!!")
                    set_btmac(ap_mac, ap_mac_offset)
                    ap_bt_mac = get_btmac(ap_mac)
                    if ap_bt_mac == ap_mac_offset:
                        result[ap_num].append(ap_bt_mac)
                        print(ap_mac + "---" + ap_bt_mac + "---Bluetooth MAC is right now.")
                else:
                    print(ap_mac + "---" + ap_bt_mac + "---Bluetooth MAC is right, no need to change.")
                    result[ap_num].append(ap_bt_mac)
                ap_num += 1
    return result


def mac_handle_offset(mac, offset=2):#默认向后偏移两位,可自己添加偏移数字
    mac_int = 0
    ex = 11
    macaddress = mac.replace(':', '')
    d1 = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
          'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15}
    for i in macaddress:
        mac_int = mac_int + d1[i] * (16 ** ex)
        ex = ex - 1
    mac_int += offset
    mac_hex = str(hex(mac_int))[2:].upper()
    mac_hex = ":".join(re.compile('.{2}').findall(mac_hex))
    return mac_hex.upper()


def save_log(data, logfile):
    head = ["AP_MAC", "BD_MAC_Init", "BD_MAC_Correct"]
    if os.path.exists(logfile):
        data_read = xlrd.open_workbook(filename, formatting_info=True)
        table = data_read.sheets()[0]
        nrows = table.nrows
        xlsc = copy(data_read)
        shtc = xlsc.get_sheet(0)
        for i in range(len(data)):
            for j in range(len(data[i])):
                shtc.write(i+nrows, j, data[i][j])
        xlsc.save(logfile)
    else:
        workBook = xlwt.Workbook(encoding='utf-8')
        sheet = workBook.add_sheet("log")
        for i in range(len(head)):
            sheet.write(0, i, head[i])
        for i in range(len(data)):
            for j in range(len(data[i])):
                sheet.write(i+1,j,data[i][j])
        workBook.save(logfile)


if __name__ == '__main__':
    access_token = get_token()
    test_result = set_all(basehost, access_token)
    save_log(test_result, filename)




