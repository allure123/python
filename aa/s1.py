
import requests
import time,os


##router  扫描性能测试，主要是单芯片 扫描到的数据包和ap数量，router的扫描模式有缺省和连续扫描方式
filter_dev_mac1 = "DC:16:A2:6E:9C:14"####过滤device mac
# filter_dev_mac2 = "DC:16:A2:70:FA:EB"####过滤device mac
# filter_dev_mac3 = "DC:16:A2:6E:9C:14"####过滤device mac
ap_Ip = '192.168.1.104'##1s记录一次
time_run = 60###扫描时间10秒
mode = '连续扫描模式'###哪种方式去扫描 连续扫描还是缺省？
chip = '0' ###那个芯片去扫描
active = '1'
ap_list,ap_protocol,ap_mac_list_version2 = [],[],[]
file_time = time.strftime("%Y%m%d%H%M%S", time.localtime())

#######缺省模式和连续广播模式下，检测扫描到的data及ap的数量

def get_scan_data_ap(mode,chip):
    """**Description**::
            To obtain the configuration of a router, including its IP address, model, version, etc.
            Get:  /api/cassia/hubs/<hubmac>
    """
    re_q = requests.session()
    start_time = time.time()###open?filter_duplicates=1  DUT00000000  AA:AA:AA:11:22:07
    num = 0
    num_mac1 ,num_mac2,num_mac3,dev_rssi1,dev_rssi2,dev_rssi3= 0,0,0,0,0,0
    testresult_dir = "Testresult-" + file_time
    os.mkdir(testresult_dir)
    file_name = os.path.join(testresult_dir, "scan.csv")



    #################
    resp = re_q.get('http://'+ap_Ip+'/gap/nodes?event=1&chip='+chip+'&active='+active, params='',headers='', stream=True)
    print('http://'+ap_Ip+'/gap/nodes?event=1&chip='+chip)
    print('status_code',resp.status_code)
    print('这是过程检查！请耐心等待！ 需要扫描 ',time_run,'秒')

    for lines in resp.iter_lines(decode_unicode="utf-8"):
        with open(file_name, "a+",encoding='utf-8') as f:
            f.write(lines+ "\n")
        now_time = time.time()

        if (now_time - start_time) > time_run:  ######:扫描10秒
            resp.close()
            break

        try:
            if ("data")  in lines :
                num = num +1
                if filter_dev_mac1 in lines :
                    num_mac1 = num_mac1 + 1
                    de_data = eval(lines[6:])
                    dev_rssi = de_data["rssi"]
                    dev_rssi1 =  dev_rssi1 + dev_rssi

                    ###统计 符合filter_dev_mac1 的 mac
                # if filter_dev_mac2 in lines:
                #     num_mac2 = num_mac2 + 1
                #     de_data = eval(lines[6:])
                #     dev_rssi = de_data["rssi"]
                #     dev_rssi2 = dev_rssi2 + dev_rssi


                # if filter_dev_mac3 in lines:
                #     num_mac3 = num_mac3 + 1
                #     de_data = eval(lines[6:])
                #     dev_rssi = de_data["rssi"]
                #     dev_rssi3= dev_rssi3 + dev_rssi


        except Exception:
            print("data error")
            break
    dev_rssi1 = dev_rssi1 / num_mac1
    # dev_rssi2 = dev_rssi2 / num_mac2
    # dev_rssi3 = dev_rssi3 / num_mac3
    print(mode+'： totol numbers  ',str(num))
    print("符合条件的mac包数分别是： ")
    print(filter_dev_mac1,'扫描包数： ',num_mac1," rssi平均值：",dev_rssi1)
    # print(filter_dev_mac2,'扫描包数： ',num_mac2," rssi平均值：",dev_rssi2)
    # print(filter_dev_mac3,'扫描包数： ',num_mac3," rssi平均值：",dev_rssi3)
    with open(file_name, "a+",newline='',encoding='utf-8-sig') as f:
        f.write(str(filter_dev_mac1)+'扫描包数： '+str(num_mac1)+" rssi平均值："+str(dev_rssi1) + "\n")
        # f.write(str(filter_dev_mac2)+'扫描包数： '+ str(num_mac2)+ " rssi平均值："+ str(dev_rssi2)+ "\n")
        # f.write(str(filter_dev_mac3)+'扫描包数： '+ str(num_mac2)+ " rssi平均值："+ str(dev_rssi2)+ "\n")


if __name__ == '__main__':
    get_scan_data_ap(mode,chip)
