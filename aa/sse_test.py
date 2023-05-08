# -*- coding: utf-8 -*-
import requests,logging,sys,threading, json
from urllib import request
from time import sleep

ap_ip = "172.16.60.43"
ap_mac = "CC:1B:E0:E0:DC:BC"
num_sse = 32

ID = 'tester'
SECRET = '10b83f9a2e823c47'
achost = "172.16.60.200/api"


#define sse requests url
scan_url = 'http://' + ap_ip +'/gap/nodes/?event=1&chip=0&mac='+ap_mac
notify_url = 'http://' + ap_ip + '/gatt/nodes/?event=1&mac=' + ap_mac

def log(name):
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    ch_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch_handler.setFormatter(formatter)
    log.addHandler(ch_handler)
    return log

log = log("TEST")


def get_token():
    url = 'http://'+achost+'/oauth2/token'
    data={'grant_type' : 'client_credentials'}
    IDSEC=ID+':'+SECRET
    author=request.base64.b64encode((IDSEC).encode('utf-8'))
    authorize=author.decode('utf-8')
    headers={'Authorization':'Basic '+authorize}
    r = requests.post(url,headers=headers,data=data)
    access_token = json.loads(r.content.decode('utf-8'))['access_token']
    # access_token = json.loads(r.content.decode('utf-8'))
    return access_token


def sse_request(url=notify_url):
    first_flag = 1
    # access_token = get_token()
    # headers = {'Authorization': 'Bearer ' + access_token}
    try:
        response = requests.get(url, stream=True)
        status_code = response.status_code
        current_thread_name = threading.current_thread().getName()
        if status_code == 200:
            for line in response.iter_lines():
                data = line
                if first_flag:
                    # current_thread_name = threading.current_thread().getName()
                    log.info(current_thread_name+"----open success.")
                first_flag = 0
        else:
            res_content = response.content.decode('utf-8')
            log.warning(current_thread_name+"----open failed!")
            sys.exit()
    except Exception:
        log.error("pls check netlink")
        sys.exit()

def test_main():
    T_list = []
    for i in range(1, num_sse+1):
        T = threading.Thread(target=sse_request)
        # T.setDaemon(True)
        T.setName("sse %s"%i)
        T_list.append(T)
    log.info("start %d SSE"%(len(T_list)))
    for j in T_list:
        j.start()
        sleep(0.5)


if __name__ == "__main__":
    lock = threading.Lock()
    run_time = 60
    test_main()
    sleep(run_time)
    sse_max = threading.activeCount()-1
    log.info("The sse max count is %d"%sse_max)
