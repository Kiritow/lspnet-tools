import time
import subprocess
import traceback
import json
import ipaddress
from common.utils import ns_wrap, sudo_wrap


# get direct ping, return -1 if error
def get_direct_ping_us(network_namespace, target_ip, ping_count=10):
    try:
        start_time = time.time()
        print('start ping test')
        sub = subprocess.run(sudo_wrap(ns_wrap(network_namespace, ["ping", "-c", str(ping_count), "-n", "-r", target_ip])), encoding='utf-8', capture_output=True)
        print('ping test finished in {}s'.format(time.time() - start_time))

        for line in sub.stdout.split('\n'):
            if not line.startswith('rtt'):
                continue

            print(line)
            parts = line.split('=')[1].strip().split('/')
            ping_result = max(0, int(float(parts[1]) * 1000))
            print('namespace: {} target: {} count: {} ping: {}us ({})'.format(network_namespace, target_ip, ping_count, ping_result, parts[1]))
            return ping_result

        print('namespce: {} target: {} count: {} ping not found'.format(network_namespace, target_ip, ping_count))
        return -1
    except Exception:
        print(traceback.format_exc())
        print('namespace: {} target: {} count: {} ping unavailable'.format(network_namespace, target_ip, ping_count))
        return -1


def get_peer_ip(network_namespace, interface_name):
    try:
        content = subprocess.check_output(sudo_wrap(ns_wrap(network_namespace, ["ip", "-j", "address", "show", "dev", interface_name])))
        content = json.loads(content)
        ipnet = ipaddress.ip_interface("{}/{}".format(content[0]['addr_info'][0]['local'], content[0]['addr_info'][0]['prefixlen'])).network
        first_addr = str(ipnet[1])
        second_addr = str(ipnet[2])
        if first_addr == content[0]['addr_info'][0]['local']:
            return str(second_addr)
        else:
            return str(first_addr)
    except Exception:
        print(traceback.format_exc())
        return ''
