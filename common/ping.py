import time
import subprocess
import traceback
import ipaddress
from common.utils import ns_wrap, sudo_wrap
from common.device import get_interface_state


# get direct ping, return -1 if error
def get_direct_ping_us(network_namespace: str, target_ip: str, ping_count: int=10):
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
    except subprocess.CalledProcessError:
        print(traceback.format_exc())
        print('namespace: {} target: {} count: {} ping unavailable'.format(network_namespace, target_ip, ping_count))
        return -1


def get_peer_ip(network_namespace: str, interface_name: str):
    try:
        interface_state = get_interface_state(network_namespace, interface_name)
        ipaddr = ipaddress.ip_interface(interface_state.address)
        assert isinstance(ipaddr, ipaddress.IPv4Interface)
        ipnet = ipaddr.network

        first_addr = ipnet[1]
        second_addr = ipnet[2]
        if first_addr == ipaddr.ip:
            return str(second_addr)
        else:
            return str(first_addr)
    except subprocess.CalledProcessError:
        print(traceback.format_exc())
        return ''
