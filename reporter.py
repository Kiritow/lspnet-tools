from network_configparser import load_key_manager
from key_manager import KeyManager
import subprocess
import os
import traceback
import time


def nsexec_wrap(namespace, call_args):
    if namespace:
        call_args = ["ip", "netns", "exec", namespace] + call_args
    return call_args


def check_direct_ping(network_namespace, target_ip, ping_count=10):
    try:
        start_time = time.time()
        print('start ping test')
        sub = subprocess.run(nsexec_wrap(network_namespace, ["ping", "-c", str(ping_count), "-n", "-r", target_ip]), encoding='utf-8', capture_output=True)
        print('ping test finished in {}s'.format(time.time() - start_time))

        for line in sub.stdout.split('\n'):
            if not line.startswith('rtt'):
                continue

            print(line)
            parts = line.split('=')[1].strip().split('/')
            ping_result = max(int(float(parts[1]) * 1000), 0)
            print('namespace: {} target: {} count: {} ping: {}us ({})'.format(network_namespace, target_ip, ping_count, ping_result, parts[1]))
            return ping_result

        print('namespce: {} target: {} count: {} ping not found'.format(network_namespace, target_ip, ping_count))
        return -1
    except Exception:
        print(traceback.format_exc())
        print('namespace: {} target: {} count: {} ping unavailable'.format(network_namespace, target_ip, ping_count))
        return -1


def get_wg_rxtx(network_namespace, device_name):
    output = subprocess.check_output(nsexec_wrap(network_namespace, ["wg", "show", device_name, "dump"]), encoding='utf-8').split('\n')
    line = output[1]
    parts = line.split('\t')

    return int(parts[5]), int(parts[6])


if __name__ == "__main__":
    REPORT_DOMAIN = os.getenv('REPORT_DOMAIN')
    REPORT_NETWORK = os.getenv('REPORT_NETWORK')
    REPORT_HOSTNAME = os.getenv('REPORT_HOSTNAME')
    REPORT_INTERFACE = os.getenv('REPORT_INTERFACE')
    REPORT_IP = os.getenv('REPORT_IP')
    REPORT_NAMESPACE = os.getenv('REPORT_NAMESPACE') or ''
    
    if not REPORT_DOMAIN or not REPORT_NETWORK or not REPORT_HOSTNAME or not REPORT_INTERFACE or not REPORT_IP:
        print('missing env vars')
        exit(1)

    token = load_key_manager(REPORT_DOMAIN, REPORT_NETWORK, REPORT_HOSTNAME)
    if not token:
        print('invalid or empty token')
        exit(1)

    m = KeyManager(REPORT_DOMAIN, token)
    ping_us = check_direct_ping(REPORT_NAMESPACE, REPORT_IP)
    if ping_us < 0:
        ping_us = None

    rx, tx = get_wg_rxtx(REPORT_NAMESPACE, REPORT_INTERFACE)

    m.report_stat(REPORT_INTERFACE, ping_us, rx, tx)
