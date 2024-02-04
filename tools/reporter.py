import subprocess
import os
import traceback
import time
import json
import ipaddress
import requests


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


def get_peer_ip(network_namespace, interface_name):
    try:
        content = subprocess.check_output(nsexec_wrap(network_namespace, ["ip", "-j", "address", "show", "dev", interface_name]))
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


def get_wg_rxtx(network_namespace, device_name):
    output = subprocess.check_output(nsexec_wrap(network_namespace, ["wg", "show", device_name, "dump"]), encoding='utf-8').split('\n')
    line = output[1]
    parts = line.split('\t')

    return int(parts[5]), int(parts[6])


def report_link_stat(report_domain, report_token, interface_name, ping, rx, tx):
    try:
        domain_prefix = report_domain
        if not domain_prefix.startswith('https://') and not domain_prefix.startswith('http://'):
            domain_prefix = 'https://' + domain_prefix

        r = requests.post('{}/link/report'.format(domain_prefix), headers={
            'x-service-token': report_token,
        }, json={
            "name": interface_name,
            "ping": ping,
            "rx": rx,
            "tx": tx,
        }, timeout=10)
        print(r.content)
    except Exception:
        print(traceback.format_exc())


if __name__ == "__main__":
    REPORT_DOMAIN = os.getenv('REPORT_DOMAIN')
    REPORT_TOKEN = os.getenv('REPORT_TOKEN')
    REPORT_INTERFACE = os.getenv('REPORT_INTERFACE')
    REPORT_INTERFACE_REAL = os.getenv('REPORT_INTERFACE_REAL')
    REPORT_IP = os.getenv('REPORT_IP') or ''
    REPORT_NAMESPACE = os.getenv('REPORT_NAMESPACE') or ''

    if not REPORT_DOMAIN or not REPORT_TOKEN or not REPORT_INTERFACE or not REPORT_INTERFACE_REAL:
        print('missing env vars')
        exit(1)

    if not REPORT_IP:
        REPORT_IP = get_peer_ip(REPORT_NAMESPACE, REPORT_INTERFACE_REAL)
        print('using REPORT_IP={}'.format(REPORT_IP))

    ping_us = check_direct_ping(REPORT_NAMESPACE, REPORT_IP)
    if ping_us < 0:
        ping_us = None

    rx, tx = get_wg_rxtx(REPORT_NAMESPACE, REPORT_INTERFACE_REAL)
    report_link_stat(REPORT_DOMAIN, REPORT_TOKEN, REPORT_INTERFACE, ping_us, rx, tx)
