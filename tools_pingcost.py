import os
import json
import math
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from common.ping import get_direct_ping_us, get_peer_ip
from common.podman import inspect_podman_router
from common.bird import simple_format


def render_single_hint(hint_tag, ping_data):
    skip = 0
    if 'skips' in hint_tag:
        skip = hint_tag['skips']
        
    interface_name = hint_tag['interface']
    if interface_name not in ping_data:
        return False, None

    return True, (skip, [hint_tag["raw"].format(ping_data[interface_name])])


def render_hint_pingcost(content, ping_data):
    output = []
    skip = 0
    for line in content.split('\n'):
        if skip:
            skip -= 1
            continue

        output.append(line)
        if not line.startswith('#HINT:'):
            continue

        hint_tag = json.loads(line.replace('#HINT: ', ''))
        if hint_tag['type'] != 'cost':
            continue

        is_valid, hint_data = render_single_hint(hint_tag, ping_data)
        if not is_valid:
            continue

        skip, next_lines = hint_data
        output.extend(next_lines)

    return '\n'.join(output)


if __name__ == "__main__":
    NETWORK_NAMESPACE = os.getenv('NETWORK_NAMESPACE') or ''
    INTERFACE_LIST = os.getenv("INTERFACE_LIST") or ''
    INPUT_CONFIG = os.getenv('INPUT_CONFIG') or ''
    DRY_RUN = os.getenv('DRY_RUN') or ''

    if not NETWORK_NAMESPACE or not INTERFACE_LIST or not INPUT_CONFIG:
        print('missing env vars')
        exit(1)

    interfaces = INTERFACE_LIST.split(',')
    ping_data = {}
    ping_data_lock = Lock()

    def process_single_interface(interface_name):
        peer_ip = get_peer_ip(NETWORK_NAMESPACE, interface_name)
        ping_us = get_direct_ping_us(NETWORK_NAMESPACE, peer_ip, ping_count=5)
        if ping_us < 1:
            return
        with ping_data_lock:
            ping_data[interface_name] = max(int(math.ceil(ping_us / 1000)), 1)

    if len(interfaces) < 2:
        process_single_interface(interfaces[0])
    else:
        pool = ThreadPoolExecutor(max_workers=4)
        for interface_name in interfaces:
            pool.submit(process_single_interface, interface_name)

    with open(INPUT_CONFIG) as f:
        content = f.read()

    content = render_hint_pingcost(content, ping_data)
    content = simple_format(content)

    if DRY_RUN:
        print(content)
        exit(0)

    # Update
    container_inspect_result = inspect_podman_router(NETWORK_NAMESPACE)
    if not container_inspect_result:
        print('router container not found for namespace: {}'.format(NETWORK_NAMESPACE))
        exit(1)

    with open(INPUT_CONFIG, 'w') as f:
        f.write(content)

    subprocess.check_call(["podman", "exec", container_inspect_result['Id'], "birdc", "configure"])
