import os
import json
import math
from common.ping import check_direct_ping, get_peer_ip
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
            output.append(line)
            continue

        is_valid, hint_data = render_single_hint(hint_tag, ping_data)
        if not is_valid:
            output.append(line)
            continue

        skip, next_lines = hint_data
        output.extend(next_lines)

    return '\n'.join(output)


if __name__ == "__main__":
    NETWORK_NAMESPACE = os.getenv('NETWORK_NAMESPACE') or ''
    INTERFACE_LIST = os.getenv("INTERFACE_LIST") or ''
    INPUT_CONFIG = os.getenv('INPUT_CONFIG') or ''

    if not NETWORK_NAMESPACE or not INTERFACE_LIST or not INPUT_CONFIG:
        print('missing env vars')
        exit(1)

    interfaces = INTERFACE_LIST.split(',')
    ping_data = {}
    for interface_name in interfaces:
        peer_ip = get_peer_ip(NETWORK_NAMESPACE, interface_name)
        ping_us = check_direct_ping(NETWORK_NAMESPACE, peer_ip, ping_count=5)
        if ping_us < 1:
            continue
        ping_data[interface_name] = int(math.ceil(ping_us // 1000))

    with open(INPUT_CONFIG) as f:
        content = f.read()

    content = render_hint_pingcost(content, ping_data)
    content = simple_format(content)

    # with open(INPUT_CONFIG, 'w') as f:
    #     f.write(content)
    print(content)
