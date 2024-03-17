import os
import json
from common.ping import check_direct_ping, get_peer_ip


def render_single_hint(hint_tag, ping_data):
    skip = 0
    if 'skips' in hint_tag:
        skip = hint_tag['skip']

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

        if not line.startswith('#HINT:'):
            output.append(line)
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
        ping_result = check_direct_ping(NETWORK_NAMESPACE, peer_ip, ping_count=5)
        if ping_result < 1:
            continue
        ping_data[interface_name] = ping_result

    with open(INPUT_CONFIG) as f:
        content = f.read()
    
    content = render_hint_pingcost(content, ping_data)
    
    # with open(INPUT_CONFIG, 'w') as f:
    #     f.write(content)
    print(content)
