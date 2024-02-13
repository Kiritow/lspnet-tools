import os
import time
import subprocess
from typing import List

from common.utils import ns_wrap, parse_ports_expression
from common.device import dump_wireguard_state


def check_and_switch_port(network_namespace, device_name, ports: List[int]):
    interface_state = dump_wireguard_state(network_namespace, device_name)
    first_peer_public, first_peer = list(interface_state['peers'].items())[0]
    if not first_peer['keepalive']:
        print('keepalive not enabled.')
        return
    
    if first_peer['handshake'] and (int(time.time()) - first_peer['handshake']) < 150:
        print('last handshake was {} seconds ago.'.format(int(time.time()) - first_peer['handshake']))
        return

    if not first_peer['endpoint']:
        print('empty endpoint')
        return

    parts = first_peer['endpoint'].split(':')
    current_port = int(parts[1])
    
    # Find current port in ports
    try:
        next_port = ports[ports.index(current_port) + 1]
    except ValueError:
        next_port = ports[0]

    if current_port == next_port:
        print('port unchanged')
        return

    next_endpoint = "{}:{}".format(parts[0], next_port)
    print('patching interface {} endpoint from {} to {}'.format(device_name, first_peer['endpoint'], next_endpoint))
    subprocess.check_call(ns_wrap(network_namespace, ["wg", "set", device_name, "peer", first_peer_public, "endpoint", next_endpoint]))


if __name__ == '__main__':
    NETWORK_NAMESPACE = os.getenv('NETWORK_NAMESPACE') or ''
    INTERFACE_NAME = os.getenv('INTERFACE_NAME')
    START_TIME = int(os.getenv('START_TIME'))

    PORT_EXPRESSION = os.getenv('PORT_EXPRESSION')
    FROM_PORT = int(os.getenv('FROM_PORT'))
    TO_PORT = int(os.getenv('TO_PORT'))

    if not INTERFACE_NAME or not START_TIME:
        print('missing env vars')
        exit(1)

    if PORT_EXPRESSION:
        ports = parse_ports_expression(PORT_EXPRESSION)
    elif FROM_PORT and TO_PORT:
        ports = list(range(FROM_PORT, TO_PORT))  # compatible with old version

    if (int(time.time()) - START_TIME) < 60:
        print('skip checking, too quick since start')
        exit(0)

    check_and_switch_port(NETWORK_NAMESPACE, INTERFACE_NAME, ports)
