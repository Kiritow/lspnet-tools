import os
import time
import subprocess
from common.utils import ns_wrap
from common.device import dump_wireguard_state


def check_and_switch_port(network_namespace, device_name, range_from_port, range_to_port):
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
    next_port = current_port + 1
    if next_port >= range_to_port:
        next_port = range_from_port

    if current_port == next_port:
        print('port unchanged')
        return

    next_endpoint = "{}:{}".format(parts[0], next_port)
    print('patching interface {} endpoint from {} to {}'.format(device_name, first_peer['endpoint'], next_endpoint))
    subprocess.check_call(ns_wrap(network_namespace, ["wg", "set", device_name, "peer", first_peer_public, "endpoint", next_endpoint]))


if __name__ == '__main__':
    NETWORK_NAMESPACE = os.getenv('NETWORK_NAMESPACE') or ''
    INTERFACE_NAME = os.getenv('INTERFACE_NAME')
    FROM_PORT = int(os.getenv('FROM_PORT'))
    TO_PORT = int(os.getenv('TO_PORT'))
    
    if not INTERFACE_NAME or not FROM_PORT or not TO_PORT:
        print('missing env vars')
        exit(1)

    check_and_switch_port(NETWORK_NAMESPACE, INTERFACE_NAME, FROM_PORT, TO_PORT)
