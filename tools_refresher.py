import subprocess
import os
import socket
from common.utils import ns_wrap
from common.device import dump_wireguard_state


def patch_wg_endpoint(network_namespace, device_name, endpoint):
    # DNS resolve first
    parts = endpoint.split(':')
    real_endpoint = socket.gethostbyname(parts[0])
    if real_endpoint != parts[0]:
        print('endpoint {} resolve to {}'.format(parts[0], real_endpoint))
        parts[0] = real_endpoint
        real_endpoint = ':'.join(parts)
    else:
        real_endpoint = endpoint

    current_state = dump_wireguard_state(network_namespace, device_name)
    peer_public, peer_state = list(current_state["peers"].items())[0]
    if peer_state['endpoint'] != real_endpoint:
        print('patching interface {} endpoint from {} to {}'.format(device_name, peer_state['endpoint'], real_endpoint))
        subprocess.check_call(ns_wrap(network_namespace, ["wg", "set", device_name, "peer", peer_public, "endpoint", real_endpoint]))
    else:
        print('interface {} endpoint matches ({}), skipped.'.format(device_name, peer_state['endpoint']))


if __name__ == '__main__':
    NETWORK_NAMESPACE = os.getenv('NETWORK_NAMESPACE') or ''
    INTERFACE_NAME = os.getenv('INTERFACE_NAME')
    ENDPOINT_ADDR = os.getenv('ENDPOINT_ADDR')

    if not INTERFACE_NAME or not ENDPOINT_ADDR:
        print('missing env vars')
        exit(1)

    patch_wg_endpoint(NETWORK_NAMESPACE, INTERFACE_NAME, ENDPOINT_ADDR)
