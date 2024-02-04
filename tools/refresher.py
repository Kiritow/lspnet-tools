import subprocess
import os
import traceback
import socket


def nsexec_wrap(namespace, call_args):
    if namespace:
        call_args = ["ip", "netns", "exec", namespace] + call_args
    return call_args


def dump_wireguard_state(network_namespace, device_name):
    output = subprocess.check_output(nsexec_wrap(network_namespace, ["wg", "show", device_name, "dump"]), encoding='utf-8').split('\n')
    interface_state = {}

    for line in output.split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) == 4:
            interface_state = {
                "private": parts[0],
                "public": parts[1],
                "listen": int(parts[2]),
                "fwmark": 0 if parts[3] == 'off' else int(parts[3]),
                "peers": {},
            }
        else:
            interface_state["peers"][parts[0]] = {
                "preshared": '' if parts[1] == '(none)' else parts[1],
                "endpoint": '' if parts[2] == '(none)' else parts[2],
                "allow": parts[3],
                "handshake": int(parts[4]),
                "rx": int(parts[5]),
                "tx": int(parts[6]),
                "keepalive": 0 if parts[7] == 'off' else int(parts[7]),
            }

    return interface_state


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
        subprocess.check_call(nsexec_wrap(network_namespace, ["wg", "set", device_name, peer_public, "endpoint", real_endpoint]))
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
