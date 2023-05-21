import toml
import subprocess
import json
import base64
import sys
import os
import ipaddress
import uuid
from network_configparser import NetworkConfigParser
from get_logger import get_logger

logger = get_logger('app')


def sudo_call(args):
    if os.geteuid() != 0:
        logger.warning('sudo: {}'.format(args))
        subprocess.check_call(["sudo"] + args)
    else:
        subprocess.check_call(args)


def sudo_call_output(args):
    if os.geteuid() != 0:
        logger.warning('sudo: {}'.format(args))
        return subprocess.check_output(["sudo"] + args, encoding='utf-8')
    else:
        return subprocess.check_output(args, encoding='utf-8')


def ensure_netns(namespace):
    result = json.loads(subprocess.check_output(["ip", "-j", "netns", "list"], encoding='utf-8'))
    for config in result:
        if config['name'] == namespace:
            return
    logger.info('creating network namespace: {}'.format(namespace))
    sudo_call(["ip", "netns", "add", namespace])


def create_wg_device(namespace, name, address, mtu):
    logger.info('creating wireguard device: {}'.format(name))
    sudo_call(["ip", "link", "add", "dev", name, "type", "wireguard"])
    sudo_call(["ip", "link", "set", "dev", name, "netns", namespace])
    sudo_call(["ip", "-n", namespace, "address", "add", "dev", name, address])
    sudo_call(["ip", "-n", namespace, "link", "set", "dev", name, "mtu", str(mtu)])


def assign_wg_device(namespace, name, private_key, listen_port, peer, endpoint, keepalive, allowed_ips):
    config_items = []

    temp_filename = '/tmp/{}.conf'.format(uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(private_key)

    config_items.extend(["private-key", temp_filename])
    if listen_port:
        config_items.extend(["listen-port", str(listen_port)])
    if peer:
        config_items.extend(["peer", peer])
        if endpoint:
            config_items.extend(["endpoint", endpoint])
        if keepalive:
            config_items.extend(["persistent-keepalive", str(keepalive)])
        if allowed_ips:
            config_items.extend(["allowed-ips", allowed_ips])

    sudo_call(["ip", "netns", "exec", namespace, "wg", "set", name] + config_items)
    os.unlink(temp_filename)


def up_wg_device(namespace, name):
    sudo_call(["ip", "-n", namespace, "link", "set", "dev", name, "up"])


def create_veth_device(namespace, name, veth_network):
    host_name = "{}0".format(name)
    peer_name = "{}1".format(name)

    sudo_call(["ip", "link", "add", host_name, "type", "veth", "peer", peer_name])
    sudo_call(["ip", "link", "set", "dev", peer_name, "netns", namespace])
    
    vnetwork = ipaddress.ip_network(veth_network)
    vaddrs = list(vnetwork.hosts())
    host_addr = "{}/{}".format(vaddrs[0], vnetwork.prefixlen)
    peer_addr = "{}/{}".format(vaddrs[1], vnetwork.prefixlen)
    
    sudo_call(["ip", "address", "add", "dev", host_name, host_addr])
    sudo_call(["ip", "-n", namespace, "address", "add", "dev", peer_name, peer_addr])

    sudo_call(["ip", "link", "set", "dev", host_name, "up"])
    sudo_call(["ip", "-n", namespace, "link", "set", "dev", peer_name, "up"])


def config_up(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    if parser.enable_local_network:
        create_veth_device(parser.namespace, parser.local_veth_prefix, parser.local_network)

    for interface_name, interface_config in parser.interfaces.items():
        create_wg_device(parser.namespace, interface_name, interface_config['address'], interface_config['mtu'])
        assign_wg_device(parser.namespace, interface_name, interface_config['private'], interface_config['listen'], interface_config['peer'], interface_config['endpoint'], interface_config['keepalive'], interface_config['allowed'])
        up_wg_device(parser.namespace, interface_name)
    
    temp_filename = '/tmp/{}.conf'.format(uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(parser.network_bird_config)
    
    logger.info('temp bird configuration file generated at: {}'.format(temp_filename))


def config_down(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    
    for interface_name in parser.interfaces:
        result = json.loads(sudo_call_output(["ip", "-j", "-n", parser.namespace, "link"]))
        for if_config in result:
            if if_config['ifname'] == interface_name:
                # Found interface, remove it
                sudo_call(["ip", "-n", parser.namespace, "link", "del", "dev", interface_name])

    if parser.enable_local_network:
        sudo_call(["ip", "link", "del", "dev", "{}0".format(parser.local_veth_prefix)])


if __name__ == "__main__":
    action = sys.argv[1]
    conf_file = sys.argv[2]
    
    config_parser = NetworkConfigParser(toml.loads(open(conf_file).read()))
    if action == 'up':
        config_up(config_parser)
    elif action == 'down':
        config_down(config_parser)
    else:
        logger.error('unknown action {}'.format(action))
