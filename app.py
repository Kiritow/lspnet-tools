import toml
import subprocess
import json
import time
import traceback
import sys
import os
import ipaddress
import uuid
from network_configparser import NetworkConfigParser
from config_types import InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig
from get_logger import get_logger


logger = get_logger('app')
INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
logger.info('detected INSTALL_DIR={}'.format(INSTALL_DIR))


def sudo_call(args):
    if os.geteuid() != 0:
        logger.warning('sudo: {}'.format(args))
        subprocess.check_call(["sudo"] + args)
    else:
        subprocess.check_call(args)


def sudo_call_output(args):
    if os.geteuid() != 0:
        logger.info('sudo: {}'.format(args))
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

    temp_filename = '/tmp/{}-{}.conf'.format(namespace, uuid.uuid4())
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


def patch_wg_config(namespace, name, interface_item: InterfaceConfig):
    listen_port = sudo_call_output(["ip", "netns", "exec", namespace, "wg", "show", name, "listen-port"])
    interface_item.listen = int(listen_port)


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


def ensure_iptables(namespace):
    try:
        sudo_call(["iptables", "-t", "nat", "-N", "{}-POSTROUTING".format(namespace)])
        sudo_call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-j", "{}-POSTROUTING".format(namespace)])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables chain exists, skip creation.')

    try:
        sudo_call(["iptables", "-t", "nat", "-N", "{}-PREROUTING".format(namespace)])
        sudo_call(["iptables", "-t", "nat", "-I", "PREROUTING", "-j", "{}-PREROUTING".format(namespace)])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables chain exists, skip creation.')


def clear_iptables(namespace):
    try:
        sudo_call(["iptables", "-t", "nat", "-F", "{}-POSTROUTING".format(namespace)])
    except Exception:
        logger.warning(traceback.format_exc())
    
    try:
        sudo_call(["iptables", "-t", "nat", "-F", "{}-PREROUTING".format(namespace)])
    except Exception:
        logger.warning(traceback.format_exc())


def ensure_ip_forward(namespace):
    sudo_call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sudo_call(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv4.ip_forward=1"])


def get_eth_ip(name):
    result = json.loads(sudo_call_output(["ip", "-j", "address", "show", "dev", name]))
    return [addr_info['local'] for addr_info in result[0]['addr_info'] if addr_info['family'] == 'inet'][0]


def start_phantun_client(unit_prefix, install_dir, namespace, connector_item: ConnectorPhantunClientConfig, eth_name):
    bin_path = os.path.join(install_dir, "bin", "phantun_client")
    
    try:
        sudo_call(["iptables", "-t", "nat", "-C", "{}-POSTROUTING".format(namespace), "-s", connector_item.tun_peer, "-o", eth_name, "-j", "MASQUERADE"])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables rule not exist, try to insert one...')
        sudo_call(["iptables", "-t", "nat", "-A", "{}-POSTROUTING".format(namespace), "-s", connector_item.tun_peer, "-o", eth_name, "-j", "MASQUERADE"])

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_item.local), "--remote", str(connector_item.remote), "--tun", connector_item.tun_name, "--tun-local", connector_item.tun_local, "--tun-peer", connector_item.tun_peer])


def start_phantun_server(unit_prefix, install_dir, namespace, connector_item: ConnectorPhantunServerConfig, eth_name, interface_item: InterfaceConfig):
    bin_path = os.path.join(install_dir, "bin", "phantun_server")
    connector_item.dynamic_inject(interface_item)

    try:
        sudo_call(["iptables", "-t", "nat", "-C", "{}-PREROUTING".format(namespace), "-p", "tcp", "-i", eth_name, "--dport", str(connector_item.local), "-j", "DNAT", "--to-destination", connector_item.tun_peer])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables rule not exist, try to insert one...')
        sudo_call(["iptables", "-t", "nat", "-A", "{}-PREROUTING".format(namespace), "-p", "tcp", "-i", eth_name, "--dport", str(connector_item.local), "-j", "DNAT", "--to-destination", connector_item.tun_peer])


    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_item.local), "--remote", str(connector_item.remote), "--tun", connector_item.tun_name, "--tun-local", connector_item.tun_local, "--tun-peer", connector_item.tun_peer])


def config_up(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    ensure_iptables(parser.namespace)
    ensure_ip_forward(parser.namespace)

    if parser.enable_local_network:
        create_veth_device(parser.namespace, parser.local_veth_prefix, parser.local_interface.address)
        sudo_call(["iptables", "-t", "nat", "-A", "{}-POSTROUTING".format(parser.namespace), "-s", parser.local_interface.address, "-d", parser.local_interface.address, "-o", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])
        sudo_call(["iptables", "-t", "nat", "-A", "{}-POSTROUTING".format(parser.namespace), "-s", parser.local_interface.address, "!", "-d", "224.0.0.0/4", "-o", "{}0".format(parser.local_veth_prefix), "-j", "SNAT", "--to", get_eth_ip(parser.local_interface.name)])

        if parser.local_is_exit_node:
            sudo_call(["iptables", "-t", "nat", "-A", "{}-POSTROUTING".format(parser.namespace), "-o", parser.local_interface.name, "-j", "MASQUERADE"])

    for interface_name, interface_item in parser.interfaces.items():
        create_wg_device(parser.namespace, interface_name, interface_item.address, interface_item.mtu)
        assign_wg_device(parser.namespace, interface_name, interface_item.private, interface_item.listen, interface_item.peer, interface_item.endpoint, interface_item.keepalive, interface_item.allowed)
        up_wg_device(parser.namespace, interface_name)
        patch_wg_config(parser.namespace, interface_name, interface_item)

        # Connector
        task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
        if interface_item.connector:
            connector_item = interface_item.connector
            if isinstance(connector_item, ConnectorPhantunClientConfig):
                start_phantun_client(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name)
            elif isinstance(connector_item, ConnectorPhantunServerConfig):
                start_phantun_server(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name, interface_item)
            else:
                logger.error('unknown connector item: {}'.format(connector_item))

    # BIRD config
    temp_filename = '/tmp/{}-{}.conf'.format(parser.namespace, uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(parser.network_bird_config)

    logger.info('temp bird configuration file generated at: {}'.format(temp_filename))

    # Start bird container
    logger.info('starting router...')
    sudo_call(["podman", "run", "--network", "ns:/var/run/netns/{}".format(parser.namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}:/data/bird.conf:ro".format(temp_filename), "--name", "{}-router".format(parser.namespace),
               "-d", "bird-router"])


def config_down(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
        
    # stop all tasks
    task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
    sudo_call(["systemctl", "stop", "{}-*.timer".format(task_prefix)])
    sudo_call(["systemctl", "stop", "{}-*.service".format(task_prefix)])

    clear_iptables(parser.namespace)

    for interface_name in parser.interfaces:
        result = json.loads(sudo_call_output(["ip", "-j", "-n", parser.namespace, "link"]))
        for if_config in result:
            if if_config['ifname'] == interface_name:
                # Found interface, remove it
                sudo_call(["ip", "-n", parser.namespace, "link", "del", "dev", interface_name])

    if parser.enable_local_network:
        sudo_call(["ip", "link", "del", "dev", "{}0".format(parser.local_veth_prefix)])

    sudo_call(["podman", "container", "exists", "{}-router".format(parser.namespace)])
    container_inspect_result = json.loads(sudo_call_output(["podman", "container", "inspect", "{}-router".format(parser.namespace)]))
    temp_filepath = [temp_fullpath.split(':')[0] for temp_fullpath in container_inspect_result[0]["HostConfig"]["Binds"] if temp_fullpath.startswith('/tmp/{}-'.format(parser.namespace))][0]
    logger.warn('leaving temp file: {}'.format(temp_filepath))

    # Stop bird container
    logger.info('stopping router... (wait 3s for ospf)')
    time.sleep(3)
    sudo_call(["podman", "rm", "-f", "{}-router".format(parser.namespace)])


def load_wg_keys_from_oldconf(wg_conf_name):
    try:
        content = sudo_call_output(["cat", '/etc/wireguard/{}.conf'.format(wg_conf_name)])
        content = content.split('\n')
        for line in content:
            if line.startswith('PrivateKey='):
                return line.replace('PrivateKey=', '').strip()
    except Exception:
        logger.warn(traceback.format_exc())
        return ''


def import_wg_keys(parser: NetworkConfigParser, wg_conf_name):
    private_key = load_wg_keys_from_oldconf(wg_conf_name)
    if not private_key:
        logger.erorr('unable to load private key from wireguard config: {}'.format(wg_conf_name))
        return

    logger.info('loading 1 private key as {}.{}'.format(parser.namespace, wg_conf_name))
    data = {
        'private': private_key,
    }
    with open('local/{}.{}.json'.format(parser.namespace, wg_conf_name), 'w') as f:
        f.write(json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    action = sys.argv[1]
    conf_file = sys.argv[2]

    config_parser = NetworkConfigParser(toml.loads(open(conf_file).read()))
    if action == 'up':
        config_up(config_parser)
    elif action == 'down':
        config_down(config_parser)
    elif action == 'import':
        interface_name = sys.argv[3]
        import_wg_keys(config_parser, interface_name)
    else:
        logger.error('unknown action {}'.format(action))
