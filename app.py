import toml
import subprocess
import json
import base64
import traceback
import sys
import os
import ipaddress
import uuid
from network_configparser import NetworkConfigParser
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


def patch_wg_config(namespace, name, config):
    listen_port = sudo_call_output(["ip", "netns", "exec", namespace, "wg", "show", name, "listen-port"])
    config['listen'] = int(listen_port)


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


def start_phantun_client(unit_prefix, install_dir, namespace, connector_config, eth_name):
    bin_path = os.path.join(install_dir, "bin", "phantun_client")
    
    try:
        sudo_call(["iptables", "-t", "nat", "-C", "{}-POSTROUTING".format(namespace), "-s", connector_config['tun-peer'], "-o", eth_name])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables rule not exist, try to insert one...')
        sudo_call(["iptables", "-t", "nat", "-I", "{}-POSTROUTING".format(namespace), "-s", connector_config['tun-peer'], "-o", eth_name])

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_config['local']), "--remote", str(connector_config['remote']), "--tun", connector_config['tun-name'], "--tun-local", connector_config['tun-local'], "--tun-peer", connector_config['tun-peer']])


def start_phantun_server(unit_prefix, install_dir, namespace, connector_config, eth_name, interface_config):
    bin_path = os.path.join(install_dir, "bin", "phantun_server")
    if connector_config['remote'].startswith('dynamic#'):
        logger.info('resolving dynamic config: {}'.format(connector_config['remote']))
        connector_config['remote'] = connector_config['remote'].split('#')[1].format(**interface_config)
        logger.info('resolved dynamic config: {}'.format(connector_config['remote']))

    try:
        sudo_call(["iptables", "-t", "nat", "-C", "{}-PREROUTING".format(namespace), "-p", "tcp", "-i", eth_name, "--dport", str(connector_config['local']), "-j", "DNAT", "--to-destination", connector_config['tun-peer']])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.info('iptables rule not exist, try to insert one...')
        sudo_call(["iptables", "-t", "nat", "-I", "{}-PREROUTING".format(namespace), "-p", "tcp", "-i", eth_name, "--dport", str(connector_config['local']), "-j", "DNAT", "--to-destination", connector_config['tun-peer']])


    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_config['local']), "--remote", str(connector_config['remote']), "--tun", connector_config['tun-name'], "--tun-local", connector_config['tun-local'], "--tun-peer", connector_config['tun-peer']])


def config_up(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    ensure_iptables(parser.namespace)

    if parser.enable_local_network:
        create_veth_device(parser.namespace, parser.local_veth_prefix, parser.local_network)

    # BIRD config
    temp_filename = '/tmp/{}.conf'.format(uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(parser.network_bird_config)
    
    logger.info('temp bird configuration file generated at: {}'.format(temp_filename))

    for interface_name, interface_config in parser.interfaces.items():
        create_wg_device(parser.namespace, interface_name, interface_config['address'], interface_config['mtu'])
        assign_wg_device(parser.namespace, interface_name, interface_config['private'], interface_config['listen'], interface_config['peer'], interface_config['endpoint'], interface_config['keepalive'], interface_config['allowed'])
        up_wg_device(parser.namespace, interface_name)
        patch_wg_config(parser.namespace,interface_name, interface_config)

        # Connector
        task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
        if interface_config['connector']:
            connector_config = interface_config['connector']
            if connector_config['type'] == 'phantun-client':
                start_phantun_client(task_prefix, INSTALL_DIR, parser.namespace, connector_config, parser.local_ethname)
            elif connector_config['type'] == 'phantun-server':
                start_phantun_server(task_prefix, INSTALL_DIR, parser.namespace, connector_config, parser.local_ethname, interface_config)
            else:
                logger.error('unknown connector type: {}'.format(connector_config['type']))


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
