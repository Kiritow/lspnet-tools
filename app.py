import sys
try:
    import tomllib as toml
except ModuleNotFoundError:
    try:
        sys.stderr.write('tomlib not found (python 3.11+), try tomli\n')
        import tomli as toml
    except ModuleNotFoundError:
        sys.stderr.write('tomli not found (pip3 pinstall tomli), try tomli\n')
        import toml


import subprocess
import json
import time
import traceback
import os
import ipaddress
import socket
import uuid
from network_configparser import NetworkConfigParser, load_or_create_keys
from config_types import InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, NetworkMappingConfig
from get_logger import get_logger


logger = get_logger('app')
INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
logger.info('detected INSTALL_DIR={}'.format(INSTALL_DIR))


def sudo_wrap(args):
    if os.geteuid() != 0:
        logger.warning('sudo: {}'.format(args))
        return ["sudo"] + args
    return args


def sudo_call(args):
    return subprocess.check_call(sudo_wrap(args))


def sudo_call_output(args):
    return subprocess.check_output(sudo_wrap(args), encoding='utf-8')


def ensure_netns(namespace):
    result = subprocess.check_output(["ip", "-j", "netns", "list"])
    print(result)
    if not result:
        logger.warning('[FIX] ip command does not return valid json text, return empty array')
        result = '[]'

    result = json.loads(result)
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
            # DNS resolve first
            parts = endpoint.split(':')
            real_endpoint = socket.gethostbyname(parts[0])
            if real_endpoint != parts[0]:
                logger.warning('endpoint {} resolve to {}, auto-refresh is not supported yet.'.format(parts[0], real_endpoint))
                parts[0] = real_endpoint
                real_endpoint = ':'.join(parts)
            else:
                real_endpoint = endpoint
            config_items.extend(["endpoint", real_endpoint])
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


def try_create_iptables_chain(table_name, chain_name):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-N", chain_name]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Chain already exists.' not in e.stderr:
            raise

        logger.info('iptables chain {} exists in {} table, skip creation.'.format(chain_name, table_name))


def try_append_iptables_rule(table_name, chain_name, rule_args):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-C", chain_name] + rule_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Bad rule (does a matching rule exist in that chain?)' not in e.stderr and 'iptables: No chain/target/match by that name' not in e.stderr:
            raise

        logger.info('iptables rule not exist, adding: iptables -t {} -A {} {}'.format(table_name, chain_name, ' '.join(rule_args)))
        sudo_call(["iptables", "-t", table_name, "-A", chain_name] + rule_args)


def try_insert_iptables_rule(table_name, chain_name, rule_args):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-C", chain_name] + rule_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Bad rule (does a matching rule exist in that chain?)' not in e.stderr and 'iptables: No chain/target/match by that name' not in e.stderr:
            raise

        logger.info('iptables rule not exist, inserting: iptables -t {} -I {} {}'.format(table_name, chain_name, rule_args))
        sudo_call(["iptables", "-t", table_name, "-I", chain_name] + rule_args)


def try_flush_iptables(table_name, chain_name):
    try:
        sudo_call(["iptables", "-t", table_name, "-F", chain_name])
    except Exception:
        logger.warning(traceback.format_exc())


def ensure_iptables(namespace):
    try_create_iptables_chain("nat", f"{namespace}-POSTROUTING")
    try_insert_iptables_rule("nat", "POSTROUTING", ["-j", "{}-POSTROUTING".format(namespace)])

    try_create_iptables_chain("nat", f"{namespace}-PREROUTING")
    try_insert_iptables_rule("nat", "PREROUTING", ["-j", "{}-PREROUTING".format(namespace)])

    try_create_iptables_chain("raw", f"{namespace}-PREROUTING")
    try_insert_iptables_rule("raw", "PREROUTING", ["-j", "{}-PREROUTING".format(namespace)])

    try_create_iptables_chain("mangle", f"{namespace}-POSTROUTING")
    try_insert_iptables_rule("mangle", "POSTROUTING", ["-j", "{}-POSTROUTING".format(namespace)])
    
    try_create_iptables_chain("filter", f"{namespace}-FORWARD")
    try_insert_iptables_rule("filter", "FORWARD", ["-j", "{}-FORWARD".format(namespace)])

    try_create_iptables_chain("filter", f"{namespace}-INPUT")
    try_insert_iptables_rule("filter", "INPUT", ["-j", "{}-INPUT".format(namespace)])


def clear_iptables(namespace):
    try_flush_iptables("nat", f"{namespace}-POSTROUTING")
    try_flush_iptables("nat", f"{namespace}-PREROUTING")
    try_flush_iptables("raw", f"{namespace}-PREROUTING")
    try_flush_iptables("mangle", f"{namespace}-POSTROUTING")
    try_flush_iptables("filter", f"{namespace}-FORWARD")
    try_flush_iptables("filter", f"{namespace}-INPUT")

    # in namespace
    try:
        sudo_call(["ip", "netns", "exec", namespace, "iptables", "-F", "FORWARD"])
    except Exception:
        logger.warning(traceback.format_exc())


def ensure_ip_forward(namespace):
    sudo_call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sudo_call(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv4.ip_forward=1"])


def get_eth_ip(name):
    result = sudo_call_output(["ip", "-j", "address", "show", "dev", name])
    print(result)
    result = json.loads(result)
    return [addr_info['local'] for addr_info in result[0]['addr_info'] if addr_info['family'] == 'inet'][0]


def start_phantun_client(unit_prefix, install_dir, namespace, connector_item: ConnectorPhantunClientConfig, eth_name):
    bin_path = os.path.join(install_dir, "bin", "phantun_client")
    
    try_append_iptables_rule("nat", f"{namespace}-POSTROUTING", ["-s", connector_item.tun_peer, "-o", eth_name, "-j", "MASQUERADE"])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-i", connector_item.tun_name, "-j", "ACCEPT"])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-o", connector_item.tun_name, "-j", "ACCEPT"])
    try_append_iptables_rule("filter", f"{namespace}-INPUT", ["-p", "tcp", "--dport", str(connector_item.local), "-j", "ACCEPT"])

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_item.local), "--remote", str(connector_item.remote), "--tun", connector_item.tun_name, "--tun-local", connector_item.tun_local, "--tun-peer", connector_item.tun_peer])


def start_phantun_server(unit_prefix, install_dir, namespace, connector_item: ConnectorPhantunServerConfig, eth_name, interface_item: InterfaceConfig):
    bin_path = os.path.join(install_dir, "bin", "phantun_server")
    connector_item.dynamic_inject(interface_item)
    
    try_append_iptables_rule("nat", f"{namespace}-PREROUTING", ["-p", "tcp", "-i", eth_name, "--dport", str(connector_item.local), "-j", "DNAT", "--to-destination", connector_item.tun_peer])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-i", connector_item.tun_name, "-j", "ACCEPT"])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-o", connector_item.tun_name, "-j", "ACCEPT"])
    try_append_iptables_rule("filter", f"{namespace}-INPUT", ["-p", "tcp", "--dport", str(connector_item.local), "-j", "ACCEPT"])

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", str(connector_item.local), "--remote", str(connector_item.remote), "--tun", connector_item.tun_name, "--tun-local", connector_item.tun_local, "--tun-peer", connector_item.tun_peer])


def start_nfq_workers(unit_prefix, install_dir, namespace, config_item: NetworkMappingConfig, eth_name):
    bin_path = os.path.join(install_dir, "bin", "nfq-worker")

    # EGRESS
    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always",
               bin_path, "--mode", "1", "--num", str(config_item.queue_number), "--len", str(config_item.queue_size), "--from", config_item.from_addr, "--to", config_item.to_addr])

    # INGRESS
    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always",
               bin_path, "--mode", "2", "--num", str(config_item.queue_number + 1), "--len", str(config_item.queue_size), "--from", config_item.to_addr, "--to", config_item.from_addr])

    # EGRESS
    try_append_iptables_rule("mangle", f"{namespace}-POSTROUTING", ["-o", eth_name, "-d", config_item.from_addr, "-j", "NFQUEUE", "--queue-num", str(config_item.queue_number)])

    # INGRESS
    try_append_iptables_rule("raw", f"{namespace}-PREROUTING", ["-i", eth_name, "-s", config_item.to_addr, "-j", "NFQUEUE", "--queue-num", str(config_item.queue_number + 1)])


def config_up(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    ensure_iptables(parser.namespace)
    ensure_ip_forward(parser.namespace)

    task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)

    if parser.enable_local_network and parser.enable_veth_link:
        create_veth_device(parser.namespace, parser.local_veth_prefix, parser.local_interface.address)
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", parser.local_interface.address, "-d", parser.local_interface.address, "-o", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", parser.local_interface.address, "!", "-d", "224.0.0.0/4", "-o", "{}0".format(parser.local_veth_prefix), "-j", "SNAT", "--to", get_eth_ip(parser.local_interface.name)])
        try_append_iptables_rule("filter", f"{parser.namespace}-FORWARD", ["-o", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])
        try_append_iptables_rule("filter", f"{parser.namespace}-FORWARD", ["-i", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])

    if parser.enable_local_network and parser.local_is_exit_node:
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-o", parser.local_interface.name, "-j", "MASQUERADE"])
        try_append_iptables_rule("filter", f"{parser.namespace}-FORWARD", ["-i", "{}0".format(parser.local_veth_prefix), "-o", parser.local_interface.name, "-j", "ACCEPT"])

    if parser.enable_local_network and parser.local_interface.enable_ospf:
        try_append_iptables_rule("filter", f"{parser.namespace}-INPUT", ["-p", "ospf", "-j", "ACCEPT"])

    # Network mapping
    if parser.enable_local_network and parser.local_network_mapping:
        for mapping_config_item in parser.local_network_mapping:
            start_nfq_workers(task_prefix, INSTALL_DIR, parser.namespace, mapping_config_item, parser.local_interface.name)

    # PMTU fix
    sudo_call(["ip", "netns", "exec", parser.namespace, "iptables", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])

    # WireGuard
    for interface_name, interface_item in parser.interfaces.items():
        create_wg_device(parser.namespace, interface_name, interface_item.address, interface_item.mtu)
        assign_wg_device(parser.namespace, interface_name, interface_item.private, interface_item.listen, interface_item.peer, interface_item.endpoint, interface_item.keepalive, interface_item.allowed)
        up_wg_device(parser.namespace, interface_name)
        patch_wg_config(parser.namespace, interface_name, interface_item)

        # Connector
        if interface_item.connector:
            connector_item = interface_item.connector
            if isinstance(connector_item, ConnectorPhantunClientConfig):
                start_phantun_client(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name)
            elif isinstance(connector_item, ConnectorPhantunServerConfig):
                start_phantun_server(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name, interface_item)

    # BIRD config
    temp_filename = '/tmp/{}-{}.conf'.format(parser.namespace, uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(parser.network_bird_config)

    logger.info('temp bird configuration file generated at: {}'.format(temp_filename))

    # Remove bird contianer if exists
    try:
        sudo_call(["podman", "container", "exists", "{}-router".format(parser.namespace)])
        logger.info('found existing container, remove it...')
        sudo_call(["podman", "rm", "-f", "{}-router".format(parser.namespace)])
    except Exception:
        logger.warning(traceback.format_exc())
        logger.warning('container does not exist, skip removing.')

    # Start bird container
    logger.info('starting router...')
    sudo_call(["podman", "run", "--network", "ns:/var/run/netns/{}".format(parser.namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}:/data/bird.conf:ro".format(temp_filename), "--name", "{}-router".format(parser.namespace),
               "-d", "bird-router"])

    logger.info('network is up.')


def config_down(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)

    # stop all tasks
    task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
    sudo_call(["systemctl", "stop", "{}-*.timer".format(task_prefix)])
    sudo_call(["systemctl", "stop", "{}-*.service".format(task_prefix)])

    clear_iptables(parser.namespace)

    for interface_name in parser.interfaces:
        result = sudo_call_output(["ip", "-j", "-n", parser.namespace, "link"])
        print(result)
        result = json.loads(result)
        for if_config in result:
            if if_config['ifname'] == interface_name:
                # Found interface, remove it
                sudo_call(["ip", "-n", parser.namespace, "link", "del", "dev", interface_name])

    if parser.enable_local_network and parser.enable_veth_link:
        sudo_call(["ip", "link", "del", "dev", "{}0".format(parser.local_veth_prefix)])

    sudo_call(["podman", "container", "exists", "{}-router".format(parser.namespace)])
    container_inspect_result = json.loads(sudo_call_output(["podman", "container", "inspect", "{}-router".format(parser.namespace)]))
    temp_filepath = [temp_fullpath.split(':')[0] for temp_fullpath in container_inspect_result[0]["HostConfig"]["Binds"] if temp_fullpath.startswith('/tmp/{}-'.format(parser.namespace))][0]

    # Stop bird container
    logger.info('stopping router... (wait 3s for ospf)')
    time.sleep(3)
    sudo_call(["podman", "rm", "-f", "{}-router".format(parser.namespace)])
    
    logger.info('removing temp file: {}'.format(temp_filepath))
    sudo_call(["rm", "-f", temp_filepath])

    logger.info('network is down.')


def load_wg_keys_from_oldconf(wg_conf_name):
    try:
        content = sudo_call_output(["cat", '/etc/wireguard/{}.conf'.format(wg_conf_name)])
        content = content.split('\n')
        for line in content:
            if line.startswith('PrivateKey='):
                return line.replace('PrivateKey=', '').strip()
    except Exception:
        logger.warning(traceback.format_exc())
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
    conf_file = sys.argv[1]
    action = sys.argv[2]
    
    # compatible with old version
    if not os.path.exists(conf_file) and os.path.exists(action):
        logger.warning('new version requires conf_file as 1st place. please adjust your script to avoid future breaking changes')
        conf_file, action = action, conf_file

    logger.info('using config file: {}'.format(conf_file))
    config_parser = NetworkConfigParser(toml.loads(open(conf_file).read()))

    if action == 'up':
        config_up(config_parser)
    elif action == 'down':
        config_down(config_parser)
    elif action == 'import':
        interface_name = sys.argv[3]
        import_wg_keys(config_parser, interface_name)
    elif action == 'list':
        for interface_name, interface_config in config_parser.interfaces.items():
            print("{}\t{}".format(interface_name, interface_config.public))
    elif action == 'test':
        print(config_parser.network_bird_config)
    else:
        logger.error('unknown action {}'.format(action))
