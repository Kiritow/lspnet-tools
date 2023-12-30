import sys
try:
    import tomllib as toml
except ModuleNotFoundError:
    try:
        sys.stderr.write('tomlib not found (python 3.11+), try tomli\n')
        import tomli as toml
    except ModuleNotFoundError:
        sys.stderr.write('tomli not found (pip3 pinstall tomli), try toml\n')
        import toml


import subprocess
import json
import traceback
import os
import ipaddress
import socket
import uuid
import time
import getopt
from prettytable import PrettyTable
from network_configparser import NetworkConfigParser
from network_configparser import create_new_wireguard_keys
from config_types import InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, NetworkMappingConfig, ParserOptions
from get_logger import get_logger


logger = get_logger('app')
INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
logger.info('detected INSTALL_DIR={}'.format(INSTALL_DIR))


def sudo_wrap(args):
    if os.geteuid() != 0:
        logger.warning('sudo: {}'.format(args))
        return ["sudo"] + args
    return args


def ns_wrap(namespace, args):
    if namespace:
        return ["ip", "netns", "exec", namespace] + args
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


def get_tempdir_path(namespace):
    return "/tmp/networktools-{}".format(namespace)


def ensure_tempdir(namespace):
    sudo_call(["mkdir", "-p", get_tempdir_path(namespace)])
    sudo_call(["mkdir", "-p", "{}/router".format(get_tempdir_path(namespace))])


def clear_tempdir(namespace):
    sudo_call(["rm", "-rf", get_tempdir_path(namespace)])


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
                logger.info('endpoint {} resolved to {}'.format(parts[0], real_endpoint))
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


def create_dummy_device(name, address, mtu):
    sudo_call(["ip", "link", "add", name, "type", "dummy"])
    sudo_call(["ip", "address", "add", "dev", name, address])
    sudo_call(["ip", "link", "set", "dev", name, "up"])


def destroy_device_if_exists(namespace, interface_name):
    result = sudo_call_output(ns_wrap(namespace, ["ip", "-j", "link"]))
    print(result)
    result = json.loads(result)

    for if_config in result:
        if if_config['ifname'] == interface_name:
            # Found interface, remove it
            sudo_call(ns_wrap(namespace, ["ip", "link", "del", "dev", interface_name]))


def create_ns_connect(current_namespace, remote_namespace, veth_network):
    ensure_netns(remote_namespace)

    current_dev = "veth-{}".format(current_namespace)
    remote_dev = "veth-{}".format(remote_namespace)

    sudo_call(["ip", "link", "add", current_dev, "type", "veth", "peer", remote_dev])
    sudo_call(["ip", "link", "set", "dev", current_dev, "netns", remote_namespace])
    sudo_call(["ip", "link", "set", "dev", remote_dev, "netns", current_namespace])

    vnetwork = ipaddress.ip_network(veth_network)
    vaddrs = list(vnetwork.hosts())
    current_addr = "{}/{}".format(vaddrs[0], vnetwork.prefixlen)
    remote_addr = "{}/{}".format(vaddrs[1], vnetwork.prefixlen)

    sudo_call(["ip", "-n", current_namespace, "address", "add", "dev", remote_dev, remote_addr])
    sudo_call(["ip", "-n", remote_namespace, "address", "add", "dev", current_dev, current_addr])

    sudo_call(["ip", "-n", current_namespace, "link", "set", "dev", remote_dev, "up"])
    sudo_call(["ip", "-n", remote_namespace, "link", "set", "dev", current_dev, "up"])


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
    try_append_iptables_rule("filter", f"{namespace}-INPUT", ["-p", "tcp", "--dport", str(connector_item.local_port), "-j", "ACCEPT"])

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always", "-E", "RUST_LOG=debug",
               bin_path, "--local", "{}:{}".format(connector_item.local_address, connector_item.local_port), "--remote", str(connector_item.remote), "--tun", connector_item.tun_name, "--tun-local", connector_item.tun_local, "--tun-peer", connector_item.tun_peer])


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


def start_link_reporter(unit_prefix, install_dir, namespace, domain, report_token, interface_item: InterfaceConfig):
    script_path = os.path.join(install_dir, 'reporter.py')
    
    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect",
               "--timer-property", "AccuracySec=10",
               "--timer-property", "RandomizedDelaySec=3",
               "--on-calendar", "*-*-* *:*:00",
               "--property", "RuntimeMaxSec=30",
               "-E", "REPORT_DOMAIN={}".format(domain),
               "-E", "REPORT_TOKEN={}".format(report_token),
               "-E", "REPORT_INTERFACE={}".format(interface_item.short_name),
               "-E", "REPORT_INTERFACE_REAL={}".format(interface_item.name),
               "-E", "REPORT_NAMESPACE={}".format(namespace),
               "python3", script_path,
               ])


def start_endpoint_refresher(unit_prefix, install_dir, namespace, interface_item: InterfaceConfig):
    script_path = os.path.join(install_dir, 'refresher.py')
    
    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect",
               "--timer-property", "AccuracySec=10",
               "--timer-property", "RandomizedDelaySec=3",
               "--on-calendar", "*-*-* *:*:30",
               "--property", "RuntimeMaxSec=15",
               "-E", "NETWORK_NAMESPACE={}".format(namespace),
               "-E", "INTERFACE_NAME={}".format(interface_item.name),
               "-E", "ENDPOINT_ADDR={}".format(interface_item.endpoint),
               "python3", script_path,
               ])


def inspect_podman_router(namespace):
    container_name = "{}-router".format(namespace)

    container_list = sudo_call_output(["podman", "ps", "-a", "--format=json"])
    container_list = json.loads(container_list)
    for container_info in container_list:
        if container_name in container_info['Names']:
            logger.info('found container {} with names: {}'.format(container_info['Id'], container_info['Names']))

            container_inspect_result = sudo_call_output(["podman", "container", "inspect", container_info['Id']])
            container_inspect_result = json.loads(container_inspect_result)

            return container_inspect_result[0]


def shutdown_podman_router(namespace):
    container_inspect_result = inspect_podman_router(namespace)
    if not container_inspect_result:
        return

    logger.info('removing container: {}'.format(container_inspect_result['Id']))
    sudo_call(["podman", "rm", "-f", container_inspect_result['Id']])

    # make sure legacy mount/tmpfiles are cleared
    temp_dirpath = [temp_fullpath.split(':')[0] for temp_fullpath in container_inspect_result["HostConfig"]["Binds"] if temp_fullpath.startswith(get_tempdir_path(namespace))][0]
    logger.info('removing temp directory: {}'.format(temp_dirpath))
    sudo_call(["rm", "-rf", temp_dirpath])


def config_up(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)
    ensure_iptables(parser.namespace)
    ensure_ip_forward(parser.namespace)
    ensure_tempdir(parser.namespace)

    task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
    
    if parser.enable_local_dummy:
        vnetwork = ipaddress.ip_network(parser.local_dummy_interface.address)
        vaddrs = list(vnetwork.hosts())
        local_dummy_snat_address = str(vaddrs[0])
        create_dummy_device(parser.local_dummy_interface.name, "{}/{}".format(vaddrs[0], vnetwork.prefixlen), parser.local_dummy_interface.mtu)

    if parser.enable_local_network and parser.enable_veth_link:
        create_veth_device(parser.namespace, parser.local_veth_prefix, parser.local_interface.address)
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", parser.local_interface.address, "-d", parser.local_interface.address, "-o", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])
        if parser.enable_local_dummy:
            snat_ip = local_dummy_snat_address
        else:
            snat_ip = get_eth_ip(parser.local_interface.name)
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", parser.local_interface.address, "!", "-d", "224.0.0.0/4", "-o", "{}0".format(parser.local_veth_prefix), "-j", "SNAT", "--to", snat_ip])
        try_append_iptables_rule("filter", f"{parser.namespace}-FORWARD", ["-o", "{}0".format(parser.local_veth_prefix), "-j", "ACCEPT"])

    if parser.enable_local_network and parser.local_is_exit_node:
        try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-o", parser.local_interface.name, "-j", "MASQUERADE"])

    if parser.enable_local_network and parser.local_interface.enable_ospf:
        try_append_iptables_rule("filter", f"{parser.namespace}-INPUT", ["-p", "ospf", "-j", "ACCEPT"])

    # Network mapping
    if parser.enable_local_network and parser.local_network_mapping:
        for mapping_config_item in parser.local_network_mapping:
            start_nfq_workers(task_prefix, INSTALL_DIR, parser.namespace, mapping_config_item, parser.local_interface.name)

    # Namespace Connect
    if parser.enable_local_network and parser.local_connect_namespaces:
        for connect_config in parser.local_connect_namespaces:
            create_ns_connect(parser.namespace, connect_config.namespace, connect_config.network)

    # PMTU fix
    sudo_call(["ip", "netns", "exec", parser.namespace, "iptables", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])

    # WireGuard
    for interface_name, interface_item in parser.interfaces.items():
        create_wg_device(parser.namespace, interface_name, interface_item.address, interface_item.mtu)
        assign_wg_device(parser.namespace, interface_name, interface_item.private, interface_item.listen, interface_item.peer, interface_item.endpoint, interface_item.keepalive, interface_item.allowed)
        up_wg_device(parser.namespace, interface_name)

        if interface_item.listen:
            try_append_iptables_rule("filter", f"{parser.namespace}-INPUT", ["-p", "udp", "--dport", str(interface_item.listen), "-j", "ACCEPT"])

        patch_wg_config(parser.namespace, interface_name, interface_item)

        # Cloud Report
        if interface_item.enable_report:
            start_link_reporter(task_prefix, INSTALL_DIR, parser.namespace, parser.manager_domain, parser.report_token, interface_item)

        # Auto Refresh
        if interface_item.autorefresh:
            start_endpoint_refresher(task_prefix, INSTALL_DIR, parser.namespace, interface_item)

        # Connector
        if interface_item.connector:
            connector_item = interface_item.connector
            if isinstance(connector_item, ConnectorPhantunClientConfig):
                start_phantun_client(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name)
            elif isinstance(connector_item, ConnectorPhantunServerConfig):
                start_phantun_server(task_prefix, INSTALL_DIR, parser.namespace, connector_item, parser.local_interface.name, interface_item)

    # BIRD config
    temp_filepath = '/tmp/{}'.format(uuid.uuid4())
    with open(temp_filepath, 'w') as f:
        f.write(parser.network_bird_config)
    logger.info('temp bird configuration file generated at: {}'.format(temp_filepath))
    sudo_call(["mv", temp_filepath, "{}/router/bird.conf".format(get_tempdir_path(parser.namespace))])

    # Remove bird contianer if exists
    shutdown_podman_router(parser.namespace)

    # Start bird container
    logger.info('starting router...')
    sudo_call(["podman", "run", "--network", "ns:/var/run/netns/{}".format(parser.namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}/router:/data:ro".format(get_tempdir_path(parser.namespace)), "--name", "{}-router".format(parser.namespace),
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
        destroy_device_if_exists(parser.namespace, interface_name)

    if parser.enable_local_network and parser.enable_veth_link:
        destroy_device_if_exists('', "{}0".format(parser.local_veth_prefix))

    if parser.enable_local_dummy:
        destroy_device_if_exists('', parser.local_dummy_interface.name)

    # Namespace Connect
    if parser.enable_local_network and parser.local_connect_namespaces:
        for connect_config in parser.local_connect_namespaces:
            interface_name = 'veth-{}'.format(connect_config.namespace)
            destroy_device_if_exists(parser.namespace, interface_name)

    # Stop bird container
    shutdown_podman_router(parser.namespace)

    clear_tempdir(parser.namespace)
    logger.info('network is down.')


def config_update(parser: NetworkConfigParser):
    logger.warning('config update only supports BIRD config reload for now.')
    
    container_inspect_result = inspect_podman_router(parser.namespace)
    if not container_inspect_result:
        return

    # BIRD config
    temp_filepath = '/tmp/{}'.format(uuid.uuid4())
    with open(temp_filepath, 'w') as f:
        f.write(parser.network_bird_config)
    logger.info('temp bird configuration file generated at: {}'.format(temp_filepath))
    sudo_call(["mv", temp_filepath, "{}/router/bird.conf".format(get_tempdir_path(parser.namespace))])

    # Update
    sudo_call(["podman", "exec", container_inspect_result['Id'], "birdc", "configure"])


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


def dump_all_wireguard_state(namespace):
    output = sudo_call_output(ns_wrap(namespace, ["wg", "show", "all", "dump"]))
    interface_states = {}
    for line in output.split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if parts[0] not in interface_states:
            # new interface
            interface_states[parts[0]] = {
                "private": parts[1],
                "public": parts[2],
                "listen": int(parts[3]),
                "fwmark": 0 if parts[4] == 'off' else int(parts[4]),
                "peers": {},
            }
        else:
            interface_states[parts[0]]["peers"][parts[1]] = {
                "preshared": '' if parts[2] == '(none)' else parts[2],
                "endpoint": '' if parts[3] == '(none)' else parts[3],
                "allow": parts[4],
                "handshake": int(parts[5]),
                "rx": int(parts[6]),
                "tx": int(parts[7]),
                "keepalive": 0 if parts[8] == 'off' else int(parts[8]),
            }
    return interface_states


def human_readable_bytes(b):
    if b < 1024:
        return "{} B".format(b)
    if b < 1024 * 1024:
        return "{:.2f} KiB".format(b / 1024)
    if b < 1024 * 1024 * 1024:
        return "{:.2f} MiB".format(b / 1024 / 1024)

    return "{:.2f} GiB".format(b / 1024 / 1024 / 1024)


def human_readable_duration(s):
    if s < 60:
        return "{}s".format(s)
    if s < 60 * 60:
        return "{}m{}s".format(int(s / 60), s % 60)

    return "{}h{}m{}s".format(int(s / 3600), int((s % 3600) / 60), s % 60)


def show_network_status(parser: NetworkConfigParser):
    interface_states = dump_all_wireguard_state(parser.namespace)
    pt = PrettyTable(["Peer Name", "Interface Name", "Listen", "Recv", "Send", "Peer Address", "Keepalive", "Last Handshake"])
    pt_data = []

    for interface_name, interface_config in parser.interfaces.items():
        if interface_name not in interface_states:
            pt.add_row([interface_config.short_name, "<unknown>"])
            continue

        interface_state = interface_states[interface_name]
        peer_state = list(interface_state["peers"].items())[0][1]

        endpoint_status = ''
        if interface_config.endpoint:
            if peer_state['endpoint'] != interface_config.endpoint:
                endpoint_status = '!'
        else:
            endpoint_status = '*'

        pt_data.append([interface_config.short_name, interface_name,
                    "{}{}".format(interface_state['listen'], '*' if interface_state['listen'] != interface_config.listen else ''),
                    human_readable_bytes(peer_state['rx']), human_readable_bytes(peer_state['tx']),
                    "{}{}".format(peer_state['endpoint'] or '-', endpoint_status if peer_state['endpoint'] else ''),
                    human_readable_duration(peer_state['keepalive']) if peer_state['keepalive'] else "-",
                    human_readable_duration(int(time.time() - peer_state['handshake'])) if peer_state['handshake'] else '-'])

    pt_data = sorted(pt_data, key=lambda x: x[0])
    pt.add_rows(pt_data)
    print(pt)


if __name__ == "__main__":
    _opts, args = getopt.getopt(sys.argv[1:], 'hc:', ['config=', 'offline', 'load-cache', 'update-cache'])
    opts = {}
    for k, v in _opts:
        opts[k] = v

    conf_file = opts.get('-c') or opts.get('--config') or os.getenv('CONFIG_FILE')
    if not conf_file and len(args) > 1:
        print('Warning: no config file found in command line options or env vars. will use legacy mode to read config file.')
        conf_file, action = args[0], args[1]
    else:
        action = args[0]

    parser_opts = ParserOptions()
    if action == 'status':
        parser_opts.online_mode = False
        parser_opts.skip_error_validate = True
        parser_opts.skip_bird = True

    if '--offline' in opts:
        parser_opts.online_mode = False
    if '--load-cache' in opts:
        parser_opts.use_cahce = True
    if '--update-cache' in opts:
        parser_opts.use_cahce = True

    logger.info('using config file: {}'.format(conf_file))
    config_parser = NetworkConfigParser(toml.loads(open(conf_file).read()), parser_opts)

    if action == 'up':
        config_up(config_parser)
    elif action == 'down':
        config_down(config_parser)
    elif action == 'update':
        config_update(config_parser)
    elif action == 'import':
        interface_name = sys.argv[3]
        import_wg_keys(config_parser, interface_name)
    elif action == 'rotate':
        interface_name = sys.argv[3]
        if interface_name == 'all':
            for interface_name, interface_config in config_parser.interfaces.items():
                logger.info('rotating keys for {}...'.format(interface_name))
                create_new_wireguard_keys(config_parser.namespace, interface_name)
        else:
            logger.info('rotating keys for {}...'.format(interface_name))
            create_new_wireguard_keys(config_parser.namespace, interface_name)
    elif action == 'list':
        for interface_name, interface_config in config_parser.interfaces.items():
            print("{}\t{}".format(interface_name, interface_config.public))
    elif action == 'status':
        show_network_status(config_parser)
    elif action == 'test':
        print(config_parser.network_bird_config)
    else:
        logger.error('unknown action {}'.format(action))
