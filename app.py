import sys
import json
import traceback
import os
import ipaddress
import uuid
import time
import getopt
from prettytable import PrettyTable
from network_configparser import NetworkConfigParser
from network_configparser import create_new_wireguard_keys
from common.config_types import InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, ParserOptions
from common.utils import sudo_call, sudo_call_output
from common.utils import ensure_netns, ensure_ip_forward, ensure_tempdir, clear_tempdir
from common.utils import get_eth_ip, get_tempdir_path
from common.utils import human_readable_bytes, human_readable_duration
from common.device import create_dummy_device, create_veth_device, create_ns_connect, destroy_device_if_exists
from common.device import create_wg_device, assign_wg_device, up_wg_device, dump_all_wireguard_state
from common.iptables import ensure_iptables, try_append_iptables_rule, clear_iptables
from common.external_tool import start_nfq_workers, start_link_reporter, start_phantun_client, start_phantun_server, start_endpoint_refresher
from common.podman import inspect_podman_router, shutdown_podman_router, start_podman_router
from common.best_toml import toml
from common.utils import logger


INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
logger.info('detected INSTALL_DIR={}'.format(INSTALL_DIR))


def patch_wg_config(namespace, name, interface_item: InterfaceConfig):
    listen_port = sudo_call_output(["ip", "netns", "exec", namespace, "wg", "show", name, "listen-port"])
    interface_item.listen = int(listen_port)


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
    start_podman_router(parser.namespace)

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
