import sys
import json
import traceback
import os
import ipaddress
import uuid
import time
import argparse
from prettytable import PrettyTable
from network_configparser import NetworkConfigParser
from network_configparser import create_new_wireguard_keys
from common.config_types import InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, ServiceWireGuard, ParserOptions
from common.utils import sudo_call, sudo_call_output
from common.utils import ensure_netns, ensure_ip_forward, ensure_tempdir, clear_tempdir
from common.utils import get_eth_ip, get_tempdir_path, get_all_loaded_services
from common.utils import human_readable_bytes, human_readable_duration
from common.utils import port_segments_to_expression, ports_to_segments
from common.device import create_dummy_device, create_veth_device, create_ns_connect, destroy_device_if_exists
from common.device import create_wg_device, assign_wg_device, up_wg_device, dump_all_wireguard_state
from common.iptables import ensure_iptables, try_append_iptables_rule, clear_iptables
from common.iptables_extra import try_append_iptables_multiple_port_forward_udp
from common.external_tool import start_nfq_workers, start_link_reporter, start_phantun_client, start_phantun_server, start_gost_forwarder, start_endpoint_refresher, start_endpoint_switcher, start_bird_pingcost
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
    
    if parser.enable_local_network and parser.enable_local_dummy:
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

    # Local services
    if parser.enable_local_network and parser.local_services:
        for service_config in parser.local_services:
            if isinstance(service_config, ServiceWireGuard):
                create_wg_device(None, service_config.name, service_config.address, service_config.mtu)
                assign_wg_device(None, service_config.name, service_config.private, service_config.listen, service_config.peer, '', 0, service_config.allowed)
                up_wg_device(None, service_config.name)
                # Don't forget to smile! -- hoshikawa
                if service_config.enable_in_nat:  # external wireguard --> current node --> Connected network
                    wg_network = str(ipaddress.ip_interface(service_config.address).network)
                    if parser.enable_veth_link:
                        if parser.enable_local_dummy:
                            try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", wg_network, "!", "-d", "224.0.0.0/4", "-o", "{}0".format(parser.local_veth_prefix), "-j", "SNAT", "--to", local_dummy_snat_address])
                        else:
                            try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-s", wg_network, "!", "-d", "224.0.0.0/4", "-o", "{}0".format(parser.local_veth_prefix), "-j", "SNAT", "--to", get_eth_ip(parser.local_interface.name)])
                    else:
                        logger.warning("wg_service in-nat enabled but no local veth link configured")

                if service_config.enable_out_nat:  # Connected network --> current node --> external wireguard
                    try_append_iptables_rule("nat", f"{parser.namespace}-POSTROUTING", ["-o", service_config.name, "-j", "MASQUERADE"])

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

        # Multiports
        if interface_item.multiports and interface_item.endpoint:
            start_endpoint_switcher(task_prefix, INSTALL_DIR, parser.namespace, interface_item.name, port_segments_to_expression(ports_to_segments(interface_item.multiports)))

        # Forwarder
        if interface_item.forwarders:
            for forwarder_item in interface_item.forwarders:
                if forwarder_item.type == 'iptables':
                    try_append_iptables_multiple_port_forward_udp(parser.namespace, parser.local_interface.name, forwarder_item.ports, interface_item.listen)
                elif forwarder_item.type == 'gost':
                    start_gost_forwarder(task_prefix, INSTALL_DIR, parser.namespace, forwarder_item.ports, interface_item.listen)

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
    target_bird_filepath = "{}/router/bird.conf".format(get_tempdir_path(parser.namespace))
    sudo_call(["mv", temp_filepath, target_bird_filepath])

    # Remove bird contianer if exists
    shutdown_podman_router(parser.namespace)
    start_podman_router(parser.namespace)

    # pingcost
    pingcost_interfaces = [interface_name for interface_name, interface_item in parser.interfaces.items() if interface_item.enable_ospf and interface_item.ospf_config and interface_item.ospf_config.pingcost]
    if pingcost_interfaces:
        start_bird_pingcost(task_prefix, INSTALL_DIR, parser.namespace, pingcost_interfaces, target_bird_filepath)

    logger.info('network is up.')


def config_down(parser: NetworkConfigParser):
    ensure_netns(parser.namespace)

    # stop all tasks
    task_prefix = "networktools-{}-{}".format(parser.hostname, parser.namespace)
    running_tasks = get_all_loaded_services()
    running_timers = [task for task in running_tasks if task.startswith(task_prefix) and task.endswith('.timer')]
    running_services = [task for task in running_tasks if task.startswith(task_prefix) and task.endswith('.service')]

    logger.info('stopping timers: {}'.format(','.join(running_timers)))
    for timer_name in running_timers:
        try:
            sudo_call(["systemctl", "stop", timer_name])
        except Exception:
            logger.warning('failed to stop {}: {}'.format(timer_name, traceback.format_exc()))

    logger.info('stopping services: {}'.format(','.join(running_services)))
    for service_name in running_services:
        try:
            sudo_call(["systemctl", "stop", service_name])
        except Exception:
            logger.warning('failed to stop {}: {}'.format(service_name, traceback.format_exc()))

    clear_iptables(parser.namespace)

    for interface_name in parser.interfaces:
        destroy_device_if_exists(parser.namespace, interface_name)
    
    if parser.enable_local_network and parser.local_services:
        for service_config in parser.local_services:
            if isinstance(service_config, ServiceWireGuard):
                destroy_device_if_exists('', service_config.name)

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
            pt.add_row([interface_config.short_name, "<unknown>", "", "", "", "", "", ""])
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
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-c', '--config', type=str, help='config file path', action='store')
    arg_parser.add_argument('--offline', help='offline mode', action='store_true')
    arg_parser.add_argument('--cache', help='use cache', action='store_true')
    arg_parser.add_argument('--save', help='save cache', action='store_true')
    arg_parser.add_argument('action', type=str, help='action to perform', action='store')

    args = arg_parser.parse_args()
    conf_file = args.config or os.getenv('CONFIG_FILE')
    if not conf_file:
        sys.stderr.write('missing config file!\n')
        exit(1)

    parser_opts = ParserOptions()
    if args.action == 'status':
        parser_opts.online_mode = False
        parser_opts.skip_error_validate = True
        parser_opts.skip_bird = True

    if args.offline:
        parser_opts.online_mode = False
    if args.cache:
        parser_opts.use_cache = True
    if args.save:
        parser_opts.save_cache = True

    logger.info('using config file: {}'.format(conf_file))
    config_parser = NetworkConfigParser(toml.loads(open(conf_file).read()), parser_opts)

    if args.action == 'up':
        config_up(config_parser)
    elif args.action == 'down':
        config_down(config_parser)
    elif args.action == 'update':
        config_update(config_parser)
    elif args.action == 'import':
        interface_name = sys.argv[3]
        import_wg_keys(config_parser, interface_name)
    elif args.action == 'rotate':
        interface_name = sys.argv[3]
        if interface_name == 'all':
            for interface_name, interface_config in config_parser.interfaces.items():
                logger.info('rotating keys for {}...'.format(interface_name))
                create_new_wireguard_keys(config_parser.namespace, interface_name)
        else:
            logger.info('rotating keys for {}...'.format(interface_name))
            create_new_wireguard_keys(config_parser.namespace, interface_name)
    elif args.action == 'list':
        for interface_name, interface_config in config_parser.interfaces.items():
            print("{}\t{}".format(interface_name, interface_config.public))
    elif args.action == 'status':
        show_network_status(config_parser)
    elif args.action == 'test':
        print(config_parser.network_bird_config)
    else:
        logger.error('unknown action {}'.format(args.action))
