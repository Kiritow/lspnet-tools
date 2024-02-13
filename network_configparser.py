import json
import subprocess
import time
import ipaddress
from typing import Dict
from getpass import getpass

from common.config_types import CommonOSPFConfig, InterfaceConfig, ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, ForwarderConfig, NetworkMappingConfig, BFDConfig, NamespaceConnectConfig, DummyInterfaceConfig, ParserOptions
from common.bird import get_bird_config
from common.get_logger import get_logger
from common.key_manager import KeyManager
from common.utils import parse_ports_expression, parse_endpoint_expression
from cache_manager import CacheManager


logger = get_logger('app')


def create_new_wireguard_keys(namespace, name):
    new_key = subprocess.check_output(["wg", "genkey"], encoding='utf-8').strip()
    new_pub = subprocess.check_output(["wg", "pubkey"], encoding='utf-8', input=new_key).strip()
    data = {
        "private": new_key,
        "public": new_pub,
    }
    with open('local/{}.{}.json'.format(namespace, name), 'w') as f:
        f.write(json.dumps(data, ensure_ascii=False))
    return data


def load_or_create_keys(namespace, name):
    try:
        with open('local/{}.{}.json'.format(namespace, name)) as f:
            content = f.read()
        data =  json.loads(content)
        new_key = data['private']
        new_pub = subprocess.check_output(["wg", "pubkey"], encoding='utf-8', input=new_key).strip()
        pub_key = data.get('public', '')
        if pub_key and pub_key != new_pub:
            logger.warning('wireguard public key does not match private key! name: {}'.format(name))
        return {
            "private": new_key,
            "public": new_pub,
        }
    except FileNotFoundError:
        return create_new_wireguard_keys(namespace, name)


def load_key_manager(domain, network, hostname):
    try:
        with open('local/{}.{}.token'.format(network, hostname)) as f:
            token = f.read()
        m = KeyManager(domain, token)
        if not m.validate():
            logger.warn('invalid or expired token found.')
            return None

        return token
    except FileNotFoundError:
        return None


def load_or_login_manager(domain, network, hostname):
    token = load_key_manager(domain, network, hostname)
    if token:
        return token

    m = KeyManager(domain)
    passwd = getpass('[Managed by {}] Password for network `{}`: '.format(domain, network))
    m.login(network, hostname, passwd)

    with open('local/{}.{}.token'.format(network, hostname), 'w') as f:
        f.write(m.token)

    return m.token


class NetworkConfigParser:
    def __init__(self, root_config, parser_opts: ParserOptions):
        self.hostname = root_config['hostname']
        self.namespace = root_config['namespace']
        self.ifname_prefix = root_config.get('prefix', self.hostname)
        self.router_id = root_config.get('routerid', '')

        self.cache_manager : CacheManager = None
        if parser_opts.use_cahce or parser_opts.save_cache:
            self.cache_manager = CacheManager(readonly=not parser_opts.save_cache)

        self.key_manager : KeyManager = None
        self.report_token = ''
        self.manager_domain = root_config.get('manager')
        if self.manager_domain:
            self.managed_network = root_config.get('network', self.namespace)
            if parser_opts.online_mode:
                self.key_manager = KeyManager(self.manager_domain, load_or_login_manager(self.manager_domain, self.managed_network, self.hostname))
            else:
                logger.warning('offline mode detected, skip loading KeyManager')

        local_config = root_config.get('local', {})
        if not local_config:
            logger.warning('no local config found, node will work in forward-mode only')
            self.enable_local_network = False
        else:
            self.enable_local_network = True
            self.enable_veth_link = local_config.get('enable', True)
            self.local_is_exit_node = local_config.get('exit', True)
            self.local_veth_prefix = local_config.get('name', '{}-veth'.format(self.namespace))

            self.enable_local_dummy = 'dummy' in local_config
            if self.enable_local_dummy:
                self.local_dummy_interface = DummyInterfaceConfig(
                    local_config['dummy']['name'],
                    local_config['dummy']['address'],
                    local_config['dummy'].get('mtu', 1500),
                )

            self.local_interface = InterfaceConfig()
            self.local_interface.address = local_config['address']
            self.local_interface.name = local_config['ethname']
            # Local OSPF
            self.local_interface.enable_ospf = local_config.get('ospf', False)
            if self.local_interface.enable_ospf:
                self.local_interface.ospf_config = CommonOSPFConfig(
                    local_config.get('area', 0),
                    local_config.get('cost', 0),
                    local_config.get('auth', ''),
                    'ptp')
            local_mapping_config = local_config.get('mapping', [])

            # Local Network Mapping
            self.local_network_mapping = [
                NetworkMappingConfig(data['from'], data['to'], data['num'], data.get('size', 1024))
                for data in local_mapping_config
            ]

            # Network namespace interconnect
            local_connect_config = local_config.get('connect', [])
            self.local_connect_namespaces = []
            for connect_config in local_connect_config:
                new_connect_config = NamespaceConnectConfig(connect_config["namespace"], connect_config["network"])
                self.local_connect_namespaces.append(new_connect_config)

        network_config = root_config['config']
        self.network_default_enable_ospf = network_config.get('ospf', False)
        self.network_default_ospf_config = CommonOSPFConfig(
            network_config.get('area', 0),
            network_config.get('cost', 0),
            network_config.get('auth', ''),
            'ptp',
        )
        self.network_default_enable_bfd = network_config.get('bfd', False)
        self.network_default_bfd_config = BFDConfig(
            network_config.get('bfd_interval', 0),
            network_config.get('bfd_rx', 0),
            network_config.get('bfd_tx', 0),
            network_config.get('bfd_idle', 0),
            network_config.get('bfd_multiplier', 0),
        )
        self.network_default_enable_report = network_config.get('report', False)

        # Firewall
        firewall_config = root_config.get('firewall', {})
        if not firewall_config:
            logger.warn('no firewall configured. make sure you have UFW enabled or have custom rules configured!')
            self.enable_local_firewall = False
        else:
            self.enable_local_firewall = True

        # Key manager
        cloud_keys = {}
        cloud_links = {}
        if self.cache_manager:
            cloud_keys = self.cache_manager.get('keys') or {}
            cloud_links = self.cache_manager.get('links') or {}
        if self.key_manager:
            cloud_keys = self.key_manager.list_keys()
            cloud_links = self.key_manager.list_links()
            if self.cache_manager:
                self.cache_manager.set('keys', cloud_keys)
                self.cache_manager.set('links', cloud_links)

        # Interfaces
        network_config = root_config['networks']
        self.interfaces : Dict[str, InterfaceConfig] = {}

        for interface_name, interface_config in network_config.items():
            wg_config = load_or_create_keys(self.namespace, interface_name)
            new_interface = InterfaceConfig(
                interface_name,
                "{}-{}".format(self.namespace, interface_name),
                wg_config['private'],
                wg_config['public'],
                interface_config.get('mtu', 1420),
                interface_config.get('address', ''),
                interface_config.get('listen', 0),
                interface_config.get('peer', '') if (self.key_manager or not parser_opts.online_mode) else interface_config['peer'],  # if managed or in offline mode, peer can be empty
                '0.0.0.0/0',
                interface_config.get('endpoint', ''),
                interface_config.get('keepalive', 25 if interface_config.get('endpoint', '') else 0),
                interface_config.get('autorefresh', False),
            )

            # endpoint syntax and multiports
            if new_interface.endpoint:
                endpoint_host, _, endpoint_ports = parse_endpoint_expression(new_interface.endpoint)
                if len(endpoint_ports) > 1:  # new syntax
                    new_interface.endpoint = "{}:{}".format(endpoint_host, endpoint_ports[0])
                elif 'multiport' in interface_config:  # compatiable with old version
                    endpoint_ports = list(range(endpoint_ports[0], endpoint_ports[0] + int(interface_config['multiport'])))
                new_interface.multiports = endpoint_ports

            new_interface.enable_ospf = interface_config.get('ospf', self.network_default_enable_ospf)
            if new_interface.enable_ospf:
                new_interface.ospf_config = CommonOSPFConfig(
                    interface_config.get('area', self.network_default_ospf_config.area),
                    interface_config.get('cost', self.network_default_ospf_config.cost),
                    interface_config.get('auth', self.network_default_ospf_config.auth),
                    'ptp',
                )
            new_interface.enable_bfd = interface_config.get('bfd', self.network_default_enable_bfd)
            if new_interface.enable_bfd:
                new_interface.bfd_config = BFDConfig(
                    interface_config.get('bfd_interval', self.network_default_bfd_config.intervalMs),
                    interface_config.get('bfd_rx', self.network_default_bfd_config.rxMs),
                    interface_config.get('bfd_tx', self.network_default_bfd_config.txMs),
                    interface_config.get('bfd_idle', self.network_default_bfd_config.idleMs),
                    interface_config.get('bfd_multiplier', self.network_default_bfd_config.multiplier),
                )
            new_interface.enable_report = interface_config.get('report', self.network_default_enable_report)

            # Key Manager
            if self.key_manager:
                if interface_name not in cloud_keys or cloud_keys[interface_name] != wg_config['public']:
                    self.key_manager.patch_key(interface_name, wg_config['public'])

                if interface_name not in cloud_links:
                    cloud_links[interface_name] = self.key_manager.create_link(interface_name, new_interface.address, new_interface.mtu, new_interface.keepalive)

                logger.info('patching interface {} with cloud link: {}'.format(interface_name, json.dumps(cloud_links[interface_name])))
                new_interface.address = cloud_links[interface_name]["address"]
                if int(cloud_links[interface_name]["mtu"]) != 0:
                    new_interface.mtu = int(cloud_links[interface_name]["mtu"])
                if int(cloud_links[interface_name]["keepalive"]) != 0:
                    new_interface.keepalive = int(cloud_links[interface_name]["keepalive"])

                # Request report token
                if new_interface.enable_report and not self.report_token:
                    self.report_token = self.key_manager.get_report_token()

            # Validation
            if not new_interface.validate():
                if not parser_opts.skip_error_validate:
                    exit(1)

            if not self.key_manager and new_interface.enable_report and parser_opts.online_mode:
                logger.error('cannot enable reporter with unmanaged network')
                exit(1)

            # Connector
            new_connector = None
            if 'connector' in interface_config:
                connector_config = interface_config['connector']

                if connector_config['type'] == 'phantun-server':
                    new_connector = ConnectorPhantunServerConfig(
                        connector_config['listen'],
                        connector_config['tun-name'],
                        connector_config['tun-local'],
                        connector_config['tun-peer'],
                    )

                    if new_interface.listen == 0:
                        logger.warning('connector type [{}] requires wireguard listen-port not to be zero, a dynamic config will be generated'.format(connector_config['type']))
                        new_connector.remote = '#dynamic'
                    else:
                        new_connector.remote = '127.0.0.1:{}'.format(new_interface.listen)
                elif connector_config['type'] == 'phantun-client':
                    new_connector = ConnectorPhantunClientConfig(
                        '127.0.0.1',
                        connector_config['listen'],
                        connector_config['remote'],
                        connector_config['tun-name'],
                        connector_config['tun-local'],
                        connector_config['tun-peer'],
                    )

                    if new_interface.endpoint:
                        logger.warning('interface [{}] has specified an endpoint ({}), which will be override by connector [{}]'.format(interface_name, new_interface.endpoint, connector_config['type']))

                    new_interface.endpoint = '127.0.0.1:{}'.format(connector_config['listen'])
                else:
                    logger.error('unknown connector type: {}'.format(connector_config['type']))
                    exit(1)

            new_interface.connector = new_connector

            # Forwarder (serverside)
            new_interface.forwarders = []
            if 'forwarder' in interface_config:
                # Compatiable with older version
                forwarder_configs = isinstance(interface_config['forwarder'], list) and interface_config['forwarder'] or [interface_config['forwarder']]
                for forwarder_config in forwarder_configs:
                    # Compatiable with older version
                    if 'from' in forwarder_config and 'to' in forwarder_config:
                        source_ports = list(range(int(forwarder_config['from']), int(forwarder_config['to'])))
                        new_interface.forwarders.append(ForwarderConfig('iptables', source_ports))
                        continue
                    # New Syntax: a,b-c,d
                    source_ports = parse_ports_expression(forwarder_config['ports'])
                    new_interface.forwarders.append(ForwarderConfig('iptables', source_ports))

            self.interfaces[new_interface.name] = new_interface

        # Key Manager
        if self.key_manager:
            todo_keys = {}
            for interface_name, interface_config in network_config.items():
                interface_real_name = "{}-{}".format(self.namespace, interface_name)
                # Cache Manager
                if not self.interfaces[interface_real_name].peer and self.cache_manager:
                    self.interfaces[interface_real_name].peer = self.cache_manager.get('{}.peer'.format(interface_name)) or ''
                if not self.interfaces[interface_real_name].peer:
                    todo_keys[interface_name] = interface_real_name

            retry_counter = 0
            max_retry_times = 60

            while True:
                real_todo_keys = list(todo_keys.keys())
                logger.info('requesting peer key for interface {}...{}'.format(','.join(real_todo_keys), " (tried {} time{})".format(retry_counter, 's' if retry_counter > 1 else '') if retry_counter else ''))
                result_keys = self.key_manager.batch_request_key(real_todo_keys)
                for interface_name in result_keys:
                    self.interfaces[todo_keys[interface_name]].peer = result_keys[interface_name]
                    todo_keys.pop(interface_name)
                    # Cache Manager
                    if self.cache_manager:
                        self.cache_manager.set('{}.peer'.format(interface_name), result_keys[interface_name])

                if not todo_keys:
                    break
                time.sleep(1)
                retry_counter += 1
                if retry_counter >= max_retry_times:
                    logger.error('max retry times exceeded')
                    exit(1)

        if parser_opts.skip_bird:
            return

        # BIRD config
        interface_cidrs = [str(ipaddress.ip_interface(interface_item.address).network) for interface_item in self.interfaces.values() if interface_item.enable_ospf]
        if self.enable_local_network and self.local_interface.enable_ospf:
            interface_cidrs.append(str(ipaddress.ip_network(self.local_interface.address)))

        ospf_area_config = {}
        bfd_config = {}

        for interface_item in self.interfaces.values():
            if not interface_item.enable_ospf:
                continue

            if interface_item.ospf_config.area not in ospf_area_config:
                ospf_area_config[interface_item.ospf_config.area] = {}

            ospf_area_config[interface_item.ospf_config.area][interface_item.name] = interface_item.ospf_config

            # OSPF use BFD
            if interface_item.enable_bfd:
                if interface_item.name not in bfd_config:
                    bfd_config[interface_item.name] = {}

                bfd_config[interface_item.name] = interface_item.bfd_config

        if self.enable_local_network and self.local_interface.enable_ospf:
            if self.local_interface.ospf_config.area not in ospf_area_config:
                ospf_area_config[self.local_interface.ospf_config.area] = {}

            ospf_area_config[self.local_interface.ospf_config.area]["{}1".format(self.local_veth_prefix)] = self.local_interface.ospf_config

        # Accept local connect
        if self.enable_local_network:
            temp_ospf_config = CommonOSPFConfig(0, 1, '', 'ptp')
            ospf_area_config[temp_ospf_config.area]["veth-*"] = temp_ospf_config

        self.network_bird_config = get_bird_config('', [], interface_cidrs, [], ospf_area_config, bfd_config)
        self.network_bird_config_dynamic = get_bird_config('', [], interface_cidrs, [], ospf_area_config, bfd_config, is_dynamic=True)
