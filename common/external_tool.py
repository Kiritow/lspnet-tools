import os
import uuid
import time
from typing import List

from .config_types import ConnectorPhantunClientConfig, ConnectorPhantunServerConfig, NetworkMappingConfig, InterfaceConfig
from .iptables import try_append_iptables_rule
from .utils import sudo_call, ports_to_segments


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


def start_gost_forwarder(unit_prefix, install_dir, namespace, source_ports, dst_port):
    bin_path = os.path.join(install_dir, "bin", "gost")
    
    port_segs = ports_to_segments(source_ports)
    for seg in port_segs:
        begin_port, end_port = seg
        if end_port != begin_port:
            real_port = "{}:{}".format(begin_port, end_port)
        else:
            real_port = begin_port
        try_append_iptables_rule("filter", f"{namespace}-INPUT", ["-p", "udp", "--dport", str(real_port), "-j", "ACCEPT"])

    call_args = []
    for port in source_ports:
        if port == dst_port:
            continue
        call_args.append("-L=udp://:{}/127.0.0.1:{}".format(port, dst_port))

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always",
               bin_path] + call_args)


def start_socat_udp_forwarder(unit_prefix, namespace, source_ports, dst_port):
    port_segs = ports_to_segments(source_ports)
    for seg in port_segs:
        begin_port, end_port = seg
        if end_port != begin_port:
            real_port = "{}:{}".format(begin_port, end_port)
        else:
            real_port = begin_port
        try_append_iptables_rule("filter", f"{namespace}-INPUT", ["-p", "udp", "--dport", str(real_port), "-j", "ACCEPT"])

    for port in source_ports:
        if port == dst_port:
            continue
        sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect", "--property", "Restart=always",
                   "socat", "UDP-LISTEN:{},reuseaddr,fork".format(port), "UDP:127.0.0.1:{}".format(dst_port)])


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
    script_path = os.path.join(install_dir, 'tools_reporter.py')
    
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
    script_path = os.path.join(install_dir, 'tools_refresher.py')
    
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


def start_endpoint_switcher(unit_prefix, install_dir, namespace, interface_name, port_expression):
    script_path = os.path.join(install_dir, 'tools_switch_endpoint.py')
    
    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect",
               "--timer-property", "AccuracySec=10",
               "--timer-property", "RandomizedDelaySec=3",
               "--on-calendar", "*-*-* *:*:45",
               "--property", "RuntimeMaxSec=15",
               "-E", "NETWORK_NAMESPACE={}".format(namespace),
               "-E", "INTERFACE_NAME={}".format(interface_name),
               "-E", "PORT_EXPRESSION={}".format(port_expression),
               "-E", "START_TIME={}".format(int(time.time())),
               "python3", script_path,
               ])


def start_bird_pingcost(unit_prefix, install_dir, namespace, interface_list: List[str], bird_config_filepath):
    script_path = os.path.join(install_dir, 'tools_pingcost.py')

    sudo_call(["systemd-run", "--unit", "{}-{}".format(unit_prefix, uuid.uuid4()), "--collect",
               "--timer-property", "AccuracySec=10",
               "--timer-property", "RandomizedDelaySec=3",
               "--on-calendar", "*-*-* *:*:00",
               "--property", "RuntimeMaxSec=45",
               "-E", "NETWORK_NAMESPACE={}".format(namespace),
               "-E", "INTERFACE_LIST={}".format(','.join(interface_list)),
               "-E", "INPUT_CONFIG={}".format(bird_config_filepath),
               "python3", script_path,
               ])
