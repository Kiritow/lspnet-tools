
from concurrent.futures import ThreadPoolExecutor
import json
import math
import socket
import subprocess
from threading import Lock
import traceback
import ipaddress
from typing import Optional
import uuid
from common.bird import get_bird_config
from common.config_db import ConfigStore
from common.config_types import BFDConfig, CommonOSPFConfig
from common.device import assign_wg_device, create_veth_device, create_wg_device, destroy_device_if_exists, get_interface_state, dump_all_wireguard_state, up_wg_device
from common.iptables import clear_iptables, dump_iptables, try_check_iptables_rule, try_delete_iptables_rule, try_append_iptables_rule, ensure_iptables
from common.ping import get_direct_ping_us, get_peer_ip
from common.podman import inspect_podman_router, shutdown_podman_router, start_podman_router_via_systemd
from common.utils import clear_tempdir, ensure_ip_forward, ensure_netns, ensure_tempdir, get_eth_ip, get_tempdir_path, ns_wrap, sudo_call, sudo_wrap
from common.node_manager import NodeManager
from common.models import RemoteConfigNode, RemoteConfigOSPF, RemoteConfigPeerExtraOSPF, RemoteConfigPeers
from common.types import WireGuardState


def sync_settings_exitnode(remote_state: bool, namespace: str, eth_name: str):
    print("Sync exit node settings...")

    local_state = try_check_iptables_rule("nat", "{}-POSTROUTING", ["-o", eth_name, "-j", "MASQUERADE".format(namespace)])
    if local_state and not remote_state:
        print("Removing MASQUERADE rule for exit node")
        try_delete_iptables_rule("nat", "{}-POSTROUTING".format(namespace), ["-o", eth_name, "-j", "MASQUERADE"])
    elif not local_state and remote_state:
        print("Adding MASQUERADE rule for exit node")
        try_append_iptables_rule("nat", "{}-POSTROUTING".format(namespace), ["-o", eth_name, "-j", "MASQUERADE"])


def sync_settings_veth(remote_state: Optional[str], namespace: str, eth_name: str):
    print("Sync veth settings...")

    try:
        local_state = get_interface_state("", "{}-veth0".format(namespace))
    except subprocess.CalledProcessError:
        print(traceback.format_exc())
        local_state = None
    
    if local_state and not remote_state:
        print("Removing veth interface")
        destroy_device_if_exists("", "{}-veth0".format(namespace))
        all_rules = dump_iptables()
        if "nat" in all_rules:
            for rule in all_rules["nat"]:
                if "{}-POSTROUTING".format(namespace) in rule and "#local_veth#" in rule:
                    print("Removing veth rule: {}".format(rule))
                    rule_parts = rule.split()
                    rule_parts = rule_parts[2:] # -A <chain> ...
                    try_delete_iptables_rule("nat", "{}-POSTROUTING".format(namespace), rule.split())
        if "filter" in all_rules:
            for rule in all_rules["filter"]:
                if "{}-FORWARD".format(namespace) in rule and "#local_veth#" in rule:
                    print("Removing veth rule: {}".format(rule))
                    rule_parts = rule.split()
                    rule_parts = rule_parts[2:] # -A <chain> ...
                    try_delete_iptables_rule("filter", "{}-FORWARD".format(namespace), rule.split())
                if "{}-INPUT".format(namespace) in rule and "#local_veth#" in rule:
                    print("Removing veth rule: {}".format(rule))
                    rule_parts = rule.split()
                    rule_parts = rule_parts[2:]
                    try_delete_iptables_rule("filter", "{}-INPUT".format(namespace), rule.split())

    elif not local_state and remote_state:
        print("Adding veth interface")
        create_veth_device(namespace, "{}-veth".format(namespace), remote_state)
        try_append_iptables_rule("nat", "{}-POSTROUTING".format(namespace), ["-s", remote_state, "-d", remote_state, "-o", "{}-veth0".format(namespace), "-j", "ACCEPT", "-m", "comment", "--comment", "#local_veth#"])
        # TODO: dummy interface SNAT
        snat_ip = get_eth_ip(eth_name)
        try_append_iptables_rule("nat", "{}-POSTROUTING".format(namespace), ["-s", remote_state, "!", "-d", "224.0.0.0/4", "-o", "{}-veth0".format(namespace), "-j", "SNAT", "--to", snat_ip, "-m", "comment", "--comment", "#local_veth#"])
        try_append_iptables_rule("filter", "{}-FORWARD".format(namespace), ["-o", "{}-veth0".format(namespace), "-j", "ACCEPT", "-m", "comment", "--comment", "#local_veth#"])
        try_append_iptables_rule("filter", "{}-INPUT".format(namespace), ["-p", "ospf", "-j", "ACCEPT", "-m", "comment", "--comment", "#local_veth#"])


def try_patch_pmtu(namespace: str):
    print("Sync PMTU settings...")

    try:
        subprocess.run(sudo_wrap(["ip", "netns", "exec", namespace, "iptables", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
        print("TCPMSS rule already exists, skipping.")
        return
    except subprocess.CalledProcessError as e:
        if 'iptables: Bad rule (does a matching rule exist in that chain?)' not in e.stderr and 'iptables: No chain/target/match by that name' not in e.stderr:
            raise
    
    print("Adding TCPMSS rule")
    sudo_call(["ip", "netns", "exec", namespace, "iptables", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])


def resolve_endpoint(endpoint: str):
    parts = endpoint.split(':')
    real_endpoint = socket.gethostbyname(parts[0])
    if real_endpoint != parts[0]:
        print('endpoint {} resolve to {}'.format(parts[0], real_endpoint))
        parts[0] = real_endpoint
        real_endpoint = ':'.join(parts)
    else:
        real_endpoint = endpoint
    
    return real_endpoint


def sync_settings_peers(store: ConfigStore, remote_peers: list[RemoteConfigPeers], namespace: str):
    print("Sync peers settings...")

    local_states: dict[str, WireGuardState] = {}
    try:
        local_states = dump_all_wireguard_state(namespace)
    except subprocess.CalledProcessError:
        print(traceback.format_exc())
    
    marked_local_names: list[str] = []
    all_wg_keymap = {x[1]: x[0] for x in store.get_all_wg_keys()} # publicKey -> privateKey

    for peer in remote_peers:
        expected_name = "{}-{}".format(namespace, peer.id)
        if expected_name in local_states:
            marked_local_names.append(expected_name)
            print("Peer {} exists, check endpoint...".format(expected_name))
            if peer.endpoint:
                real_peer_endpoint = resolve_endpoint(peer.endpoint)
                current_peer_endpoint = list(local_states[expected_name].peers.items())[0][1].endpoint
                if current_peer_endpoint != real_peer_endpoint:
                    print("Updating endpoint from {} to {}".format(current_peer_endpoint, real_peer_endpoint))
                    subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "endpoint", real_peer_endpoint]))
            continue

        print("Peer {} does not exist locally, creating.".format(expected_name))
        private_key = all_wg_keymap[peer.publicKey]

        create_wg_device(namespace, expected_name, peer.addressCIDR, peer.mtu or 1420)
        assign_wg_device(namespace, expected_name, private_key, peer.listenPort, peer.peerPublicKey, peer.endpoint, peer.keepalive, "0.0.0.0/0")
        up_wg_device(namespace, expected_name)
        
        if peer.listenPort:
            try_append_iptables_rule("filter", "{}-INPUT".format(namespace), ["-p", "udp", "--dport", str(peer.listenPort), "-j", "ACCEPT", "-m", "comment", "--comment", "#peer_{}#".format(expected_name)])

    to_delete = [name for name in local_states if name not in marked_local_names]
    for to_delete_name in to_delete:
        print("Peer {} does not exist in remote config, deleting...".format(to_delete_name))
        destroy_device_if_exists(namespace, to_delete_name)
        all_rules = dump_iptables()
        if "filter" in all_rules:
            for rule in all_rules["filter"]:
                if "{}-INPUT".format(namespace) in rule and "#peer_{}#".format(to_delete_name) in rule:
                    print("Removing peer rule: {}".format(rule))
                    rule_parts = rule.split()
                    rule_parts = rule_parts[2:]
                    try_delete_iptables_rule("filter", "{}-INPUT".format(namespace), rule_parts)


def ensure_router_container(namespace: str) -> str:
    container_inspect_result = inspect_podman_router(namespace)
    if container_inspect_result:
        # container exists, check state
        if container_inspect_result['State']['Status'] == 'running':
            print("Router container already running")
            return container_inspect_result['Id']
        
        # otherwise, delete it first
        shutdown_podman_router(namespace, clear_temp=False)

    # container does not exist or not running, create it
    print("Creating router container...")
    start_podman_router_via_systemd(namespace)
    print("Router container started")

    container_inspect_result = inspect_podman_router(namespace)
    if not container_inspect_result:
        raise RuntimeError("Failed to create router container")
    
    return container_inspect_result['Id']


def parse_ospf_from_peer_extra(extra: str) -> Optional[RemoteConfigPeerExtraOSPF]:
    if not extra:
        return None

    try:
        jextra = json.loads(extra)
    except json.JSONDecodeError:
        print("Failed to parse extra field: {}".format(extra))
        return None
    
    if "ospf" not in jextra:
        print("No OSPF config found in extra field")
        return None

    try:
        return RemoteConfigPeerExtraOSPF.model_validate(jextra["ospf"])
    except Exception as e:
        print("Failed to parse OSPF config: {}".format(e))
        return None


def get_all_pingcost(namespace: str, interface_names: list[str]):
    ping_data: dict[str, int] = {}
    ping_data_lock = Lock()

    def get_pingcost(interface_name: str):
        peer_ip = get_peer_ip(namespace, interface_name)
        ping_us = get_direct_ping_us(namespace, peer_ip, ping_count=5)
        with ping_data_lock:
            if ping_us < 1:
                ping_data[interface_name] = 500
            else:
                ping_data[interface_name] = max(1, int(math.ceil(ping_us / 1000)))

    max_workers = min(20, len(interface_names))
    print("Create ThreadPool with {} threads to calculate ping costs".format(max_workers))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for interface_name in interface_names:
            pool.submit(get_pingcost, interface_name)

    return ping_data


def sync_settings_bird(remote_peers: list[RemoteConfigPeers], namespace: str, local_veth_cidr: Optional[str] = None, local_ospf_config: Optional[CommonOSPFConfig] = None):
    print("Sync bird settings...")

    local_interface_cidrs = [str(ipaddress.ip_interface(peer.addressCIDR).network) for peer in remote_peers]
    
    bfd_config: dict[str, BFDConfig] = {} # interface_name -> bfd_config
    ospf_area_config: dict[str, dict[str, CommonOSPFConfig]] = {} # area_id -> interface_name -> ospf_config
    ospf_area_config["0"] = {} # area 0
    
    # calculate ping costs
    todo_pingcost_interfaces: list[str] = []
    cost_data: dict[str, int] = {}
    offset_data: dict[str, int] = {}
    for peer in remote_peers:
        expected_name = "{}-{}".format(namespace, peer.id)
        remote_ospf_config = parse_ospf_from_peer_extra(peer.extra)
        if remote_ospf_config and remote_ospf_config.ping:
            todo_pingcost_interfaces.append(expected_name)
            offset_data[expected_name] = remote_ospf_config.offset
        elif remote_ospf_config:
            cost_data[expected_name] = remote_ospf_config.cost
        else:
            print("Peer {} does not have OSPF config, using default cost: 500".format(expected_name))
            cost_data[expected_name] = 500 # default cost, if not specified

    if todo_pingcost_interfaces:
        print("Calculating ping costs for interfaces: {}".format(",".join(todo_pingcost_interfaces)))
        pingcost_data = get_all_pingcost(namespace, todo_pingcost_interfaces)
        for interface_name in pingcost_data:
            pingcost = pingcost_data[interface_name]
            if interface_name in offset_data:
                pingcost += offset_data[interface_name]
            
            cost_data[interface_name] = pingcost
            print("Ping cost calculated for {}: {}".format(interface_name, pingcost))

    for peer in remote_peers:
        expected_name = "{}-{}".format(namespace, peer.id)
        ospf_area_config["0"][expected_name] = CommonOSPFConfig(
            area=0,
            cost=cost_data.get(expected_name, 500),
            auth='',
            type='ptp',
        )
        
        # Use BFD by default
        bfd_config[expected_name] = BFDConfig(
            intervalMs=1000,
            txMs=0, # unspecified
            rxMs=0, # unspecified
            idleMs=5000,
            multiplier=5,
        )
    
    # if has local network (veth)...
    if local_veth_cidr and local_ospf_config:
        ospf_area_config[str(local_ospf_config.area)] = {}
        veth_name = "{}-veth1".format(namespace) # we are inside the network namespace
        ospf_area_config[str(local_ospf_config.area)][veth_name] = local_ospf_config


    bird_config_content = get_bird_config('', [], local_interface_cidrs, [], ospf_area_config, bfd_config)
    
    # Write to temp file first, then move to target file
    temp_filepath = "/tmp/{}".format(str(uuid.uuid4()))
    with open(temp_filepath, 'w') as f:
        f.write(bird_config_content)
    
    print("Temp bird config file created at: {}".format(temp_filepath))
    target_filepath = "{}/router/bird.conf".format(get_tempdir_path(namespace))
    sudo_call(["mv", temp_filepath, target_filepath])
    
    container_id = ensure_router_container(namespace)
    # do hot reload once
    print("Reloading bird config...")
    sudo_call(["podman", "exec", container_id, "birdc", "configure"])
    print("Bird config reloaded")


def convert_remote_node_ospf_to_common_ospf(remote_config_ospf: Optional[RemoteConfigOSPF]) -> Optional[CommonOSPFConfig]:
    if not remote_config_ospf:
        return None
    
    return CommonOSPFConfig(
        area=remote_config_ospf.area,
        cost=remote_config_ospf.cost,
        auth=remote_config_ospf.auth or "",
        type='ptp',
    )


def do_sync_with_remote(node_manager: NodeManager):
    store = node_manager.db
    eth_name = store.get_node_config("ethName")
    assert isinstance(eth_name, str), "ethName must be a string"
    network_namespace = store.get_node_config("namespace")
    assert isinstance(network_namespace, str), "namespace must be a string"
    
    ensure_netns(network_namespace)
    ensure_iptables(network_namespace)
    ensure_ip_forward(network_namespace)
    ensure_tempdir(network_namespace)
    try_patch_pmtu(network_namespace)

    print("Sync keys...")
    node_manager.init_keystore(20)
    node_manager.sync_keystore()
    
    print("Sync node config...")
    res = node_manager.get_config()
    remote_node_config = RemoteConfigNode.model_validate_json(res["config"])
    res = node_manager.get_peers()
    remote_peers = [RemoteConfigPeers.model_validate(x) for x in res["peers"]]
    
    print(remote_node_config)
    print(remote_peers)

    sync_settings_exitnode(remote_node_config.exitNode, network_namespace, eth_name)
    sync_settings_veth(remote_node_config.vethCIDR, network_namespace, eth_name)
    
    sync_settings_peers(store, remote_peers, network_namespace)
    sync_settings_bird(remote_peers, network_namespace, remote_node_config.vethCIDR, convert_remote_node_ospf_to_common_ospf(remote_node_config.ospf))
    
    print("Sync completed")


def do_cleanup_everything(namespace: str):
    print("Cleaning up...")
    ensure_netns(namespace)
    
    # stop all wireguard devices
    interface_states = dump_all_wireguard_state(namespace)
    for interface_name in interface_states:
        print("Stopping wireguard device {}".format(interface_name))
        destroy_device_if_exists(namespace, interface_name)

    print("Stopping veth pairs...")
    destroy_device_if_exists(namespace, "{}-veth1".format(namespace))
    
    print("Cleanup iptables...")
    clear_iptables(namespace)
    
    print("Stop containers...")
    shutdown_podman_router(namespace)
    
    print("Clearing temp dir...")
    clear_tempdir(namespace)
    
    print("Cleanup completed")
