
from concurrent.futures import ThreadPoolExecutor
import json
import math
import socket
import subprocess
from threading import Lock
import time
import traceback
import ipaddress
from typing import Any, Optional, cast
import uuid

from common.bird import get_bird_config
from common.config_db import ConfigStore
from common.config_types import BFDConfig, CommonOSPFConfig
from common.device import assign_wg_device, create_veth_device, create_wg_device, destroy_device_if_exists, get_interface_state, dump_all_wireguard_state, up_wg_device
from common.external_tool import start_gost_forwarder
from common.iptables import clear_iptables, dump_iptables, try_check_iptables_rule, try_delete_iptables_rule, try_append_iptables_rule, ensure_iptables
from common.ping import get_direct_ping_us, get_peer_ip
from common.podman import inspect_podman_router, shutdown_podman_router, start_podman_router_via_systemd
from common.utils import clear_tempdir, ensure_ip_forward, ensure_netns, ensure_tempdir, get_all_loaded_services, get_eth_ip, get_tempdir_path, ns_wrap, sudo_call, sudo_wrap, get_install_dir
from common.node_manager import NodeManager
from common.models import LocalGostWorkerStore, RemoteConfigNode, RemoteConfigOSPF, RemoteConfigPeerExtraOSPF, RemoteConfigPeers
from common.types import WireGuardState


def sync_settings_exitnode(remote_state: bool, namespace: str, eth_name: str):
    print("Sync exit node settings...")

    local_state = try_check_iptables_rule("nat", "{}-POSTROUTING".format(namespace), ["-o", eth_name, "-j", "MASQUERADE"])
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


def resolve_endpoint(endpoint: str) -> tuple[str, int]:
    if not endpoint:
        return "", 0

    parts = endpoint.split(':')
    assert len(parts) == 2, "Invalid endpoint format: {}".format(endpoint)
    raw_host, raw_port = parts
    port = int(raw_port)
    raw_ip = socket.gethostbyname(raw_host)
    if raw_ip != raw_host:
        print('endpoint {} resolve to {}'.format(raw_host, raw_ip))
    return raw_ip, port


def parse_multiport_from_peer_extra(extra: str) -> Optional[list[int]]:
    if not extra:
        return None

    try:
        jextra = json.loads(extra)
    except json.JSONDecodeError:
        print("Failed to parse extra field: {}".format(extra))
        return None

    if "multiport" not in jextra:
        print("No multiport config found in extra field")
        return None

    try:
        multiport_arr = jextra["multiport"]
        assert isinstance(multiport_arr, list) and all(isinstance(x, int) for x in multiport_arr), "multiport must be a list of integers" # type: ignore
        multiport_arr = cast(list[int], multiport_arr)
        return multiport_arr
    except Exception as e:
        print("Failed to parse multiport config: {}".format(e))
        return None


def sync_settings_peer_endpoint(namespace: str, expected_name: str, local_state: WireGuardState, peer: RemoteConfigPeers):
    local_peer_state = list(local_state.peers.items())[0][1]

    if local_peer_state.keepalive != peer.keepalive:
        print("Keepalive for {} changed from {} to {}".format(expected_name, local_peer_state.keepalive, peer.keepalive))
        # peer.keepalive could be 0, which will disables keepalive
        subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "persistent-keepalive", str(peer.keepalive)]))

    # Peer could have multiports
    real_peer_endpoint_ip, real_peer_endpoint_port = resolve_endpoint(peer.endpoint)
    current_peer_endpoint_ip, current_peer_endpoint_port = resolve_endpoint(local_peer_state.endpoint)
    multiports = parse_multiport_from_peer_extra(peer.extra)

    # compare ip first
    if current_peer_endpoint_ip != real_peer_endpoint_ip:
        print("Updating endpoint from {}:{} to {}:{}".format(current_peer_endpoint_ip, current_peer_endpoint_port, real_peer_endpoint_ip, real_peer_endpoint_port))
        subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "endpoint", "{}:{}".format(real_peer_endpoint_ip, real_peer_endpoint_port)]))
        return

    # ip is same, check ports...
    if not multiports:
        # single port, compare and exit
        if real_peer_endpoint_port and current_peer_endpoint_port != real_peer_endpoint_port:
            print("Updating endpoint from {}:{} to {}:{}".format(current_peer_endpoint_ip, current_peer_endpoint_port, real_peer_endpoint_ip, real_peer_endpoint_port))
            subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "endpoint", "{}:{}".format(real_peer_endpoint_ip, real_peer_endpoint_port)]))
        return

    real_peer_endpoint_ports = sorted(set([real_peer_endpoint_port] + multiports))
    if current_peer_endpoint_port not in real_peer_endpoint_ports:
        # if current endpoint port is not in any or multiports, use the specified one.
        print("Updating endpoint from {}:{} to {}:{}".format(current_peer_endpoint_ip, current_peer_endpoint_port, real_peer_endpoint_ip, real_peer_endpoint_port))
        subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "endpoint", "{}:{}".format(real_peer_endpoint_ip, real_peer_endpoint_port)]))
        return

    # port is in array. check if we can and need to switch endpoints.
    if not peer.keepalive: # keepalive already synced at the beginning
        # no keepalive, no switch endpoint.
        return
    
    if local_peer_state.handshake and (int(time.time()) - local_peer_state.handshake) < 180: # last handshake was 3 minutes ago?
        print("Last handshake was {} seconds ago.".format(int(peer.keepalive) - local_peer_state.handshake))
        return

    # switch to next port
    try:
        next_port = real_peer_endpoint_ports[real_peer_endpoint_ports.index(current_peer_endpoint_port) + 1]
    except (IndexError, ValueError):
        next_port = real_peer_endpoint_ports[0]

    if next_port != current_peer_endpoint_port:
        print("Updating endpoint from {}:{} to {}:{}".format(current_peer_endpoint_ip, current_peer_endpoint_port, real_peer_endpoint_ip, next_port))
        subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "peer", peer.peerPublicKey, "endpoint", "{}:{}".format(real_peer_endpoint_ip, next_port)]))
        return


def parse_multilisten_from_peer_extra(extra: str) -> Optional[list[int]]:
    if not extra:
        return None

    try:
        jextra = json.loads(extra)
    except json.JSONDecodeError:
        print("Failed to parse extra field: {}".format(extra))
        return None

    if "multilisten" not in jextra:
        print("No multilisten config found in extra field")
        return None

    try:
        multilisten_arr = jextra["multilisten"]
        assert isinstance(multilisten_arr, list) and all(isinstance(x, int) for x in multilisten_arr), "multilisten must be a list of integers" # type: ignore
        multilisten_arr = cast(list[int], multilisten_arr)
        return multilisten_arr
    except Exception as e:
        print("Failed to parse multilisten config: {}".format(e))
        return None


def sync_settings_peer_listen(store: ConfigStore, namespace: str, expected_name: str, local_state: WireGuardState, peer: RemoteConfigPeers):
    current_listen_port = local_state.listen
    remote_multilisten = parse_multilisten_from_peer_extra(peer.extra)
    # We cannot technically "read" states from processess. so we need to store it "somewhere".
    store_key = "multilisten-{}".format(expected_name)
    stored_multilisten = store.get_kv(store_key)
    stored_multilisten = LocalGostWorkerStore.model_validate_json(stored_multilisten) if stored_multilisten else None

    if current_listen_port != peer.listenPort:
        print("Updating listen port from {} to {}".format(current_listen_port, peer.listenPort))
        subprocess.check_call(ns_wrap(namespace, ["wg", "set", expected_name, "listen-port", str(peer.listenPort)]))

    if not stored_multilisten and not remote_multilisten:
        # no multilisten.
        return

    if not stored_multilisten and remote_multilisten:
        # no multilisten locally, got multilisten from remote. setup it
        print("Adding multilisten ports: {}".format(",".join([str(x) for x in remote_multilisten])))
        unit_name = "networktools-{}-worker-{}".format(namespace, str(uuid.uuid4()))
        start_gost_forwarder(unit_name, get_install_dir(), namespace, remote_multilisten, peer.listenPort)

        store_info = LocalGostWorkerStore(unit_name=unit_name, multilisten=sorted(remote_multilisten), dst_port=peer.listenPort)
        store.set_kv(store_key, store_info.model_dump_json())
        return

    if stored_multilisten and not remote_multilisten:
        # multilisten locally, but not remotely. remove it.
        print("Removing multilisten ports: {}, service: {}".format(",".join([str(x) for x in stored_multilisten.multilisten]), stored_multilisten.unit_name))
        service_name = stored_multilisten.unit_name + ".service"
        if service_name in get_all_loaded_services():
            print("Stopping service: {}".format(service_name))
            try:
                sudo_call(["systemctl", "stop", service_name])
            except subprocess.CalledProcessError as e:
                print(traceback.format_exc())
                print("Failed to stop service: {}".format(e))
        store.delete_kv(store_key)
        return
    
    assert stored_multilisten and remote_multilisten, "unlikely"
    # compare local stored multilisten and remote multilisten
    if sorted(stored_multilisten.multilisten) == sorted(remote_multilisten):
        return
    
    # port changed, remove and add the new one
    print("Updating multilisten ports: {} -> {}".format(",".join([str(x) for x in stored_multilisten.multilisten]), ",".join([str(x) for x in remote_multilisten])))
    
    # delete first
    service_name = stored_multilisten.unit_name + ".service"
    if service_name in get_all_loaded_services():
        print("Stopping service: {}".format(service_name))
        try:
            sudo_call(["systemctl", "stop", service_name])
        except subprocess.CalledProcessError as e:
            print(traceback.format_exc())
            print("Failed to stop service: {}".format(e))
    store.delete_kv(store_key)

    # then add the new one
    new_unit_name = "networktools-{}-worker-{}".format(namespace, str(uuid.uuid4()))
    start_gost_forwarder(new_unit_name, get_install_dir(), namespace, remote_multilisten, peer.listenPort)

    store_info = LocalGostWorkerStore(unit_name=new_unit_name, multilisten=sorted(remote_multilisten), dst_port=peer.listenPort)
    store.set_kv(store_key, store_info.model_dump_json())
    return


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
            print("Peer {} exists, check states...".format(expected_name))
            if peer.endpoint:
                sync_settings_peer_endpoint(namespace, expected_name, local_states[expected_name], peer)

            if peer.listenPort:
                sync_settings_peer_listen(store, namespace, expected_name, local_states[expected_name], peer)

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


def get_many_direct_ping_us(namespace: str, interface_names: list[str]):
    ping_data: dict[str, int] = {}
    ping_data_lock = Lock()

    def get_ping(interface_name: str):
        peer_ip = get_peer_ip(namespace, interface_name)
        ping_us = get_direct_ping_us(namespace, peer_ip, ping_count=5)
        with ping_data_lock:
            ping_data[interface_name] = ping_us
    
    max_workers = min(20, len(interface_names))
    print("Create ThreadPool with {} threads to collect ping data".format(max_workers))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for interface_name in interface_names:
            pool.submit(get_ping, interface_name)
    
    return ping_data


def telemetry_report_stat(node_manager: NodeManager, remote_peers: list[RemoteConfigPeers], namespace: str):
    print("Sending Telemetry...")

    local_states: dict[str, WireGuardState] = {}
    try:
        local_states = dump_all_wireguard_state(namespace)
    except subprocess.CalledProcessError:
        print(traceback.format_exc())
    
    link_map: dict[str, int] = {}
    for peer in remote_peers:
        expected_name = "{}-{}".format(namespace, peer.id)
        if expected_name in local_states:
            link_map[expected_name] = peer.id
    
    ping_data = get_many_direct_ping_us(namespace, sorted(link_map.keys()))
    report_data: list[dict[str, Any]] = []
    for interface_name in link_map:
        peer_state = list(local_states[interface_name].peers.values())[0]
        rx, tx = peer_state.rx, peer_state.tx
        report_data.append({
            "id": link_map[interface_name],
            "ping": ping_data[interface_name],
            "rx": rx,
            "tx": tx,
        })

    # send to telemetry server
    node_manager.send_link_telemetry(report_data)


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

    telemetry_report_stat(node_manager, remote_peers, network_namespace)
    
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
