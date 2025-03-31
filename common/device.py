import os
import socket
import ipaddress
from typing import Optional
import uuid
import json
import time

from .types import InterfaceState, WireGuardPeerState, WireGuardState
from .utils import sudo_call, sudo_call_output, ns_wrap, ensure_netns
from .utils import logger


def create_wg_device(namespace: str, name: str, address: str, mtu: int):
    logger.info('creating wireguard device: {}'.format(name))
    sudo_call(["ip", "link", "add", "dev", name, "type", "wireguard"])
    if namespace:
        sudo_call(["ip", "link", "set", "dev", name, "netns", namespace])
    
    sudo_call(ns_wrap(namespace, ["ip", "address", "add", "dev", name, address]))
    sudo_call(ns_wrap(namespace, ["ip", "link", "set", "dev", name, "mtu", str(mtu)]))


def assign_wg_device(namespace: str, name: str, private_key: str, listen_port: int, peer: str, endpoint: str, keepalive: int, allowed_ips: str):
    config_args: list[str] = []

    temp_filename = '/tmp/{}.conf'.format(uuid.uuid4())
    with open(temp_filename, 'w') as f:
        f.write(private_key)

    config_args.extend(["private-key", temp_filename])
    if listen_port:
        config_args.extend(["listen-port", str(listen_port)])
    if peer:
        config_args.extend(["peer", peer])
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
            config_args.extend(["endpoint", real_endpoint])
        if keepalive:
            config_args.extend(["persistent-keepalive", str(keepalive)])
        if allowed_ips:
            config_args.extend(["allowed-ips", allowed_ips])

    sudo_call(ns_wrap(namespace, ["wg", "set", name] + config_args))
    os.unlink(temp_filename)


def up_wg_device(namespace: str, name: str):
    sudo_call(ns_wrap(namespace, ["ip", "link", "set", "dev", name, "up"]))


def create_veth_device(namespace: str, name: str, veth_network: str):
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


def create_dummy_device(name: str, address: str, mtu: int):
    sudo_call(["ip", "link", "add", name, "type", "dummy"])
    sudo_call(["ip", "address", "add", "dev", name, address])
    sudo_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
    sudo_call(["ip", "link", "set", "dev", name, "up"])


def create_gre_device(name: str, address: str, mtu: int, local_ip: str, remote_ip: str, ttl: Optional[int]=None, key: Optional[int]=None, checksum: bool=False, seqnum: bool=False):
    call_args = ["ip", "link", "add", name, "type", "gre", "local", local_ip, "remote", remote_ip]
    if ttl:
        call_args.extend(["ttl", str(int(ttl))])  # PTMU will be enabled if ttl presents
    if key:
        call_args.extend(["key", str(int(key))])
    if checksum:
        call_args.append("csum")
    if seqnum:
        call_args.append("seq")

    sudo_call(call_args)
    sudo_call(["ip", "address", "add", "dev", name, address])
    sudo_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
    sudo_call(["ip", "link", "set", "dev", name, "up"])


def destroy_device_if_exists(namespace: str, interface_name: str):
    result = sudo_call_output(ns_wrap(namespace, ["ip", "-j", "link"]))
    try:
        result = json.loads(result)
    except Exception:
        time.sleep(3)
        result = sudo_call_output(ns_wrap(namespace, ["ip", "-j", "link"]))
        result = json.loads(result)

    for if_config in result:
        if if_config['ifname'] == interface_name:
            # Found interface, remove it
            sudo_call(ns_wrap(namespace, ["ip", "link", "del", "dev", interface_name]))


def create_ns_connect(current_namespace: str, remote_namespace: str, veth_network: str):
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


def dump_all_wireguard_state(namespace: str):
    output = sudo_call_output(ns_wrap(namespace, ["wg", "show", "all", "dump"]))
    interface_states: dict[str, WireGuardState] = {}

    for line in output.split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if parts[0] not in interface_states:
            # new interface
            interface_states[parts[0]] = WireGuardState(
                private=parts[1],
                public=parts[2],
                listen=int(parts[3]),
                fwmark=0 if parts[4] == 'off' else int(parts[4]),
                peers={},
            )
        else:
            state = interface_states[parts[0]]
            state.peers[parts[1]] = WireGuardPeerState(
                preshared='' if parts[2] == '(none)' else parts[2],
                endpoint='' if parts[3] == '(none)' else parts[3],
                allow=parts[4],
                handshake=int(parts[5]),
                rx=int(parts[6]),
                tx=int(parts[7]),
                keepalive=0 if parts[8] == 'off' else int(parts[8]),
            )
    return interface_states


def dump_wireguard_state(namespace: str, device_name: str):
    output = sudo_call_output(ns_wrap(namespace, ["wg", "show", device_name, "dump"]))
    state: Optional[WireGuardState] = None

    for line in output.split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) == 4:
            state = WireGuardState(
                private=parts[0],
                public=parts[1],
                listen=int(parts[2]),
                fwmark=0 if parts[3] == 'off' else int(parts[3]),
                peers={},
            )
        else:
            assert state is not None
            state.peers[parts[0]] = WireGuardPeerState(
                preshared='' if parts[1] == '(none)' else parts[1],
                endpoint='' if parts[2] == '(none)' else parts[2],
                allow=parts[3],
                handshake=int(parts[4]),
                rx=int(parts[5]),
                tx=int(parts[6]),
                keepalive=0 if parts[7] == 'off' else int(parts[7]),
            )

    assert state is not None
    return state


def get_interface_state(namespace: str, device_name: str):
    addr_output = sudo_call_output(ns_wrap(namespace, ["ip", "-j", "addr", "show", "dev", device_name]))
    addr_output = json.loads(addr_output)[0]

    mtu = int(addr_output['mtu'])
    v4_cidrs = ["{}/{}".format(info["local"], info["prefixlen"]) for info in addr_output['addr_info'] if info['family'] == 'inet']
    # v6_cidrs = ["{}/{}".format(info["local"], info["prefixlen"]) for info in addr_output['addr_info'] if info['family'] == 'inet6']

    return InterfaceState(
        name=device_name,
        mtu=mtu,
        address=v4_cidrs[0] if v4_cidrs else "",
        # address6=v6_cidrs[0] if v6_cidrs else "",
    )


def get_all_interface_state(namespace: str):
    addr_output = sudo_call_output(ns_wrap(namespace, ["ip", "-j", "addr", "show"]))
    addr_output = json.loads(addr_output)
    
    states: list[InterfaceState] = []
    for if_output in addr_output:
        name = if_output['ifname']
        mtu = int(if_output['mtu'])
        v4_cidrs = ["{}/{}".format(info["local"], info["prefixlen"]) for info in if_output['addr_info'] if info['family'] == 'inet']
        
        states.append(InterfaceState(
            name=name,
            mtu=mtu,
            address=v4_cidrs[0] if v4_cidrs else "",
        ))
    
    return states
