import os
import subprocess
import json
import socket
import traceback
import pwd
import grp
from typing import List, Tuple

from .get_logger import get_logger


logger = get_logger('app')


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


def ensure_ip_forward(namespace):
    sudo_call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sudo_call(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv4.ip_forward=1"])


def get_eth_ip(name):
    result = sudo_call_output(["ip", "-j", "address", "show", "dev", name])
    print(result)
    result = json.loads(result)
    return [addr_info['local'] for addr_info in result[0]['addr_info'] if addr_info['family'] == 'inet'][0]


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


def get_git_version_user():
    try:
        stat = os.stat('.')
        uid, gid = stat.st_uid, stat.st_gid
        uname = pwd.getpwuid(uid).pw_name
        gname = grp.getgrgid(gid).gr_name
        return subprocess.check_output(["sudo", "-u", uname, "-g", gname, "git", "rev-parse", "--verify", "HEAD"], encoding='utf-8').strip()
    except Exception:
        logger.warn(traceback.format_exc())
        return "https://github.com/Kiritow/lspnet-tools"


def get_git_version():
    try:
        return subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], encoding='utf-8').strip()
    except Exception:
        logger.warning('unable to get git commit, try again with correct user...')
        return get_git_version_user()


def get_all_loaded_services():
    output = sudo_call_output(["systemctl", "show", "*", "--state=loaded", "--property=Id", "--value"])
    return list(set([line for line in output.split('\n') if line]))


def parse_ports_expression(port_str: str):
    parts = port_str.split(',')
    all_ports = set()
    for s in parts:
        if '-' in s:
            begin_port, end_port = s.split('-')
            all_ports.update(range(int(begin_port), int(end_port)+1))
        else:
            all_ports.add(int(s))

    return list(all_ports)


def parse_endpoint_expression(endpoint_str: str):
    parts = endpoint_str.split(':')
    try:
        real_host = socket.gethostbyname(parts[0])
    except Exception:
        logger.warning('unable to resolve: {}'.format(parts[0]))
        real_host = ''

    return parts[0], real_host, parse_ports_expression(parts[1])


def ports_to_segments(ports: List[int]):
    sorted_ports = sorted(set([int(x) for x in ports]))
    segs = []
    
    begin_port = 0
    end_port = 0
    for port in sorted_ports:
        if not begin_port:
            begin_port = port
            end_port = port
            continue
        
        if port - end_port > 1:
            # not-continuous
            segs.append((begin_port, end_port))
            begin_port = port
            end_port = port
            continue

        # continous
        end_port = port

    if begin_port:
        segs.append((begin_port, end_port))

    return segs


def port_segments_to_expression(segments: List[Tuple[int, int]]):
    output = []
    for seg in segments:
        begin_port, end_port = seg
        if end_port != begin_port:
            output.append('{}-{}'.format(begin_port, end_port))
        else:
            output.append('{}'.format(begin_port))
    
    return ','.join(output)
