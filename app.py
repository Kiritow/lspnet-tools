import subprocess
import sys
import traceback
import os
import uuid
import time
import argparse
from prettytable import PrettyTable
from common.config_db import ConfigStore
from common.node_manager import NodeManager, get_or_init_node_interactive
from common.utils import sudo_call
from common.utils import get_all_loaded_services
from common.utils import human_readable_bytes, human_readable_duration
from common.device import dump_all_wireguard_state
from common.utils import logger
from common.controller import do_cleanup_everything, do_sync_with_remote


INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
logger.info('detected INSTALL_DIR={}'.format(INSTALL_DIR))


def show_network_status(namespace: str):
    interface_states = dump_all_wireguard_state(namespace)
    pt = PrettyTable(["Interface Name", "Listen", "Recv", "Send", "Peer Address", "Keepalive", "Last Handshake"])
    pt_data: list[list[str]] = []
    
    for interface_name, interface_state in interface_states.items():
        peer_state = list(interface_state.peers.items())[0][1]

        pt_data.append([
                    interface_name, str(interface_state.listen),
                    human_readable_bytes(peer_state.rx), human_readable_bytes(peer_state.tx),
                    peer_state.endpoint,
                    human_readable_duration(peer_state.keepalive) if peer_state.keepalive else "-",
                    human_readable_duration(int(time.time() - peer_state.handshake)) if peer_state.handshake else '-'])

    pt.add_rows(pt_data)
    print(pt)


def start_service(config_filepath: str, namespace: str):
    unit_name = "networktools-{}-{}".format(namespace, uuid.uuid4())
    sudo_call(["systemd-run", "--unit", unit_name, "--collect",
               "--timer-property", "AccuracySec=10",
               "--timer-property", "RandomizedDelaySec=3",
               "--on-calendar", "*-*-* *:*:00", # every minute
               "--working-directory={}".format(INSTALL_DIR),
               "--property", "RuntimeMaxSec=120", # max run 2 minutes
               "{}/venv/bin/python3".format(INSTALL_DIR),
               "app.py",
               "-d", config_filepath,
               "service-main"
               ])


def stop_service(namespace: str):
    running_tasks = get_all_loaded_services()
    unit_prefix = "networktools-{}-".format(namespace)
    running_timers = [task for task in running_tasks if task.startswith(unit_prefix) and task.endswith(".timer")]
    running_services = [task for task in running_tasks if task.startswith(unit_prefix) and task.endswith(".service")]
    
    for timer_name in running_timers:
        logger.info('stopping timer {}'.format(timer_name))
        try:
            sudo_call(["systemctl", "stop", timer_name])
        except subprocess.CalledProcessError as e:
            print(traceback.format_exc())
            logger.warning('failed to stop timer {}: {}'.format(timer_name, e))
    
    for service_name in running_services:
        logger.info('stopping service {}'.format(service_name))
        try:
            sudo_call(["systemctl", "stop", service_name])
        except subprocess.CalledProcessError as e:
            print(traceback.format_exc())
            logger.warning('failed to stop service {}: {}'.format(service_name, e))
    
    do_cleanup_everything(namespace)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-d', '--database', type=str, help='network config database to use', action='store')
    arg_parser.add_argument('action', type=str, help='action to perform', action='store')

    args = arg_parser.parse_args()
    if args.action == 'init':
        if not args.database:
            logger.error('init action requires a database name')
            sys.exit(1)

        node_manager = get_or_init_node_interactive(args.database)
        print(node_manager.get_info())
        print("node manager initialized")
        sys.exit(0)

    if args.action == 'service-up':
        store = ConfigStore(args.database)
        namespace = store.get_node_config('namespace')
        assert namespace, "namespace not set in config store, store might be corrupted"
        start_service(args.database, namespace)
        sys.exit(0)
    
    if args.action == 'service-down':
        store = ConfigStore(args.database)
        namespace = store.get_node_config('namespace')
        assert namespace, "namespace not set in config store, store might be corrupted"
        stop_service(namespace)
        sys.exit(0)
    
    if args.action == 'service-main':
        node_manager = NodeManager(ConfigStore(args.database))
        do_sync_with_remote(node_manager)
        sys.exit(0)

    if args.action == 'status':
        store = ConfigStore(args.database)
        namespace = store.get_node_config('namespace')
        assert namespace, "namespace not set in config store, store might be corrupted"
        show_network_status(namespace)
        sys.exit(0)
    
    if args.action == "debug-sync":
        do_sync_with_remote(get_or_init_node_interactive(args.database))
        sys.exit(0)

    logger.error('unknown action {}'.format(args.action))
    sys.exit(1)
