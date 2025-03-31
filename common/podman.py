import json
import subprocess

from .utils import get_all_loaded_services, sudo_call, sudo_call_output, get_tempdir_path
from .utils import logger


def inspect_podman_router(namespace: str):
    expected_container_name = "{}-router".format(namespace)

    container_list = sudo_call_output(["podman", "ps", "-a", "--format=json"])
    container_list = json.loads(container_list)
    for container_info in container_list:
        if expected_container_name in container_info['Names']:
            logger.info('found container {} with names: {}'.format(container_info['Id'], container_info['Names']))

            container_inspect_result = sudo_call_output(["podman", "container", "inspect", container_info['Id']])
            container_inspect_result = json.loads(container_inspect_result)
            # print(container_inspect_result[0])
            return container_inspect_result[0]


def shutdown_podman_router(namespace: str, clear_temp: bool=True):
    container_inspect_result = inspect_podman_router(namespace)
    if not container_inspect_result:
        return

    # delete systemd service if it was started via systemd
    unit_name = "networktools-{}-router.service".format(namespace)
    running_tasks = get_all_loaded_services()
    if unit_name in running_tasks:
        logger.info('stopping systemd service {}'.format(unit_name))
        try:
            sudo_call(["systemctl", "stop", unit_name])
        except subprocess.CalledProcessError as e:
            logger.warning('failed to stop systemd service {}: {}'.format(unit_name, e))

    logger.info('removing container: {}'.format(container_inspect_result['Id']))
    sudo_call(["podman", "rm", "-f", container_inspect_result['Id']])

    # make sure legacy mount/tmpfiles are cleared
    if clear_temp:
        temp_dirpath = [temp_fullpath.split(':')[0] for temp_fullpath in container_inspect_result["HostConfig"]["Binds"] if temp_fullpath.startswith(get_tempdir_path(namespace))][0]
        logger.info('removing temp directory: {}'.format(temp_dirpath))
        sudo_call(["rm", "-rf", temp_dirpath])



def start_podman_router(namespace: str):
    logger.info('starting router with namespace {}'.format(namespace))
    sudo_call(["podman", "run", "--network", "ns:/var/run/netns/{}".format(namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}/router:/data:ro".format(get_tempdir_path(namespace)), "--name", "{}-router".format(namespace),
               "-d", "bird-router"])


def start_podman_router_via_systemd(namespace: str):
    logger.info("create router with namespace {}".format(namespace))
    sudo_call(["podman", "create", "--network", "ns:/var/run/netns/{}".format(namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}/router:/data:ro".format(get_tempdir_path(namespace)), "--name", "{}-router".format(namespace),
               "bird-router"])
    container_inspect_result = inspect_podman_router(namespace)
    if not container_inspect_result:
        print("failed to create podman container")
        return

    container_id: str = container_inspect_result['Id']
    logger.info('starting router with namespace {} via systemd'.format(namespace))    
    unit_name = "networktools-{}-router".format(namespace)
    sudo_call(["systemd-run", "--unit", unit_name, "--collect",
               "--property", "KillMode=none", "--property", "Type=forking",
               "podman", "start", container_id])
