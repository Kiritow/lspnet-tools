import json
from utils import sudo_call, sudo_call_output, get_tempdir_path
from utils import logger


def inspect_podman_router(namespace):
    container_name = "{}-router".format(namespace)

    container_list = sudo_call_output(["podman", "ps", "-a", "--format=json"])
    container_list = json.loads(container_list)
    for container_info in container_list:
        if container_name in container_info['Names']:
            logger.info('found container {} with names: {}'.format(container_info['Id'], container_info['Names']))

            container_inspect_result = sudo_call_output(["podman", "container", "inspect", container_info['Id']])
            container_inspect_result = json.loads(container_inspect_result)

            return container_inspect_result[0]


def shutdown_podman_router(namespace):
    container_inspect_result = inspect_podman_router(namespace)
    if not container_inspect_result:
        return

    logger.info('removing container: {}'.format(container_inspect_result['Id']))
    sudo_call(["podman", "rm", "-f", container_inspect_result['Id']])

    # make sure legacy mount/tmpfiles are cleared
    temp_dirpath = [temp_fullpath.split(':')[0] for temp_fullpath in container_inspect_result["HostConfig"]["Binds"] if temp_fullpath.startswith(get_tempdir_path(namespace))][0]
    logger.info('removing temp directory: {}'.format(temp_dirpath))
    sudo_call(["rm", "-rf", temp_dirpath])



def start_podman_router(namespace):
    logger.info('starting router with namespace {}'.format(namespace))
    sudo_call(["podman", "run", "--network", "ns:/var/run/netns/{}".format(namespace), 
               "--cap-add", "NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "NET_RAW", "--cap-add", "NET_BROADCAST",
               "-v", "{}/router:/data:ro".format(get_tempdir_path(namespace)), "--name", "{}-router".format(namespace),
               "-d", "bird-router"])
