import os
import sys
import json
import subprocess
import traceback
import requests
import hashlib


API_HOST = os.getenv('API_HOST')
API_TOKEN = os.getenv('API_TOKEN')
RUN_USER = os.getenv('RUN_USER')
INSTALL_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
CONF_DIR = os.getenv('CONF_DIR') or '/tmp'


def get_config_hash(conf_path):
    try:
        with open(conf_path, 'rb') as f:
            h = hashlib.sha256()
            h.update(f.read())
            return h.hexdigest()
    except Exception:
        print(traceback.format_exc())
        return ''


def do_get_json(url):
    r = requests.get('{}{}'.format(API_HOST, url), headers={
        'x-service-token': API_TOKEN,
    }, timeout=5)
    if r.status_code != 200:
        raise Exception('got status code {}, expected 200'.format(r.status_code))
    print(r.content)
    return r.json()


def do_post(url, jdata):
    r = requests.post('{}{}'.format(API_HOST, url), headers={
        'x-service-token': API_TOKEN,
    }, json=jdata, timeout=5)
    if r.status_code != 200:
        raise Exception('got status code {}, expected 200'.format(r.status_code))
    print(r.content)
    return r.content


def get_config_list():
    config_list = do_get_json('/tunnel/list')
    return {
        'frpc': config_list.get('frpc', []),
        'frps': config_list.get('frps', []),
        'gost': config_list.get('gost', []),
    }


def get_config_path(service_type, name):
    return os.path.join(CONF_DIR, '{}_{}.json'.format(service_type, name))


def load_config(service_type, name, expected_hash):
    conf_path = get_config_path(service_type, name)

    try:
        if expected_hash == get_config_hash(conf_path):
            return False

        # config changed, download new config
        print('downloading config for [{}]{}...'.format(service_type, name))
        new_config = do_get_json('/tunnel/config?name={}'.format(name))
        with open(conf_path, 'wb') as f:
            f.write(new_config['data'].encode())

        return True
    except Exception:
        print(traceback.format_exc())
        return False


def start_frp_client(name, run_user):
    bin_path = os.path.join(INSTALL_DIR, "bin", "frpc")
    conf_path = get_config_path('frpc', name)

    call_args = ["systemd-run", "--unit", "proxy-agent-frpc-{}".format(name), "--collect", "--property", "Restart=always", "--property", "RestartSec=5s"]
    if run_user:
        call_args.extend(["--uid", run_user])
    call_args.extend([bin_path, "-c", conf_path])

    print(call_args)
    subprocess.check_call(call_args)


def start_frp_server(name, run_user):
    bin_path = os.path.join(INSTALL_DIR, "bin", "frps")
    conf_path = get_config_path('frps', name)

    call_args = ["systemd-run", "--unit", "proxy-agent-frps-{}".format(name), "--collect", "--property", "Restart=always", "--property", "RestartSec=5s"]
    if run_user:
        call_args.extend(["--uid", run_user])
    call_args.extend([bin_path, "-c", conf_path])

    print(call_args)
    subprocess.check_call(call_args)


def start_gost_v2_simple(name, run_user):
    bin_path = os.path.join(INSTALL_DIR, "bin", "gost")
    conf_path = get_config_path('gost', name)
    with open(conf_path) as f:
        conf_parts = json.load(f)

    call_args = ["systemd-run", "--unit", "proxy-agent-gost-{}".format(name), "--collect", "--property", "Restart=always", "--property", "RestartSec=5s"]
    if run_user:
        call_args.extend(["--uid", run_user])
    call_args.extend([bin_path] + conf_parts)

    print(call_args)
    subprocess.check_call(call_args)


def report_agent_status(local_services):
    try:
        do_post('/tunnel/report', {
            "running": local_services,
        })
    except Exception:
        print(traceback.format_exc())


def try_kill_service(real_name):
    print('stopping service {}...'.format(real_name))

    try:
        subprocess.check_call(['systemctl', 'stop', real_name])
    except Exception:
        print(traceback.format_exc())


def list_local_services():
    output = subprocess.check_output(["systemctl", "show", "*", "--state=loaded", "--property=Id", "--value"], encoding='utf-8').strip()
    return list(set([line for line in output.split('\n') if line and line.startswith('proxy-agent-')]))


def agent_scan():
    config_list = get_config_list()
    processed_services = []
    running_services = list_local_services()

    # frps
    for service_config in config_list['frps']:
        service_name = service_config['name']
        expected_hash = service_config['hash']
        
        real_service_name = 'proxy-agent-frps-{}.service'.format(service_name)
        need_update = load_config('frps', service_name, expected_hash)
        if need_update or real_service_name not in running_services:
            try_kill_service(real_service_name)
            start_frp_server(service_name, RUN_USER)
        
        processed_services.append(real_service_name)

    # frpc
    for service_config in config_list['frpc']:
        service_name = service_config['name']
        expected_hash = service_config['hash']
        
        real_service_name = 'proxy-agent-frpc-{}.service'.format(service_name)
        need_update = load_config('frpc', service_name, expected_hash)
        if need_update or real_service_name not in running_services:
            try_kill_service(real_service_name)
            start_frp_client(service_name, RUN_USER)

        processed_services.append(real_service_name)

    # gost
    for service_config in config_list['gost']:
        service_name = service_config['name']
        expected_hash = service_config['hash']
        
        real_service_name = 'proxy-agent-gost-{}.service'.format(service_name)
        need_update = load_config('gost', service_name, expected_hash)
        if need_update or real_service_name not in running_services:
            try_kill_service(real_service_name)
            start_gost_v2_simple(service_name, RUN_USER)

        processed_services.append(real_service_name)

    # kill expired services
    for real_service_name in running_services:
        if real_service_name not in processed_services:
            try_kill_service(real_service_name)
    
    # report running services
    report_agent_status(list_local_services())


if __name__ == "__main__":
    agent_scan()
