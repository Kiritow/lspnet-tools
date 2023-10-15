import os
import requests
from get_logger import get_logger


logger = get_logger('app')


def get_proxies_from_env():
    http_proxy = os.getenv('http_proxy') or os.getenv('HTTP_PROXY')
    https_proxy = os.getenv('https_proxy') or os.getenv('HTTPS_PROXY')
    if not http_proxy and not https_proxy:
        return None

    return {
        "http": http_proxy,
        "https": https_proxy,
    }


class KeyManager:
    def __init__(self, domain_prefix, token='') -> None:
        self.domain_prefix = domain_prefix
        if not self.domain_prefix.startswith('https://') and not self.domain_prefix.startswith('http://'):
            self.domain_prefix = 'https://' + self.domain_prefix

        self.token = token

    def login(self, network, host, password):
        r = requests.post('{}/token'.format(self.domain_prefix), json={
            "host": host,
            "network": network,
            "token": password,
        }, timeout=10, proxies=get_proxies_from_env())
        if r.status_code != 200:
            raise Exception('login failed, status: {}, error: {}'.format(r.status_code, r.content))

        self.token = r.content.decode()

    def do_post(self, url, data=None, must_success=True):
        r = requests.post('{}{}'.format(self.domain_prefix, url), headers={
            'x-service-token': self.token,
        }, json=data, timeout=10, proxies=get_proxies_from_env())
        if must_success and r.status_code != 200:
            raise Exception('[POST] {}{} failed with status {}, error: {}'.format(self.domain_prefix, url, r.status_code, r.content))
        return r

    def do_get(self, url, params=None, must_success=True):
        r = requests.get('{}{}'.format(self.domain_prefix, url), headers={
            'x-service-token': self.token,
        }, params=params, timeout=10, proxies=get_proxies_from_env())
        if must_success and r.status_code != 200:
            raise Exception('[POST] {}{} failed with status {}, error: {}'.format(self.domain_prefix, url, r.status_code, r.content))
        return r

    def validate(self):
        logger.info('[KeyManager] validating token...')

        r = self.do_get('/info', must_success=False)
        if r.status_code != 200:
            return None

        return r.json()

    def get_report_token(self):
        logger.info('[KeyManager] requesting new report token...')
        
        r = self.do_post('/report_token')
        return r.content.decode()

    def request_key(self, host):
        logger.info('[KeyManager] requesting key {}...'.format(host))

        r = self.do_post('/wg/request', data={
            "host": host,
        })
        status = r.json()["status"]
        if status == "ready":
            return r.json()["key"]
        return ""

    def batch_request_key(self, host_arr):
        logger.info('[KeyManager] requesting keys {}...'.format(host_arr))
        r = self.do_post('/wg/batch_request', data=[{
            "host": host,
        } for host in host_arr])
        status_arr = r.json()
        result_keys = {}
        for status_info in status_arr:
            if status_info["status"] == "ready":
                result_keys[status_info["host"]] = status_info["key"]
        return result_keys

    def list_keys(self):
        logger.info('[KeyManager] fetching keys...')

        r = self.do_get("/wg/list")
        return r.json()

    def patch_key(self, name, key):
        logger.info('[KeyManager] patching key {}...'.format(name))

        self.do_post("/wg/create", data={
            "name": name,
            "key": key,
        })

    def list_links(self):
        logger.info('[KeyManager] fetching links...')

        r = self.do_get('/link/list')
        return r.json()

    def create_link(self, name, address, mtu, keepalive):
        logger.info('[KeyManager] creating link {}...'.format(name))

        r = self.do_post('/link/create', data={
            "name": name,
            "address": address or None,
            "mtu": int(mtu),
            "keepalive": int(keepalive),
        })
        return r.json()

    def report_stat(self, name, ping, rx, tx):
        logger.info('[KeyManager] send metric for link {}...'.format(name))
        
        self.do_post('/link/report', data={
            "name": name,
            "ping": ping,
            "rx": rx,
            "tx": tx,
        })
