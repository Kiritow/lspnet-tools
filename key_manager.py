import requests


class KeyManager:
    def __init__(self, domain_prefix, token='') -> None:
        self.domain_prefix = domain_prefix
        if not self.domain_prefix.startswith('https://') or not self.domain_prefix.startswith('http://'):
            self.domain_prefix = 'https://' + self.domain_prefix

        self.token = token

    def login(self, network, host, password):
        r = requests.post('{}/token'.format(self.domain_prefix), json={
            "host": host,
            "network": network,
            "token": password,
        })
        if r.status_code != 200:
            raise Exception('login failed, status: {}, error: {}'.format(r.status_code, r.content))

        self.token = r.content.decode()

    def validate(self):
        r = requests.get('{}/info'.format(self.domain_prefix), headers={
            'x-service-token': self.token,
        })
        if r.status_code != 200:
            return None

        return r.json()

    def request_key(self, host):
        r = requests.post('{}/wg/request'.format(self.domain_prefix), headers={
            'x-service-token': self.token,
        }, json={"host": host})
        if r.status_code != 200:
            raise Exception('request key failed, status: {}, error: {}'.format(r.status_code, r.content))

        status = r.json()["status"]
        if status == "ready":
            return r.json()["key"]
        return ""

    def list_keys(self):
        r = requests.get("{}/wg/list".format(self.domain_prefix), headers={
            'x-service-token': self.token,
        })
        if r.status_code != 200:
            raise Exception('unable to list keys, status: {}, error: {}'.format(r.status_code, r.content))
        return r.json()

    def patch_key(self, name, key):
        r = requests.post('{}/wg/create'.format(self.domain_prefix), headers={
            'x-service-token': self.token,
        }, json={"name": name, "key": key})
        if r.status_code != 200:
            raise Exception('patch key failed, status: {}, error: {}'.format(r.status_code, r.content))
